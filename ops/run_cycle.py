#!/usr/bin/env python3
"""One TRUVO intelligence cycle — the scheduled heartbeat.

Runs the full pipeline as separate subprocesses with per-stage PYTHONPATH
isolation (exactly how the services run in production):

    1. COLLECT   structured feeds (KEV, EPSS, ATT&CK, optional NVD)
    2. EXTRACT   rawdocs -> gated claims (structured feeds parse directly;
                 text takes the quarantined extractor: fake or llm)
    3. CORROBORATE  claims -> provenance recording (fixed consumer groups,
                 idempotent)
    4. ENRICH    claims -> exploit_intel read model
    5. SWEEP     every active tenant x relevant CVEs -> scored queue

Any stage failing makes the cycle exit non-zero (an alert, not a log line)
while later stages still attempt to run — a collect failure should not
stop scoring on yesterday's intel.

    python ops/run_cycle.py                # kev + epss + attack
    python ops/run_cycle.py --feeds kev epss
    python ops/run_cycle.py --loop 3600    # dev daemon: cycle hourly

Env: TRUVO_KAFKA_BOOTSTRAP, TRUVO_SCHEMA_REGISTRY, TRUVO_OBJSTORE_ENDPOINT,
     TRUVO_APP_DB_URL (app-role DSN), TRUVO_PROVENANCE_URL (optional),
     TRUVO_EXTRACTOR (fake|llm) + TRUVO_LLM_* for the llm path.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from alerts import alert, check_cycle_anomalies  # noqa: E402

REPO = Path(__file__).resolve().parents[1]

# optional machine-local config (gitignored): LLM keys etc. Loaded BEFORE
# stages run so every subprocess inherits it.
_LOCAL_ENV = REPO / ".env.llm.local"
if _LOCAL_ENV.is_file():
    for line in _LOCAL_ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

STAGES = [
    # (service dir, module, extra env builder)
    ("collector", "app.run_feeds", lambda a: {"TRUVO_ARGS": a}),
    ("extraction", "app.run", lambda a: {"TRUVO_BATCH_MAX": "20000"}),
    ("provenance", "app.consumer", lambda a: {"TRUVO_BATCH_MAX": "20000"}),
    ("scoring", "app.enrich", lambda a: {}),
    ("scoring", "app.sweep", lambda a: {}),
    # the honesty artifact: regenerate the calibration report each cycle
    # (cheap; withheld sections stay withheld until ground truth exists)
    ("eval-harness", "app.report", lambda a: {}),
    # the DPA's promises, executing (retention GC + credential purge)
    ("retention", "ops.retention", lambda a: {}),
]


def run_stage(service_dir: str, module: str, extra: dict) -> dict:
    svc = REPO if service_dir == "retention" else REPO / "services" / service_dir
    env = dict(os.environ)
    env["PYTHONPATH"] = str(svc)
    env.setdefault("TRUVO_KAFKA_BOOTSTRAP", "localhost:9092")
    env.setdefault("TRUVO_SCHEMA_REGISTRY", "http://localhost:18081")
    env.setdefault("TRUVO_OBJSTORE_ENDPOINT", "localhost:9000")
    app_dsn = os.environ.get("TRUVO_APP_DB_URL")
    if app_dsn:
        env.setdefault("TRUVO_PROVENANCE_DB_URL", app_dsn)
        env.setdefault("TRUVO_SCORING_DB_URL", app_dsn)
    env.update(extra)

    cmd = [sys.executable, "-m", module]
    if module == "app.run_feeds" and extra.get("TRUVO_ARGS"):
        cmd += extra["TRUVO_ARGS"].split()
    proc = subprocess.run(cmd, cwd=str(svc), env=env,
                          capture_output=True, text=True,
                          timeout=int(os.environ.get("TRUVO_STAGE_TIMEOUT",
                                                     "1200")))
    out = {}
    if proc.stdout.strip():
        line = proc.stdout.strip().splitlines()[-1]
        if line.startswith("{"):
            try:
                out = json.loads(line)
            except json.JSONDecodeError:
                out = {"raw": line[:200]}
    out["_returncode"] = proc.returncode
    if proc.returncode != 0:
        out["_stderr"] = proc.stderr.strip()[-500:]
    return out


def cycle(feeds: str, stages_filter: str = "") -> dict:
    results = {}
    failed = []
    wanted = {s.strip() for s in stages_filter.split(",") if s.strip()}
    for service_dir, module, extra_fn in STAGES:
        if wanted and module not in wanted:
            continue
        extra = extra_fn(feeds)
        res = run_stage(service_dir, module, extra)
        # summarize: stage output stays log-sized (rawdoc id lists are
        # storage business, not log business)
        for feed in res.get("feeds", []):
            feed.pop("rawdoc_ids", None)
        results["%s/%s" % (service_dir, module)] = {
            k: v for k, v in res.items() if not k.startswith("_")}
        if res["_returncode"] != 0:
            results["%s/%s" % (service_dir, module)]["_stderr"] = res.get(
                "_stderr", "")
            failed.append(module)
    results["_failed"] = failed
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds", default="kev epss attack",
                    help="space-separated feed list for the collect stage")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="run continuously, one cycle per interval")
    ap.add_argument("--stages", default="",
                    help="comma list of stage modules to run (e.g. "
                         "'app.run_feeds' for a collect-only container); "
                         "empty = all")
    args = ap.parse_args()

    while True:
        started = time.time()
        results = cycle(args.feeds, args.stages)
        failed = results.pop("_failed", [])
        print(json.dumps({
            "cycle_started": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                           time.gmtime(started)),
            "duration_s": round(time.time() - started, 1),
            "failed": failed,
            "stages": results,
        }), flush=True)
        if failed:
            alert("pipeline.cycle_failed", "critical",
                  failed_stages=failed, duration_s=round(time.time() - started, 1))
        else:
            check_cycle_anomalies(results)
        if not args.loop:
            return 1 if failed else 0
        # in loop mode a failed cycle logs and retries next interval
        time.sleep(args.loop)


if __name__ == "__main__":
    sys.exit(main())

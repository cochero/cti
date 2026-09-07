"""The calibration & platform-integrity report (Architecture §9).

What this report IS: the honest measurement artifact. It publishes what
is measurable TODAY (replay fidelity of every ledger score entry, score
distributions, stack coverage, baseline agreement) and explicitly
withholds what is not (outcome calibration — Brier, reliability curves —
until the ground-truth store holds enough adjudicated outcomes). When a
section says "withheld", that is the measurement speaking, not a gap in
tooling: the same report fills those sections automatically once n
clears the floor.

Sections:
  replay        — bit-exact re-derivation of scores from ledger entries
  distribution  — score histogram per tenant (millis bands)
  coverage      — of the CVEs that exploit the tenant's stack, how many
                  are scored (queue completeness)
  baselines     — top-k agreement vs naive rankers (CVSS-only, EPSS-only,
                  KEV-first): descriptive, NOT outcome-validated
  calibration   — OUTCOME metrics vs ground truth; withheld below
                  TRUVO_MIN_OUTCOMES (default 50) with a live counter

    python -m app.report        # env: TRUVO_EVAL_DB_URL (truvo_app role)
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.calibration import brier, precision_at_k, reliability_curve
from app.replay import verify_many

MIN_OUTCOMES = int(os.environ.get("TRUVO_MIN_OUTCOMES", "50"))
TOP_K = 20


def _tenants(cur) -> List[Dict[str, Any]]:
    cur.execute("SELECT tenant_id, slug FROM tenants WHERE status = 'active'"
                " ORDER BY created_at")
    return [{"tenant_id": str(r[0]), "slug": r[1]} for r in cur.fetchall()]


def _as_tenant(cur, tenant_id: str) -> None:
    cur.execute("SELECT set_config('truvo.tenant_id', %s, false)",
                (tenant_id,))


def _j(v):
    return json.loads(v) if isinstance(v, str) else (v or {})


def collect(cur, tenant: Dict[str, Any]) -> Dict[str, Any]:
    """All per-tenant sections under one tenant context."""
    tid = tenant["tenant_id"]
    _as_tenant(cur, tid)
    section: Dict[str, Any] = {"slug": tenant["slug"]}

    # ---- replay: latest score.emitted entry per CVE ----
    cur.execute(
        "SELECT seq, payload FROM ledger_entries"
        " WHERE kind = 'score.emitted' ORDER BY seq")
    entries = [(r[0], _j(r[1])) for r in cur.fetchall()]
    latest = {}
    for seq, payload in entries:  # later seq wins per cve
        latest[payload.get("cve")] = (seq, payload)
    section["replay"] = verify_many(list(latest.values()))

    # ---- distribution + latest scores ----
    cur.execute(
        "SELECT DISTINCT ON (cve) cve, priority_millis FROM scores"
        " ORDER BY cve, scored_at DESC")
    latest_scores = cur.fetchall()
    bands = [0] * 10
    for _, p in latest_scores:
        bands[min(p // 100, 9)] += 1
    section["distribution"] = {
        "scored_cves": len(latest_scores),
        "bands_0_to_100": bands,
        "top": sorted(latest_scores, key=lambda r: -r[1])[:TOP_K],
    }

    # ---- coverage: CVEs that exploit this tenant's stack ----
    cur.execute(
        "SELECT count(DISTINCT e.dst_id) FROM tenant_assets ta"
        " JOIN graph_edges e ON e.src_type = 'INFRASTRUCTURE'"
        "  AND e.src_id = ta.cpe AND e.rel = 'exploits'"
        "  AND e.dst_type = 'CVE'")
    stack_cves = cur.fetchone()[0]
    scored_set = {c for c, _ in latest_scores}
    cur.execute(
        "SELECT DISTINCT e.dst_id FROM tenant_assets ta"
        " JOIN graph_edges e ON e.src_type = 'INFRASTRUCTURE'"
        "  AND e.src_id = ta.cpe AND e.rel = 'exploits'"
        "  AND e.dst_type = 'CVE'")
    unscored_stack = [r[0] for r in cur.fetchall()
                      if r[0] not in scored_set]
    section["coverage"] = {
        "stack_cves_known": stack_cves,
        "stack_cves_scored": stack_cves - len(unscored_stack),
        "unscored": unscored_stack[:20],
    }

    # ---- baselines: top-k agreement with naive rankers ----
    cur.execute(
        "SELECT s.cve, s.priority_millis, ei.epss_millis, ei.cvss_millis,"
        " ei.kev FROM (SELECT DISTINCT ON (cve) cve, priority_millis"
        "  FROM scores ORDER BY cve, scored_at DESC) s"
        " LEFT JOIN exploit_intel ei ON ei.cve = s.cve")
    rows = cur.fetchall()
    truvo_top = {r[0] for r in sorted(rows, key=lambda r: -r[1])[:TOP_K]}
    for name, key in (("epss", 2), ("cvss", 3)):
        base_top = {r[0] for r in sorted(rows, key=lambda r: -(r[key] or 0))[:TOP_K]}
        section.setdefault("baselines", {})[name] = round(
            len(truvo_top & base_top) / TOP_K, 3)
    kev_first = {r[0] for r in sorted(
        rows, key=lambda r: (not r[4], -(r[2] or 0)))[:TOP_K]}
    section.setdefault("baselines", {})["kev_first"] = round(
        len(truvo_top & kev_first) / TOP_K, 3)

    # ---- outcome calibration vs ground truth ----
    cur.execute(
        "SELECT DISTINCT ON (cve) cve,"
        " (SELECT priority_millis FROM scores s WHERE s.tenant_id ="
        "   ground_truth.tenant_id AND s.cve = ground_truth.cve"
        "   ORDER BY scored_at DESC LIMIT 1), materialized"
        " FROM ground_truth ORDER BY cve, as_of DESC")
    pairs = [(r[1], r[2]) for r in cur.fetchall() if r[1] is not None]
    n_outcomes = len(pairs)
    if n_outcomes >= MIN_OUTCOMES:
        section["calibration"] = {
            "n": n_outcomes, "withheld": False,
            "brier": brier(pairs),
            "reliability": [
                {"band_mid_millis": b.predicted_mid_millis,
                 "actual_rate_millis": b.actual_rate_millis,
                 "n": b.n}
                for b in reliability_curve(pairs)],
            "precision_at_20": precision_at_k(
                sorted(pairs, reverse=True), 20),
        }
    else:
        section["calibration"] = {
            "n": n_outcomes, "withheld": True,
            "reason": "insufficient ground truth (%d of %d required) — "
                      "adjudicate outcomes to unlock outcome metrics"
                      % (n_outcomes, MIN_OUTCOMES),
        }
    return section


def build(cur) -> Dict[str, Any]:
    tenants = _tenants(cur)
    return {
        "report": "truvo-calibration",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "weights_version": "weights-v0",
        "min_outcomes_required": MIN_OUTCOMES,
        "tenants": [collect(cur, t) for t in tenants],
    }


def to_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# TRUVO Calibration & Platform-Integrity Report",
        "",
        "Generated %s · weights `%s` · eval report v%s" % (
            report["generated_at"], report["weights_version"],
            report["version"]),
        "",
        "## What this report claims — and what it does not",
        "",
        "- **Replay fidelity** is measured NOW: every score re-derived from",
        "  its ledger entry, bit-for-bit. A failure here is a sev-1.",
        "- **Outcome calibration** (Brier, reliability, precision@k) is",
        "  withheld until %d adjudicated outcomes exist per tenant. The"
        % report["min_outcomes_required"],
        "  counter below is live; the sections fill automatically.",
        "- **Baseline agreement** is descriptive (does our queue differ",
        "  from CVSS/EPSS/KEV ordering?) — it is NOT outcome validation.",
        "",
    ]
    for t in report["tenants"]:
        rep = t["replay"]
        lines += [
            "## Tenant `%s`" % t["slug"],
            "",
            "### Replay verification",
            "- entries: %d · **verified bit-exact: %d** · failed: %d ·"
            " unparseable: %d" % (rep["entries"], rep["verified"],
                                  rep["failed"], rep["unparseable"]),
            "- bit-exact rate: %s‰" % (
                rep["bit_exact_rate_millis"]
                if rep["bit_exact_rate_millis"] is not None else "n/a"),
            "",
            "### Score distribution (%d scored CVEs)" %
            t["distribution"]["scored_cves"],
            "- bands 0-100 (x100 millis): %s" %
            t["distribution"]["bands_0_to_100"],
            "",
            "### Stack coverage",
            "- %d of %d stack-relevant CVEs scored" % (
                t["coverage"]["stack_cves_scored"],
                t["coverage"]["stack_cves_known"]),
            "",
            "### Baseline top-%d agreement" % TOP_K,
            "- vs EPSS: %s · vs CVSS: %s · vs KEV-first: %s" % (
                t["baselines"]["epss"], t["baselines"]["cvss"],
                t["baselines"]["kev_first"]),
            "",
            "### Outcome calibration",
        ]
        cal = t["calibration"]
        if cal["withheld"]:
            lines.append("- **WITHHELD** — %d of %d outcomes adjudicated."
                         % (cal["n"], report["min_outcomes_required"]))
            lines.append("- %s" % cal["reason"])
        else:
            lines.append("- n=%d · Brier %.4f" % (
                cal["n"], cal["brier"]["brier"]))
            for b in cal["reliability"]:
                lines.append("  - band %s‰: actual %s‰ (n=%d)" % (
                    b["band_mid_millis"], b["actual_rate_millis"], b["n"]))
        lines.append("")
    lines += [
        "---",
        "*Produced by eval-harness `python -m app.report`. Numbers are",
        "computed, not asserted; withholding is a measurement decision.*",
    ]
    return "\n".join(lines)


def main() -> None:
    import psycopg2

    dsn = os.environ.get("TRUVO_EVAL_DB_URL")
    if not dsn:
        raise SystemExit("TRUVO_EVAL_DB_URL is required")
    out_dir = os.environ.get(
        "TRUVO_REPORT_DIR",
        os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "reports"))
    os.makedirs(out_dir, exist_ok=True)

    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            report = build(cur)
    finally:
        conn.close()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    jpath = os.path.join(out_dir, "calibration-%s.json" % stamp)
    mpath = os.path.join(out_dir, "calibration-%s.md" % stamp)
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    with open(mpath, "w", encoding="utf-8") as f:
        f.write(to_markdown(report))
    print(json.dumps({"json": jpath, "markdown": mpath,
                      "tenants": len(report["tenants"])}))


if __name__ == "__main__":
    main()

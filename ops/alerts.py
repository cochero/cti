#!/usr/bin/env python3
"""Alert dispatch — the minimal honest version (security review H4).

POSTs a JSON alert to TRUVO_ALERT_WEBHOOK (Slack-compatible payload
shape: {"text": ...} plus structured fields) with a short timeout —
alerting must never block the pipeline. No webhook configured = no-op
(logged), because dev stacks shouldn't require one.

This is deliberately small: the full Prometheus/Loki/Grafana stack is
the H4 endgame; this file makes cycle failures and anomalies REACH
someone from day one, on every profile including single-VPS.
"""

import json
import os
import urllib.request
from datetime import datetime, timezone


def webhook_url():
    return os.environ.get("TRUVO_ALERT_WEBHOOK")


def alert(event: str, severity: str = "warning", **fields) -> dict:
    """Fire-and-forget. Returns the alert body (callers log it either way
    so it lands in container logs for the future Loki pipeline)."""
    body = {
        "event": event,
        "severity": severity,  # info | warning | critical
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **fields,
    }
    line = json.dumps(body)
    print("ALERT %s" % line, flush=True)  # structured log line
    url = webhook_url()
    if url:
        try:
            req = urllib.request.Request(
                url, data=json.dumps({"text": line}).encode(),
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:  # never let alerting break the cycle
            print("ALERT-DELIVERY-FAILED %s %s" % (event, exc), flush=True)
    return body


def check_cycle_anomalies(stages: dict) -> list:
    """Anomaly rules over one cycle's stage outputs. Returns alerts fired.

    - gate-rejection-rate spike: an injection campaign or a drifted model
      shows up as rejections climbing while candidates hold steady
    - zero yield: everything rejected (model/provider contract break)
    """
    fired = []
    ex = stages.get("extraction/app.run", {})
    accepted, rejected = ex.get("accepted", 0), ex.get("rejected", 0)
    total = accepted + rejected
    if total >= 20 and rejected / total > 0.5:
        fired.append(alert("pipeline.gate_rejection_spike", "critical",
                           accepted=accepted, rejected=rejected,
                           rate=round(rejected / total, 3),
                           hint="injection campaign or model drift"))
    if total == 0 and ex:
        fired.append(alert("pipeline.zero_extraction_yield", "warning",
                           hint="model/provider contract break"))
    return fired

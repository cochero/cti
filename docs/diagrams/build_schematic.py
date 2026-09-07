#!/usr/bin/env python3
"""Generate the TRUVO implementation schematic (SVG + HTML wrapper).

One picture: how TRUVO reaches each end user (three deployment profiles)
and the operational loop — PROTECT (compile + release detections), MONITOR
(telemetry + leaks + identity), REPORT (ledger, ground truth, compliance)
— closed by the feedback flywheel back into scoring.

Geometry is programmatic: boxes are computed, arrows are routed between
clear channels (left margin, heading-free rows), columns distribute their
content evenly. Render check: build_schematic.py then headless-chrome PNG.
"""

from pathlib import Path

W, H = 1760, 1290
BG, PANEL, PANEL2, BORDER = "#0a0e14", "#10151d", "#141b25", "#223042"
TXT, DIM, FAINT = "#d7e0ea", "#8a97a8", "#5c6878"
BLUE, AMBER, GREEN, RED = "#38bdf8", "#fbbf24", "#34d399", "#f87171"
SANS = "Inter, 'Segoe UI', Roboto, sans-serif"
MONO = "'JetBrains Mono', 'Cascadia Code', Consolas, monospace"

out = []


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size=13, fill=TXT, anchor="start", weight=400,
         family=SANS, spacing=None):
    sp = ' letter-spacing="%s"' % spacing if spacing else ""
    out.append(
        f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
        f'fill="{fill}" text-anchor="{anchor}" font-weight="{weight}"{sp}>{esc(s)}</text>')


def rect(x, y, w, h, fill=PANEL, stroke=BORDER, rx=8, sw=1):
    out.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')


def arrow(points, color=BLUE, dash=False, sw=2.4):
    pts = " ".join(f"{p[0]},{p[1]}" for p in points)
    d = ' stroke-dasharray="8 6"' if dash else ""
    out.append(
        f'<polyline points="{pts}" fill="none" stroke="{color}" '
        f'stroke-width="{sw}"{d} marker-end="url(#arr-{color[1:]})"/>')


def label(x, y, s, color=DIM, size=11, anchor="middle", family=MONO):
    text(x, y, s, size=size, fill=color, anchor=anchor, family=family,
         weight=600)


# ---------------------------------------------------------------- canvas + header
out.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
text(60, 58, "TRUVO — End-User Implementation & Operational Loop", size=27,
     weight=750, spacing="0.5")
text(60, 84, "How the platform reaches every end user, and the PROTECT → MONITOR → REPORT process that runs once it does.",
     size=14, fill=DIM)

lx = W - 60
for name, col in [("PROTECT", BLUE), ("MONITOR", AMBER), ("REPORT", GREEN),
                  ("HUMAN GATE / AUDIT", RED)]:
    lx -= 26 + 8.2 * len(name)
    out.append(f'<circle cx="{lx + 8}" cy="52" r="5" fill="{col}"/>')
    text(lx + 20, 56, name, size=11.5, fill=DIM, family=MONO, weight=600)

# ---------------------------------------------------------------- deployment profiles
DY, DH, DW = 116, 112, 520
gap = (W - 120 - 3 * DW) / 2
PY = 276  # platform top
profiles = [
    ("MULTI-TENANT SAAS", "SMEs → mid-market → corporates",
     ["tenant provisioned, RLS-isolated", "shared platform, per-tenant keys",
      "console + SSO (OIDC / SAML)"], GREEN),
    ("SINGLE-TENANT VPC", "corporates & regulated industries",
     ["same Helm charts, customer's cloud", "data never leaves the VPC",
      "customer HSM holds the keys"], BLUE),
    ("AIR-GAPPED ON-PREM", "government, defense, critical infra",
     ["compact profile: k3s single rack", "signed offline bundles (diode)",
      "zero telemetry to vendor — ever"], AMBER),
]
for i, (t, sub, lines, col) in enumerate(profiles):
    x = 60 + i * (DW + gap)
    rect(x, DY, DW, DH, fill=PANEL, stroke=BORDER)
    out.append(f'<rect x="{x}" y="{DY}" width="{DW}" height="3" rx="1.5" fill="{col}"/>')
    text(x + 14, DY + 27, t, size=13.5, weight=750, family=MONO, fill=col)
    text(x + DW - 14, DY + 27, "DEPLOYMENT %d/3" % (i + 1), size=10,
         fill=FAINT, anchor="end", family=MONO)
    text(x + 14, DY + 47, sub, size=11.5, fill=DIM)
    yy = DY + 68
    for ln in lines:
        out.append(f'<circle cx="{x + 18}" cy="{yy - 4}" r="2" fill="{FAINT}"/>')
        text(x + 27, yy, ln, size=11, fill=DIM)
        yy += 15

# arrows into the platform, label centered in the clear channel between
# arrows 1 and 2 (not on the middle arrow's x)
centers = [60 + i * (DW + gap) + DW / 2 for i in range(3)]
for x in centers:
    arrow([(x, DY + DH), (x, PY - 8)], color=BLUE, sw=2)
label((centers[0] + centers[1]) / 2, PY - 14,
      "one codebase · two deployment profiles · every end user gets the full loop",
      color=DIM, size=12)

# ---------------------------------------------------------------- platform
PH = 380
rect(60, PY, W - 120, PH, fill="#0d1420", stroke=BORDER, sw=1.2, rx=10)
text(76, PY + 30, "TRUVO PLATFORM", size=14, weight=750, family=MONO,
     fill=TXT, spacing="2")
text(280, PY + 30, "collection → trust spine → prioritize → hunt ·  every step ledger-recorded",
     size=11.5, fill=FAINT, family=MONO)

col_w = (W - 120 - 24 - 4 * 14) / 5
box_y = PY + 48
col_h = PH - 66
stages = [
    ("1 · COLLECT", BLUE, [
        ("Sandboxed collectors", ["no-privilege containers"]),
        ("Structured + OSINT feeds", ["NVD · CISA KEV · EPSS", "ATT&CK STIX · TAXII", "dark web (passive read)"]),
    ]),
    ("2 · TRUST", BLUE, [
        ("Schema gate", ["LLMs propose — never trust"]),
        ("Provenance & corroboration", ["source grades A–F", "independence-aware belief"]),
        ("Entity resolution + graph", ["actors ↔ TTPs ↔ CVEs"]),
    ]),
    ("3 · PRIORITIZE", GREEN, [
        ("Deterministic scoring", ["pure · replayable", "fully decomposable"]),
        ("Tenant context", ["assets · identity · sector"]),
        ("Audit ledger entry", ["every score reproducible"]),
    ]),
    ("4 · HUNT", BLUE, [
        ("Detection factory", ["compile → detonate → sign"]),
        ("Staged rules", ["FP budget enforced"]),
        ("Sigma → KQL / SPL", ["customer's own SIEM"]),
    ]),
    ("5 · ACT", BLUE, [
        ("Response orchestrator", ["3 tiers", "circuit breakers"]),
        ("Integration gateway", ["signed single-use", "commands only"]),
    ]),
]
for si, (stitle, scol, boxes) in enumerate(stages):
    x = 76 + si * (col_w + 14)
    rect(x, box_y, col_w, col_h, fill=PANEL, stroke=BORDER, sw=0.8)
    out.append(f'<rect x="{x}" y="{box_y}" width="{col_w}" height="3" rx="1.5" fill="{scol}"/>')
    text(x + 10, box_y + 24, stitle, size=12.5, weight=750, family=MONO,
         fill=scol)
    # distribute inner boxes evenly over the column body
    content_top, content_bottom = box_y + 36, box_y + col_h - 12
    heights = [30 + 14 * len(bl) for _, bl in boxes]
    total = sum(heights)
    pad = (content_bottom - content_top - total) / max(1, len(boxes) - 1) \
        if len(boxes) > 1 else 0
    yy = content_top
    for (btitle, blines), bh in zip(boxes, heights):
        rect(x + 8, yy, col_w - 16, bh, fill=PANEL2, stroke=BORDER, sw=0.8, rx=6)
        text(x + 15, yy + 18, btitle, size=11.5, weight=600, fill=TXT)
        ly = yy + 33
        for ln in blines:
            text(x + 15, ly, ln, size=10, fill=DIM, family=MONO)
            ly += 14
        yy += bh + pad

for si in range(4):
    x1 = 76 + (si + 1) * (col_w + 14) - 14
    arrow([(x1 - 2, box_y + col_h / 2), (x1 + 16, box_y + col_h / 2)],
          color=BLUE, sw=2)

# human gate badge under ACT column, inside the platform
act_x = 76 + 4 * (col_w + 14)
rect(act_x + 8, box_y + col_h + 8, col_w - 16, 22, fill="#1c1220",
     stroke=RED, rx=11, sw=1.2)
text(act_x + col_w / 2, box_y + col_h + 23,
     "HUMAN GATE — release is a decision", size=10.5, fill=RED,
     anchor="middle", family=MONO, weight=700)

# ---------------------------------------------------------------- trust boundary + customer env
CY = PY + PH + 16
out.append(f'<line x1="60" y1="{CY}" x2="{W - 60}" y2="{CY}" stroke="{RED}" '
           f'stroke-width="1.2" stroke-dasharray="10 6" opacity="0.75"/>')
text(W - 66, CY - 8, "TRUST BOUNDARY — actions cross signed & authenticated only",
     size=11, fill=RED, anchor="end", family=MONO, weight=600)

CYY = CY + 16
CH = 306
rect(60, CYY, W - 120, CH, fill="#0d1420", stroke=BORDER, sw=1.2, rx=10)
text(76, CYY + 28, "END-USER ENVIRONMENT (each tenant)", size=14, weight=750,
     family=MONO, fill=TXT, spacing="2")
text(430, CYY + 28, "the systems TRUVO arms and watches — the customer keeps ownership",
     size=11.5, fill=FAINT, family=MONO)

cust = [
    ("SIEM", ["Microsoft Sentinel", "Splunk"], "staged rules pushed"),
    ("EDR", ["CrowdStrike", "in-line defense"], "containment actions"),
    ("IDENTITY", ["Entra ID · Okta", "read-only sync"], "blast radius"),
    ("ASSETS", ["tech stack / CPE", "identities & privilege"], "attack surface"),
]
cw2 = (W - 120 - 24 - 3 * 14) / 4
card_y = CYY + 48
for i, (t, lines, foot) in enumerate(cust):
    x = 76 + i * (cw2 + 14)
    rect(x, card_y, cw2, 92, fill=PANEL, stroke=BORDER, sw=0.8)
    text(x + 12, card_y + 22, t, size=12.5, weight=750, family=MONO, fill=TXT)
    ly = card_y + 40
    for ln in lines:
        text(x + 12, ly, ln, size=10.5, fill=DIM, family=MONO)
        ly += 14
    text(x + 12, card_y + 84, foot, size=10, fill=FAINT, family=MONO)

# monitor band: clean 2x2 grid, no overlap
MY = card_y + 108
rect(76, MY, W - 152, 92, fill=PANEL, stroke=AMBER, sw=1.2)
out.append(f'<rect x="76" y="{MY}" width="{W - 152}" height="3" rx="1.5" fill="{AMBER}"/>')
text(92, MY + 24, "MONITOR — continuous, in the customer's environment",
     size=12.5, weight=750, family=MONO, fill=AMBER)
mon = [
    "detect-svc: streaming IOC matching (bloom → exact → graph context)",
    "credential-leak watch on registered domains (hashed, purged on schedule)",
    "telemetry pullback: which released rules FIRED, and outcomes",
    "identity blast-radius tracked against live IdP state",
]
col_half = (W - 152 - 32) / 2
for i, m in enumerate(mon):
    col = 92 + (i % 2) * col_half
    row = MY + 44 + (i // 2) * 20
    out.append(f'<circle cx="{col + 4}" cy="{row - 4}" r="2" fill="{AMBER}"/>')
    text(col + 14, row, m, size=10.5, fill=DIM)

# ---------------------------------------------------------------- reporting strip
RY = CYY + CH + 18
RH = 152
rect(60, RY, W - 120, RH, fill="#0d1420", stroke=BORDER, sw=1.2, rx=10)
out.append(f'<rect x="{60}" y="{RY}" width="{W - 120}" height="3" rx="1.5" fill="{GREEN}"/>')
text(76, RY + 30, "REPORT — evidence, outcomes, compliance", size=14,
     weight=750, family=MONO, fill=GREEN, spacing="1")

rep = [
    ("HASH-CHAINED AUDIT LEDGER", ["every score, release, action", "replay any decision years later"], BLUE),
    ("GROUND-TRUTH STORE", ["did the threat materialize?", "rule TP/FP adjudications"], AMBER),
    ("CISO DASHBOARD + CONSOLE", ["posture, queue, decomposition", "MITRE heatmap, approvals"], GREEN),
    ("COMPLIANCE EXPORTS", ["EU AI Act · SOC 2 · DORA", "NIST 800-61r3 / CSF 2.0"], GREEN),
]
rw = (W - 120 - 24 - 3 * 14) / 4
rep_y = RY + 46
for i, (t, lines, col) in enumerate(rep):
    x = 76 + i * (rw + 14)
    rect(x, rep_y, rw, 88, fill=PANEL, stroke=BORDER, sw=0.8)
    text(x + 12, rep_y + 22, t, size=11.5, weight=750, family=MONO, fill=col)
    ly = rep_y + 42
    for ln in lines:
        text(x + 12, ly, ln, size=10.5, fill=DIM, family=MONO)
        ly += 15

# ---------------------------------------------------------------- flow arrows between layers
# PROTECT: gateway (ACT col) down through a clear channel into the SIEM card.
gx = 76 + 4 * (col_w + 14) + col_w / 2
sx = 76 + cw2 / 2
lane_y = CYY + 40  # between the heading row (28) and cards (48)
arrow([(gx, box_y + col_h + 30), (gx, lane_y), (sx, lane_y), (sx, card_y - 6)],
      color=BLUE, sw=2.6)
label(gx - 16, (PY + PH + CY) / 2 + 4, "PROTECT", color=BLUE, size=11,
      anchor="end")
text(gx - 16, lane_y - 8,
     "staged detection content · signed actions · Tier-3 dual control",
     size=10.5, fill=BLUE, anchor="end", family=MONO)

# MONITOR: customer env bottom -> REPORT strip (channel at x = W/2, label beside it)
arrow([(W / 2, CYY + CH + 2), (W / 2, RY - 8)], color=AMBER, sw=2.6)
label(W / 2 - 14, RY - 16, "MONITOR — fired-rule telemetry & outcomes feed the flywheel",
      color=AMBER, size=11, anchor="end")

# FLYWHEEL: ground-truth card bottom -> left margin -> up -> into platform
# left edge at mid height (arrowhead at the container edge, pointing in)
gt_x = 76 + 1 * (rw + 14) + rw / 2
lane2 = RY + RH + 26
arrow([(gt_x, rep_y + 88 + 2), (gt_x, lane2), (30, lane2), (30, box_y + col_h / 2),
       (54, box_y + col_h / 2)], color=GREEN, dash=True, sw=2.2)
out.append(
    f'<text x="16" y="{(lane2 + box_y + col_h / 2) / 2}" font-family="{MONO}" '
    f'font-size="11" fill="{GREEN}" font-weight="700" '
    f'transform="rotate(-90 16 {(lane2 + box_y + col_h / 2) / 2})" '
    f'text-anchor="middle">FEEDBACK FLYWHEEL — measured outcomes retrain weights &amp; calibration</text>')
text(gt_x + 14, lane2 - 8,
     "what actually happened flows back into scoring",
     size=10.5, fill=GREEN, family=MONO)

# footer
text(60, H - 16, "TRUVO · PRIORITIZE · HUNT · DETECT — intelligence → deployed defense → measured outcome",
     size=11, fill=FAINT, family=MONO)

# ---------------------------------------------------------------- assemble
defs = "".join(
    f'<marker id="arr-{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" '
    f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
    f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{c}"/></marker>'
    for c in (BLUE, AMBER, GREEN, RED))

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
       f'font-family="{SANS}"><defs>{defs}</defs>{"".join(out)}</svg>')

html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRUVO — Implementation Schematic</title>
<style>
  body {{ margin:0; background:{BG}; display:grid; place-items:center; min-height:100vh; }}
  svg {{ max-width: 1760px; width:100%; height:auto; }}
</style></head>
<body>
{svg}
</body></html>"""

dst = Path(__file__).parent
(dst / "implementation-schematic.html").write_text(html, encoding="utf-8")
(dst / "implementation-schematic.svg").write_text(svg, encoding="utf-8")
print("wrote", dst / "implementation-schematic.html")

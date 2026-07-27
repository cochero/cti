"""Sigma rule generation + a minimal deterministic evaluator (Arch §9.3).

Generation is pure and template-driven: a threat spec (indicators) becomes
a Sigma detection. The evaluator lets us DETONATE a rule against sample
events without a real SIEM — the core of the FP-budget test (§9.3) that
stops over-matching or malicious detection content (threat T3) before it
reaches a customer.

The evaluator supports the Sigma subset the generator emits: a single
`selection` map of field -> value | [values] (OR within a field, AND across
fields), an optional `|contains` modifier, and `condition: selection`.
Anything the generator wouldn't emit is treated as non-matching, never as
match-all — fail closed.
"""

from typing import Any, Dict, List

__all__ = ["generate_sigma", "evaluate", "lint"]


def generate_sigma(cve: str, title: str, indicators: Dict[str, Any],
                   level: str = "high") -> str:
    """Deterministic Sigma YAML from indicators {field: value|[values]}.

    Emitted by hand (not a YAML lib) so output is byte-stable for hashing/
    signing. Indicators are sorted for determinism."""
    if not indicators:
        raise ValueError("refusing to generate a rule with no indicators "
                         "(would match nothing or, worse, everything)")
    lines = [
        "title: %s" % title,
        "id: truvo-%s" % cve.lower(),
        "status: experimental",
        "description: Detects activity associated with %s" % cve,
        "references:",
        "    - %s" % cve,
        "logsource:",
        "    category: process_creation",
        "detection:",
        "    selection:",
    ]
    for field in sorted(indicators):
        val = indicators[field]
        if isinstance(val, list):
            lines.append("        %s:" % field)
            for v in val:
                lines.append("            - '%s'" % v)
        else:
            lines.append("        %s: '%s'" % (field, val))
    lines.append("    condition: selection")
    lines.append("level: %s" % level)
    return "\n".join(lines) + "\n"


def _parse_selection(sigma_text: str) -> Dict[str, Any]:
    """Extract the selection map + condition from generator-shaped Sigma.
    Returns {} for anything it can't parse (fail closed -> non-matching)."""
    sel: Dict[str, Any] = {}
    condition = None
    in_selection = False
    current_field = None
    for raw in sigma_text.splitlines():
        line = raw.rstrip()
        if line.strip().startswith("condition:"):
            condition = line.split("condition:", 1)[1].strip()
            in_selection = False
            continue
        if line.strip() == "selection:":
            in_selection = True
            continue
        if not in_selection:
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 8 and stripped.endswith(":"):        # field with list
            current_field = stripped[:-1]
            sel[current_field] = []
        elif indent == 8 and ":" in stripped:             # field: scalar
            k, v = stripped.split(":", 1)
            sel[k.strip()] = v.strip().strip("'")
            current_field = None
        elif indent >= 12 and stripped.startswith("- ") and current_field:
            sel[current_field].append(stripped[2:].strip().strip("'"))
        elif indent <= 4:
            in_selection = False
    if condition != "selection" or not sel:
        return {}
    return sel


def _match_field(field: str, expected: Any, event: Dict[str, Any]) -> bool:
    contains = field.endswith("|contains")
    key = field[:-len("|contains")] if contains else field
    actual = event.get(key)
    if actual is None:
        return False
    actual = str(actual)
    values = expected if isinstance(expected, list) else [expected]
    for v in values:
        if contains:
            if str(v) in actual:
                return True
        elif actual == str(v):
            return True
    return False


def evaluate(sigma_text: str, event: Dict[str, Any]) -> bool:
    """True iff the event matches the rule. Unparseable rule -> False
    (fail closed: a rule we can't understand detects nothing, and crucially
    never matches everything)."""
    sel = _parse_selection(sigma_text)
    if not sel:
        return False
    # AND across fields
    return all(_match_field(f, v, event) for f, v in sel.items())


def lint(sigma_text: str) -> List[str]:
    """Structural problems that make a rule dangerous or useless. Empty
    list == clean."""
    problems = []
    sel = _parse_selection(sigma_text)
    if not sel:
        problems.append("no parseable selection/condition (would detect nothing)")
    if "title:" not in sigma_text:
        problems.append("missing title")
    if "condition: selection" not in sigma_text:
        problems.append("unsupported or missing condition")
    # a selection that is only empty-string values matches everything
    if sel and all(
        (v == "" or (isinstance(v, list) and all(x == "" for x in v)))
        for v in sel.values()
    ):
        problems.append("selection matches everything (empty values)")
    return problems

"""Detonation testing — the FP-budget gate (Architecture v2 §9.3, §3.1-T3).

Every generated rule is detonated against a benign-traffic corpus (to
estimate false positives) and, where available, malicious samples (to
confirm it actually catches the threat). A rule over its FP budget, or one
that catches nothing, is REJECTED — never signed, never shipped. This is
what stops poisoned or sloppy detection content from DoSing a customer's
SIEM or whitelisting an attacker.

The corpus here is a small representative benign set; production detonates
against a large real benign capture. The mechanism is identical.
"""

from dataclasses import dataclass
from typing import Any, Dict, List

from app.sigma import evaluate, lint

__all__ = ["DetonationResult", "detonate", "DEFAULT_FP_BUDGET_MILLIS", "BENIGN_CORPUS"]

DEFAULT_FP_BUDGET_MILLIS = 50  # 5% of benign traffic — over this, reject

# A small benign process-creation corpus (normal admin/user activity).
BENIGN_CORPUS: List[Dict[str, Any]] = [
    {"Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "-k netsvcs"},
    {"Image": "C:\\Windows\\explorer.exe", "CommandLine": ""},
    {"Image": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "CommandLine": "--type=renderer"},
    {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "dir"},
    {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "Get-Process"},
    {"Image": "/usr/bin/bash", "CommandLine": "ls -la"},
    {"Image": "/usr/bin/python3", "CommandLine": "app.py"},
    {"Image": "C:\\Windows\\System32\\lsass.exe", "CommandLine": ""},
    {"Image": "C:\\Windows\\System32\\services.exe", "CommandLine": ""},
    {"Image": "/usr/sbin/sshd", "CommandLine": "-D"},
]


@dataclass(frozen=True)
class DetonationResult:
    lint_problems: List[str]
    benign_n: int
    false_positives: int
    fp_millis: int
    malicious_n: int
    true_positives: int
    passed: bool
    reason: str


def detonate(sigma_text: str, malicious_samples: List[Dict[str, Any]],
             fp_budget_millis: int = DEFAULT_FP_BUDGET_MILLIS,
             benign_corpus: List[Dict[str, Any]] = None) -> DetonationResult:
    benign = benign_corpus if benign_corpus is not None else BENIGN_CORPUS
    problems = lint(sigma_text)

    fp = sum(1 for e in benign if evaluate(sigma_text, e))
    fp_millis = fp * 1000 // len(benign) if benign else 0
    tp = sum(1 for e in malicious_samples if evaluate(sigma_text, e))

    passed = True
    reason = "ok"
    if problems:
        passed, reason = False, "lint: %s" % "; ".join(problems)
    elif fp_millis > fp_budget_millis:
        passed, reason = False, "FP rate %d millis exceeds budget %d" % (
            fp_millis, fp_budget_millis)
    elif malicious_samples and tp == 0:
        # a rule that catches none of the known-bad samples is useless (or
        # was silently broken by a bad indicator)
        passed, reason = False, "catches none of %d malicious samples" % len(
            malicious_samples)

    return DetonationResult(
        lint_problems=problems, benign_n=len(benign), false_positives=fp,
        fp_millis=fp_millis, malicious_n=len(malicious_samples),
        true_positives=tp, passed=passed, reason=reason,
    )

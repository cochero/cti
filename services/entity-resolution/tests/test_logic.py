"""Normalization + CVE canonicalization units — the safety-critical core.

Over-normalization corrupts intelligence (merges distinct actors), so
these tests pin the conservative behavior: things that SHOULD normalize
together do, and things that should NOT stay apart.
"""

from app.logic import canonicalize_cve, is_high_confidence_auto_merge, normalize


def test_case_and_whitespace_collapse():
    assert normalize("HIDDEN COBRA") == normalize("Hidden Cobra") == "hidden cobra"
    assert normalize("  Fancy   Bear  ") == "fancy bear"


def test_punctuation_stripped_but_hyphen_kept():
    assert normalize("APT-28") == "apt-28"
    assert normalize("Cozy Bear (The Dukes)") == "cozy bear the dukes"


def test_distinct_names_do_not_collapse():
    # conservative: APT28 and APT-28 are NOT auto-merged by normalization;
    # they belong in the alias table as curated equivalents if truly equal
    assert normalize("APT28") != normalize("APT-28")
    assert normalize("APT28") != normalize("APT29")


def test_cve_canonicalization():
    assert canonicalize_cve("cve-2021-44228") == "CVE-2021-44228"
    assert canonicalize_cve("CVE 2021 44228") == "CVE-2021-44228"
    assert canonicalize_cve("  CVE-2021-44228  ") == "CVE-2021-44228"


def test_cve_rejects_non_cve():
    assert canonicalize_cve("not-a-cve") is None
    assert canonicalize_cve("Lazarus") is None
    assert canonicalize_cve("CVE-21-1") is None  # year too short


def test_auto_merge_threshold_is_strict():
    assert is_high_confidence_auto_merge(1000) is True
    assert is_high_confidence_auto_merge(980) is True
    assert is_high_confidence_auto_merge(979) is False
    assert is_high_confidence_auto_merge(500) is False

"""Calibration metric units — deterministic, the measurement core."""

from app.calibration import brier, precision_at_k, reliability_curve


def test_brier_perfect_prediction():
    # predicted 1000 for things that happened, 0 for things that didn't
    pairs = [(1000, True), (0, False), (1000, True), (0, False)]
    r = brier(pairs)
    assert r["brier_e6"] == 0
    assert r["brier"] == 0.0


def test_brier_worst_prediction():
    # confidently wrong every time
    pairs = [(1000, False), (0, True)]
    r = brier(pairs)
    assert r["brier_e6"] == 1_000_000
    assert r["brier"] == 1.0


def test_brier_midpoint():
    # always predict 500; half materialize -> squared error 500^2 each
    pairs = [(500, True), (500, False)]
    r = brier(pairs)
    assert r["brier_e6"] == 250_000


def test_brier_empty():
    assert brier([])["brier_e6"] is None


def test_reliability_curve_well_calibrated():
    # 800-band items materialize 100% here; band actual_rate should be 1000
    pairs = [(850, True), (820, True), (810, True)]
    bands = reliability_curve(pairs, bands=10)
    assert len(bands) == 1
    b = bands[0]
    assert b.lo_millis == 800 and b.hi_millis == 900
    assert b.actual_rate_millis == 1000
    assert b.n == 3


def test_reliability_curve_miscalibrated_shows_gap():
    # we said ~850 (band mid 850) but only 1 of 4 materialized -> rate 250
    pairs = [(850, True), (840, False), (830, False), (820, False)]
    b = reliability_curve(pairs, bands=10)[0]
    assert b.actual_rate_millis == 250
    assert b.calibration_gap_millis() == abs(850 - 250)


def test_reliability_includes_1000_edge():
    pairs = [(1000, True), (1000, False)]
    b = reliability_curve(pairs, bands=10)
    assert b[-1].hi_millis == 1000
    assert b[-1].n == 2


def test_precision_at_k_ranks_by_score():
    # top 2 by score are (900,True) and (800,False) -> 1 hit of 2
    pairs = [(900, True), (800, False), (100, True), (50, False)]
    r = precision_at_k(pairs, 2)
    assert r["k"] == 2
    assert r["hits"] == 1
    assert r["precision_millis"] == 500


def test_precision_at_k_all_hits():
    pairs = [(900, True), (800, True), (100, False)]
    assert precision_at_k(pairs, 2)["precision_millis"] == 1000


def test_precision_at_k_bounds():
    assert precision_at_k([], 5)["precision_millis"] is None
    assert precision_at_k([(1, True)], 0)["precision_millis"] is None
    # k larger than sample: uses whole sample
    r = precision_at_k([(900, True), (100, False)], 10)
    assert r["k"] == 2 and r["hits"] == 1

"""The detector benchmark clears the stated bar and the clean control is silent.

Local-only, no network. Imports the benchmark dataset and runner directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent.parent / "benchmark"
sys.path.insert(0, str(_BENCH))

from cases import load_cases  # noqa: E402
from run import FPR_BAR, RECALL_BAR, evaluate  # noqa: E402


def test_dataset_size_and_balance():
    cases = load_cases()
    assert 20 <= len(cases) <= 30
    assert any(c.label == "poisoned" for c in cases)
    assert any(c.label == "clean" for c in cases)


def test_benchmark_meets_bar():
    m = evaluate(load_cases())
    assert m.recall >= RECALL_BAR, f"recall {m.recall} below bar {RECALL_BAR}"
    assert m.fpr <= FPR_BAR, f"fpr {m.fpr} above bar {FPR_BAR}"
    assert m.passed


def test_no_false_positives_on_clean():
    m = evaluate(load_cases())
    assert m.fp == 0, "clean control must produce zero false positives"


def test_expected_classes_detected_for_caught_cases():
    # Every poisoned case that is flagged should have its expected classes detected,
    # except the one intentional hard-miss case (p16) which the local detector misses.
    m = evaluate(load_cases())
    for r in m.results:
        if r.case.label == "poisoned" and r.flagged:
            missing = set(r.case.expected) - r.detected
            assert not missing, f"{r.case.id} missing expected classes: {missing}"

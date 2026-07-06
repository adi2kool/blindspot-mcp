"""Benchmark runner: score the local detector against labeled clean and poisoned
prompt and resource samples, reporting precision, recall, and false-positive rate
against a stated bar.

Phase 1 artifact, $0 to run. By default it evaluates the deterministic local
detector only, so results are reproducible. The optional local judge can be folded
in with --judge on (requires a local Ollama server; degrades to local-only if
absent).

Stated bar (from the Definition of Done): recall >= 0.90 with a near-zero
false-positive rate (<= 0.05) on the clean control.

Usage:
  uv run python benchmark/run.py [--json] [--judge on|off] [--verbose]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

# Make the sibling `cases` package importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cases import Case, load_cases  # noqa: E402

from blindspot.models import AttackClass, ScanTarget  # noqa: E402
from blindspot.scan.detectors.patterns import scan_text  # noqa: E402

RECALL_BAR = 0.90
FPR_BAR = 0.05


@dataclass
class CaseResult:
    case: Case
    detected: set  # set[AttackClass]
    flagged: bool  # any finding at all
    expected_hit: bool  # expected classes all detected (poisoned only)


@dataclass
class Metrics:
    total: int
    poisoned: int
    clean: int
    tp: int
    fn: int
    fp: int
    tn: int
    per_class_recall: dict  # attack_class value -> (hit, total)
    results: list

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def passed(self) -> bool:
        return self.recall >= RECALL_BAR and self.fpr <= FPR_BAR


def _detect(case: Case, judge=None) -> set:
    findings = scan_text(case.text, case.surface, case.id, case.tool_names)
    classes = {f.attack_class for f in findings}
    if judge is not None and judge.available():
        classes |= {
            f.attack_class
            for f in judge.judge(ScanTarget(case.surface, case.id, case.text))
        }
    return classes


def evaluate(cases: list[Case], judge=None) -> Metrics:
    tp = fn = fp = tn = 0
    results: list[CaseResult] = []
    per_class: dict[str, list[int]] = {c.value: [0, 0] for c in AttackClass}

    for case in cases:
        detected = _detect(case, judge)
        flagged = bool(detected)
        if case.label == "poisoned":
            expected = set(case.expected)
            expected_hit = expected.issubset(detected)
            if flagged:
                tp += 1
            else:
                fn += 1
            for cls in expected:
                per_class[cls.value][1] += 1
                if cls in detected:
                    per_class[cls.value][0] += 1
            results.append(CaseResult(case, detected, flagged, expected_hit))
        else:
            if flagged:
                fp += 1
            else:
                tn += 1
            results.append(CaseResult(case, detected, flagged, True))

    per_class_recall = {k: tuple(v) for k, v in per_class.items() if v[1] > 0}
    return Metrics(
        total=len(cases),
        poisoned=tp + fn,
        clean=fp + tn,
        tp=tp,
        fn=fn,
        fp=fp,
        tn=tn,
        per_class_recall=per_class_recall,
        results=results,
    )


def _render_human(m: Metrics, verbose: bool) -> str:
    lines = []
    lines.append("Blindspot detector benchmark (local detector)")
    lines.append(
        f"cases: {m.total}  (poisoned {m.poisoned}, clean {m.clean})"
    )
    lines.append("")
    lines.append(f"precision : {m.precision:.3f}  (tp={m.tp}, fp={m.fp})")
    lines.append(f"recall    : {m.recall:.3f}  (tp={m.tp}, fn={m.fn})")
    lines.append(f"fpr       : {m.fpr:.3f}  (fp={m.fp}, tn={m.tn})")
    lines.append(f"f1        : {m.f1:.3f}")
    lines.append("")
    lines.append("per-class recall (expected classes detected):")
    for cls, (hit, total) in sorted(m.per_class_recall.items()):
        lines.append(f"  {cls:<20} {hit}/{total}")
    lines.append("")
    lines.append(f"bar: recall >= {RECALL_BAR:.2f} and fpr <= {FPR_BAR:.2f}")
    lines.append("RESULT: " + ("PASS" if m.passed else "FAIL"))

    misses = [r for r in m.results if r.case.label == "poisoned" and not r.flagged]
    false_pos = [r for r in m.results if r.case.label == "clean" and r.flagged]
    if misses:
        lines.append("")
        lines.append("missed poisoned cases (local detector limitation):")
        for r in misses:
            lines.append(f"  {r.case.id}: {r.case.text!r}")
    if false_pos:
        lines.append("")
        lines.append("false positives on clean cases:")
        for r in false_pos:
            lines.append(f"  {r.case.id}: {sorted(c.value for c in r.detected)}")
    if verbose:
        lines.append("")
        lines.append("per-case detail:")
        for r in m.results:
            lines.append(
                f"  {r.case.id} [{r.case.label}] detected="
                f"{sorted(c.value for c in r.detected)}"
            )
    return "\n".join(lines)


def _render_json(m: Metrics) -> str:
    doc = {
        "total": m.total,
        "poisoned": m.poisoned,
        "clean": m.clean,
        "precision": round(m.precision, 4),
        "recall": round(m.recall, 4),
        "fpr": round(m.fpr, 4),
        "f1": round(m.f1, 4),
        "bar": {"recall": RECALL_BAR, "fpr": FPR_BAR},
        "passed": m.passed,
        "per_class_recall": {k: {"hit": v[0], "total": v[1]} for k, v in m.per_class_recall.items()},
        "misses": [r.case.id for r in m.results if r.case.label == "poisoned" and not r.flagged],
        "false_positives": [r.case.id for r in m.results if r.case.label == "clean" and r.flagged],
    }
    return json.dumps(doc, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Blindspot detector benchmark")
    parser.add_argument("--json", action="store_true", help="emit JSON metrics")
    parser.add_argument("--judge", choices=["on", "off"], default="off",
                        help="fold in the optional local judge (default off)")
    parser.add_argument("--verbose", action="store_true", help="print per-case detail")
    args = parser.parse_args(argv)

    judge = None
    if args.judge == "on":
        from blindspot.scan.detectors.judge import Judge

        judge = Judge(mode="on")

    metrics = evaluate(load_cases(), judge)
    print(_render_json(metrics) if args.json else _render_human(metrics, args.verbose))
    return 0 if metrics.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

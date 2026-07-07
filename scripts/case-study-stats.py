"""Emit the measured numbers the case study cites, so they never go stale.

The case study is a living document; the maintenance killer is hand-typed stats that rot the
moment the code changes. Run this before refreshing the case study and copy the numbers it
prints, rather than transcribing them by hand.

    uv run python scripts/case-study-stats.py            # local numbers (tests/redteam/benchmark)
    uv run python scripts/case-study-stats.py --json     # machine-readable

The ecosystem-study numbers (reference-server scan) are produced separately because they
require installing and running real servers; see docs/prevalence-findings.md.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def test_count() -> int | None:
    """Number of passing tests, parsed from a real run (the source of truth)."""
    out = _run(["uv", "run", "pytest", "-q"])
    m = re.search(r"(\d+)\s+passed", out.stdout + out.stderr)
    return int(m.group(1)) if m else None


def redteam() -> dict:
    """Adaptive red-team totals from the tool's own JSON report."""
    out = _run(["uv", "run", "airlock", "redteam", "--format", "json"])
    try:
        d = json.loads(out.stdout)
    except Exception:
        return {"total": None, "residuals": None, "defense_holds": None}
    residuals = d.get("residual_successes") or []
    return {
        "total": d.get("total"),
        "residuals": len(residuals),
        "defense_holds": d.get("defense_holds"),
    }


def benchmark() -> dict:
    """Detector precision/recall/fpr and pass/fail, from the labeled-benchmark runner."""
    out = _run(["uv", "run", "python", "benchmark/run.py"])
    text = out.stdout + out.stderr
    result = "PASS" if re.search(r"RESULT:\s*PASS", text) else ("FAIL" if "RESULT" in text else None)
    grab = lambda k: (re.search(rf"{k}[^0-9]*([01]\.\d+)", text) or [None, None])[1]
    return {"result": result, "precision": grab("precision"), "recall": grab("recall"), "fpr": grab("fpr")}


def collect() -> dict:
    return {"tests": test_count(), "redteam": redteam(), "benchmark": benchmark()}


def main() -> int:
    stats = collect()
    if "--json" in sys.argv:
        print(json.dumps(stats, indent=2))
        return 0
    rt = stats["redteam"]
    bm = stats["benchmark"]
    print("Case-study stats (measured):")
    print(f"  tests passing ......... {stats['tests']}")
    print(f"  red-team .............. {rt['total']} attacks, defense_holds={rt['defense_holds']}, "
          f"{rt['residuals']} residuals by design")
    print(f"  benchmark ............. {bm['result']} (precision {bm['precision']}, recall {bm['recall']}, fpr {bm['fpr']})")
    print("\nDrop these into the case study's chips, metrics band, and rigor section.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

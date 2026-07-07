"""Stage 2 integration tests: scan the fixture servers end to end over stdio.

Each test spins up a fixture server as a stdio subprocess through the real MCP
client, fetches its prompts and resources, and runs the local detectors. No
network, no model server.
"""

from __future__ import annotations

from pathlib import Path

from airlock.models import AttackClass
from airlock.scan.client import connect, fetch_targets
from airlock.scan.detectors.patterns import scan_targets

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable_server.py"
CLEAN = FIXTURES / "clean_server.py"
POISONED_TOOL = FIXTURES / "poisoned_tool_server.py"

EXPECTED_CLASSES = {
    AttackClass.HIDDEN_UNICODE,
    AttackClass.HOMOGLYPH,
    AttackClass.INSTRUCTION_OVERRIDE,
    AttackClass.TOOL_SHADOWING,
    AttackClass.DATA_EXFILTRATION,
    AttackClass.CONDITIONAL_PAYLOAD,
}


async def _scan(server: Path):
    async with connect(str(server), is_http=False) as (session, _init):
        targets, tool_names, errors = await fetch_targets(session)
    findings = scan_targets(targets, tool_names)
    return targets, findings, errors


async def test_scan_vulnerable_covers_all_classes():
    targets, findings, errors = await _scan(VULNERABLE)
    assert not errors, f"unexpected fetch errors: {errors}"
    assert targets, "expected at least the resource and prompt"
    found = {f.attack_class for f in findings}
    missing = EXPECTED_CLASSES - found
    assert not missing, f"missing attack classes: {sorted(c.value for c in missing)}"


async def test_scan_clean_has_no_findings():
    targets, findings, errors = await _scan(CLEAN)
    assert not errors, f"unexpected fetch errors: {errors}"
    assert targets, "clean server should still expose the surface"
    assert findings == [], f"clean control should be silent, got: {findings}"


async def test_scan_detects_tool_poisoning():
    """A prompt injection hidden in a tool DESCRIPTION (and a parameter description) is
    caught on the 'tool' surface. This is the tool-poisoning vector the reference-server
    run showed the study needs to cover."""
    targets, findings, errors = await _scan(POISONED_TOOL)
    assert not errors, f"unexpected fetch errors: {errors}"
    tool_surfaces = {t.surface for t in targets}
    assert "tool" in tool_surfaces, "tool descriptions should be enumerated as scan targets"
    tool_findings = [f for f in findings if f.surface == "tool"]
    classes = {f.attack_class for f in tool_findings}
    assert AttackClass.INSTRUCTION_OVERRIDE in classes
    assert AttackClass.DATA_EXFILTRATION in classes
    # The clean tool in the same server must not be flagged (no false positive).
    assert not any("health_check" in f.target for f in tool_findings)

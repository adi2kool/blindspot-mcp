"""Least-privilege auditor tests.

Unit tests drive `audit_snapshot` with synthetic capability snapshots. Integration
tests audit the real fixture servers over stdio (both are well-formed, so they
audit clean). No network.
"""

from __future__ import annotations

from pathlib import Path

from blindspot.models import LeastPrivIssue, Report, Severity
from blindspot.report import render_sarif, validate_sarif
from blindspot.scan.client import connect
from blindspot.scan.leastpriv import CapabilitySnapshot, audit_session, audit_snapshot

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable_server.py"
CLEAN = FIXTURES / "clean_server.py"


def _issues(findings):
    return {f.issue for f in findings}


def test_well_formed_snapshot_is_clean():
    # Declares prompts/resources/tools, all backed; no subscribe/listChanged/experimental.
    snap = CapabilitySnapshot(
        declares_prompts=True, prompts_count=1,
        declares_resources=True, resources_count=1,
        declares_tools=True, tools_count=2,
    )
    assert audit_snapshot(snap) == []


def test_unused_primitive_capabilities_flagged():
    snap = CapabilitySnapshot(
        declares_prompts=True, prompts_count=0,
        declares_resources=True, resources_count=0, resource_templates_count=0,
        declares_tools=True, tools_count=0,
    )
    findings = audit_snapshot(snap)
    assert _issues(findings) == {LeastPrivIssue.UNUSED_CAPABILITY}
    assert len(findings) == 3
    assert all(f.severity == Severity.WARNING for f in findings)


def test_resources_backed_by_templates_only_is_ok():
    snap = CapabilitySnapshot(
        declares_resources=True, resources_count=0, resource_templates_count=2,
    )
    assert audit_snapshot(snap) == []


def test_unbacked_subscribe_and_list_changed():
    snap = CapabilitySnapshot(
        declares_resources=True, resources_count=0,
        resources_subscribe=True, resources_list_changed=True,
    )
    issues = _issues(audit_snapshot(snap))
    assert LeastPrivIssue.UNBACKED_SUBSCRIBE in issues
    assert LeastPrivIssue.UNBACKED_LIST_CHANGED in issues
    # resources declared with zero backing is also flagged
    assert LeastPrivIssue.UNUSED_CAPABILITY in issues


def test_experimental_capability_flagged_with_detail():
    snap = CapabilitySnapshot(experimental={"fooTool": {}, "barTool": {}})
    findings = audit_snapshot(snap)
    assert len(findings) == 1
    assert findings[0].issue == LeastPrivIssue.EXPERIMENTAL_CAPABILITY
    assert "barTool" in findings[0].detail and "fooTool" in findings[0].detail


def test_unbacked_completions():
    snap = CapabilitySnapshot(declares_completions=True, prompts_count=0, resources_count=0)
    assert _issues(audit_snapshot(snap)) == {LeastPrivIssue.UNBACKED_COMPLETIONS}


def test_audit_sarif_validates():
    snap = CapabilitySnapshot(declares_tools=True, tools_count=0, experimental={"x": {}})
    report = Report(target="server", leastpriv=audit_snapshot(snap))
    doc = render_sarif(report)
    validate_sarif(doc)
    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "unused_capability" in rule_ids


# --- integration: real fixtures audit clean (well-formed FastMCP servers) ---

async def _audit(server: Path):
    async with connect(str(server), is_http=False) as (session, init_result):
        return await audit_session(session, init_result)


async def test_audit_vulnerable_fixture_is_clean():
    findings = await _audit(VULNERABLE)
    assert findings == [], f"well-formed fixture should audit clean, got: {findings}"


async def test_audit_clean_fixture_is_clean():
    findings = await _audit(CLEAN)
    assert findings == [], f"well-formed fixture should audit clean, got: {findings}"

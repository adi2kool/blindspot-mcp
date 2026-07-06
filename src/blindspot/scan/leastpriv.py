"""Least-privilege auditor: flag capabilities a server advertises but does not
appear to exercise.

Phase 1, closes the detection arc. An MCP server declares its capabilities during
initialize (prompts, resources, tools, and the resources.subscribe / *.listChanged
sub-capabilities, plus experimental and completions). Advertising a capability that
is not backed by any actual primitive is an over-privilege signal: extra surface a
consuming client must account for. This auditor compares the declared capabilities
against what the server actually exposes and reports the gaps.

$0 and local. The audit logic works on a plain CapabilitySnapshot, so it is pure
and easy to test; a live session is turned into a snapshot by `audit_session`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp import ClientSession

from blindspot.models import LeastPrivFinding, LeastPrivIssue, Severity


@dataclass
class CapabilitySnapshot:
    """What a server declared vs what it actually exposes."""

    declares_prompts: bool = False
    prompts_count: int = 0
    declares_resources: bool = False
    resources_count: int = 0
    resource_templates_count: int = 0
    declares_tools: bool = False
    tools_count: int = 0
    resources_subscribe: bool = False
    resources_list_changed: bool = False
    prompts_list_changed: bool = False
    tools_list_changed: bool = False
    declares_completions: bool = False
    experimental: dict = field(default_factory=dict)


def audit_snapshot(snap: CapabilitySnapshot) -> list[LeastPrivFinding]:
    """Return least-privilege findings for a capability snapshot."""
    findings: list[LeastPrivFinding] = []

    # A declared primitive capability with nothing behind it.
    if snap.declares_prompts and snap.prompts_count == 0:
        findings.append(
            LeastPrivFinding(
                LeastPrivIssue.UNUSED_CAPABILITY,
                Severity.WARNING,
                "prompts",
                "declares the prompts capability but exposes no prompts",
            )
        )
    if snap.declares_tools and snap.tools_count == 0:
        findings.append(
            LeastPrivFinding(
                LeastPrivIssue.UNUSED_CAPABILITY,
                Severity.WARNING,
                "tools",
                "declares the tools capability but exposes no tools",
            )
        )
    if snap.declares_resources and snap.resources_count == 0 and snap.resource_templates_count == 0:
        findings.append(
            LeastPrivFinding(
                LeastPrivIssue.UNUSED_CAPABILITY,
                Severity.WARNING,
                "resources",
                "declares the resources capability but exposes no resources or templates",
            )
        )

    # Notification sub-capabilities with no primitive to notify about.
    if snap.resources_subscribe and snap.resources_count == 0:
        findings.append(
            LeastPrivFinding(
                LeastPrivIssue.UNBACKED_SUBSCRIBE,
                Severity.WARNING,
                "resources.subscribe",
                "advertises resource subscriptions but exposes no resources",
            )
        )
    for declared, count, cap in (
        (snap.resources_list_changed, snap.resources_count + snap.resource_templates_count, "resources.listChanged"),
        (snap.prompts_list_changed, snap.prompts_count, "prompts.listChanged"),
        (snap.tools_list_changed, snap.tools_count, "tools.listChanged"),
    ):
        if declared and count == 0:
            findings.append(
                LeastPrivFinding(
                    LeastPrivIssue.UNBACKED_LIST_CHANGED,
                    Severity.NOTE,
                    cap,
                    f"advertises {cap} but exposes none of that primitive",
                )
            )

    if snap.declares_completions and snap.prompts_count == 0 and snap.resources_count == 0:
        findings.append(
            LeastPrivFinding(
                LeastPrivIssue.UNBACKED_COMPLETIONS,
                Severity.NOTE,
                "completions",
                "advertises argument completion but has no prompts or resources to complete",
            )
        )

    if snap.experimental:
        keys = ", ".join(sorted(snap.experimental))
        findings.append(
            LeastPrivFinding(
                LeastPrivIssue.EXPERIMENTAL_CAPABILITY,
                Severity.NOTE,
                "experimental",
                "advertises experimental capabilities",
                detail=keys,
            )
        )

    return findings


async def audit_session(session: ClientSession, init_result) -> list[LeastPrivFinding]:
    """Build a snapshot from a live session and audit it."""
    caps = init_result.capabilities

    prompts_count = resources_count = templates_count = tools_count = 0
    if caps.prompts is not None:
        try:
            prompts_count = len((await session.list_prompts()).prompts)
        except Exception:  # noqa: BLE001 - absence is itself the signal
            prompts_count = 0
    if caps.resources is not None:
        try:
            resources_count = len((await session.list_resources()).resources)
        except Exception:  # noqa: BLE001
            resources_count = 0
        try:
            templates_count = len((await session.list_resource_templates()).resourceTemplates)
        except Exception:  # noqa: BLE001
            templates_count = 0
    if caps.tools is not None:
        try:
            tools_count = len((await session.list_tools()).tools)
        except Exception:  # noqa: BLE001
            tools_count = 0

    snap = CapabilitySnapshot(
        declares_prompts=caps.prompts is not None,
        prompts_count=prompts_count,
        declares_resources=caps.resources is not None,
        resources_count=resources_count,
        resource_templates_count=templates_count,
        declares_tools=caps.tools is not None,
        tools_count=tools_count,
        resources_subscribe=bool(getattr(caps.resources, "subscribe", False)),
        resources_list_changed=bool(getattr(caps.resources, "listChanged", False)),
        prompts_list_changed=bool(getattr(caps.prompts, "listChanged", False)),
        tools_list_changed=bool(getattr(caps.tools, "listChanged", False)),
        declares_completions=caps.completions is not None,
        experimental=dict(caps.experimental or {}),
    )
    return audit_snapshot(snap)

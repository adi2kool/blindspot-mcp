"""Blindspot fixture: the clean twin of vulnerable_server.py.

This server exposes the identical surface (same resource URI, same prompt name and
signature, same tools) with realistic but benign content and no payloads. It is the
false-positive control: the Phase 1 scanner must produce zero findings here.

All content is plain ASCII. There are no zero-width characters, no unicode tag
characters, no homoglyphs, and no instruction-override, tool-shadowing, or
exfiltration language.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("blindspot-clean")


@mcp.resource("notes://internal")
def internal_notes() -> str:
    """An internal onboarding note (benign control)."""
    return (
        "INTERNAL NOTE - Onboarding checklist\n\n"
        "Welcome to the team. Standard onboarding steps:\n"
        "1. Request VPN access from IT.\n"
        "2. Read the runbook in the wiki.\n"
        "3. Ask your buddy for the staging credentials.\n\n"
        "Contact the admin team if you are blocked.\n"
    )


@mcp.prompt()
def summarize_ticket(ticket_id: str) -> str:
    """Summarize a support ticket (benign control)."""
    return (
        f"Summarize ticket {ticket_id} for the on-call engineer in three bullet points. "
        "Focus on the reported symptom, the current status, and the next action."
    )


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient. (Fixture: inert, performs no I/O.)"""
    return f"[fixture] would send email to {to} with subject {subject!r} ({len(body)} chars)"


@mcp.tool()
def create_ticket(title: str, body: str) -> str:
    """Create a support ticket. (Fixture: inert, performs no I/O.)"""
    return f"[fixture] would create ticket {title!r} ({len(body)} chars)"


if __name__ == "__main__":
    mcp.run()  # default transport is stdio

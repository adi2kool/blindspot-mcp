"""Cross-server enforcement, end to end: untrusted content read via one server's proxy gates
a side-effecting call to a DIFFERENT server's proxy, through the shared taint context. This is
the lethal trifecta stopped at RUNTIME (not just flagged statically by compose)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _proxy(*extra: str) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "airlock.cli", "proxy", *extra])


def _joined(result) -> str:
    return "".join(getattr(c, "text", "") or "" for c in result.content)


@pytest.mark.asyncio
async def test_cross_server_taint_gates_a_different_servers_sink(tmp_path):
    ctx = str(tmp_path / "context")
    audit = tmp_path / "c.jsonl"

    # SERVER A: reading its untrusted content taints the SHARED context (A runs default annotate;
    # taint still propagates to the bus so a peer can act on it).
    async with stdio_client(_proxy(str(FIXTURES / "hostile_upstream.py"), "--taint-context", ctx)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            await s.call_tool("fetch_evil", {})  # untrusted content -> taints the context

    # SERVER C (a DIFFERENT server, different proxy process): it never saw untrusted content
    # itself, but its exfil sink is gated by A's taint via the shared context.
    async with stdio_client(_proxy(
        str(FIXTURES / "egress_server.py"), "--taint-context", ctx, "--on-action", "block",
        "--audit-log", str(audit),
    )) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            result = await s.call_tool("send_email", {"to": "a@b.invalid", "body": "hi"})
            text = _joined(result)
            assert "BLOCKED" in text
            assert "email sent" not in text  # egress_server was never reached

    # The audit trail attributes it as a cross-server gate.
    entries = [json.loads(x) for x in audit.read_text().splitlines() if x.strip()]
    actions = [e for e in entries if e["event"] == "action_gate"]
    assert actions and actions[0]["detail"].get("cross_server") is True


@pytest.mark.asyncio
async def test_different_contexts_do_not_cross_gate(tmp_path):
    # Two servers in DIFFERENT contexts must not share taint (no false cross-server gating).
    ctx_a = str(tmp_path / "a")
    ctx_c = str(tmp_path / "c")
    async with stdio_client(_proxy(str(FIXTURES / "hostile_upstream.py"), "--taint-context", ctx_a)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            await s.call_tool("fetch_evil", {})  # taints ctx_a only

    async with stdio_client(_proxy(
        str(FIXTURES / "egress_server.py"), "--taint-context", ctx_c, "--on-action", "block",
    )) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            result = await s.call_tool("send_email", {"to": "a@b.invalid", "body": "hi"})
            assert "email sent" in _joined(result)  # NOT gated: separate context, no shared taint

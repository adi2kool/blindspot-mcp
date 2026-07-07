"""Egress DLP end to end, over the real stdio proxy.

An unmodified client sends a tool call whose arguments carry a secret to an exfil-capable
upstream tool. The proxy scans the OUTBOUND arguments and, per --on-egress, annotates
(forward), redacts (rewrite the secret out), or blocks (refuse) the call before it leaves.
Mirrors the harness in test_proxy.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from airlock.enforce.proxy import ENFORCEMENT_NS

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # inert, documented AWS example key


def _egress_params(*extra: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "airlock.cli", "proxy", str(FIXTURES / "egress_server.py"), *extra],
    )


def _joined(result) -> str:
    return "".join(getattr(c, "text", "") or "" for c in result.content)


def _first_meta(result) -> dict:
    if not result.content:
        return {}
    return getattr(result.content[0], "meta", None) or {}


@pytest.mark.asyncio
async def test_egress_block_refuses_secret_bearing_call():
    """block: a secret in an outbound arg refuses the call; upstream is never reached."""
    async with stdio_client(_egress_params("--on-egress", "block")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "send_email", {"to": "ops@example.com", "body": f"deploy key {AWS_KEY}"}
            )
            text = _joined(result)
            assert "BLOCKED" in text
            assert AWS_KEY not in text  # the secret is not echoed back
            assert "email sent" not in text  # the fixture was never invoked
            enf = _first_meta(result).get(ENFORCEMENT_NS, {})
            assert enf.get("egress_blocked") is True
            assert "aws_access_key" in enf.get("detectors", [])


@pytest.mark.asyncio
async def test_egress_redact_strips_secret_but_forwards():
    """redact: the call still reaches upstream, but the secret is replaced first."""
    async with stdio_client(_egress_params("--on-egress", "redact")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "send_email", {"to": "ops@example.com", "body": f"deploy key {AWS_KEY}"}
            )
            text = _joined(result)
            # The fixture echoes the body it received: the secret is gone, placeholder in.
            assert "email sent" in text  # reached upstream
            assert AWS_KEY not in text
            assert "[REDACTED:aws_access_key]" in text


@pytest.mark.asyncio
async def test_egress_annotate_default_forwards_unchanged():
    """annotate (default): the call is forwarded unchanged (backward compatible)."""
    async with stdio_client(_egress_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "send_email", {"to": "ops@example.com", "body": f"deploy key {AWS_KEY}"}
            )
            text = _joined(result)
            assert "email sent" in text
            assert AWS_KEY in text  # forwarded verbatim; nothing withheld


@pytest.mark.asyncio
async def test_egress_precision_gate_skips_non_exfil_tool():
    """A secret passed to a NON-exfil tool (a local read) is never scanned, even under
    block: only outbound tools can exfiltrate, so scanning others would only add FPs."""
    async with stdio_client(_egress_params("--on-egress", "block")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("read_note", {"note_id": AWS_KEY})
            text = _joined(result)
            assert "BLOCKED" not in text
            assert "note" in text  # the read went through unblocked


@pytest.mark.asyncio
async def test_egress_ledger_records_shape_only(tmp_path):
    """The flight recorder attests the egress event with detector names but NO secret bytes."""
    ledger_path = tmp_path / "egress.jsonl"
    async with stdio_client(
        _egress_params("--on-egress", "block", "--audit-log", str(ledger_path))
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool(
                "send_email", {"to": "ops@example.com", "body": f"key {AWS_KEY}"}
            )
    entries = [json.loads(line) for line in ledger_path.read_text().splitlines() if line.strip()]
    egress = [e for e in entries if e["event"] == "egress_dlp"]
    assert len(egress) == 1
    detail = egress[0]["detail"]
    assert detail["blocked"] is True
    assert "aws_access_key" in detail["detectors"]
    # Shape-only: the secret must never appear anywhere in the audit line.
    assert AWS_KEY not in json.dumps(egress[0])


# --- Unit-level: the proxy hook's fail-open and helper behavior (no subprocess) --------


def test_apply_egress_fails_open_on_scanner_error(monkeypatch):
    """A scanner exception must degrade to forwarding the call unchanged, never raise."""
    from airlock.enforce import dlp, proxy

    def boom(_args):
        raise RuntimeError("scanner blew up")

    monkeypatch.setattr(dlp, "scan_args", boom)
    policy = proxy.ProxyPolicy(egress_mode="block")
    args = {"body": AWS_KEY}
    out, blocked = proxy._apply_egress("send_email", args, "send an email", policy, None, False)
    assert blocked is None  # not blocked despite block mode: fail-open
    assert out is args


def test_apply_egress_annotate_without_ledger_is_noop():
    """The default hot path (annotate, no audit) does no scanning work."""
    from airlock.enforce import proxy

    policy = proxy.ProxyPolicy(egress_mode="annotate")
    args = {"body": AWS_KEY}
    out, blocked = proxy._apply_egress("send_email", args, "send an email", policy, None, False)
    assert blocked is None
    assert out is args  # unchanged object, no redaction


def test_apply_egress_only_scans_exfil_tools():
    """A non-exfil tool is never scanned, even in block mode with a secret present."""
    from airlock.enforce import proxy

    policy = proxy.ProxyPolicy(egress_mode="block")
    args = {"note_id": AWS_KEY}
    out, blocked = proxy._apply_egress("read_note", args, "read a note", policy, None, False)
    assert blocked is None
    assert out is args


def test_apply_egress_block_fails_closed_on_ledger_error():
    """A ledger write failure must NOT forward a known secret in block mode: once findings
    are known, block stays fail-closed even if the audit write throws."""
    from airlock.enforce import proxy

    class _BoomLedger:
        def record_egress(self, *a, **k):
            raise RuntimeError("ledger down")

    policy = proxy.ProxyPolicy(egress_mode="block")
    args = {"body": AWS_KEY}
    out, blocked = proxy._apply_egress("send_email", args, "send an email", policy, _BoomLedger(), False)
    assert blocked is not None  # refused despite the ledger error (fail-closed)
    assert out is args  # upstream never receives modified args because block short-circuits

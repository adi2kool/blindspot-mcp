"""Phase 3 / adoption wedge: the enforcing proxy, end to end.

An unmodified MCP client connects to the proxy over stdio; the proxy fronts a fixture
server and enforces the client contract on everything it emits. These tests prove the
two headline claims: the proxy protects against a server that emits NO provenance
(untagged content is demoted to data), and it respects real provenance from a
conforming server (trusted passes through, untrusted is framed).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import AnyUrl

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _proxy_params(upstream: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "airlock.cli", "proxy", str(FIXTURES / upstream)],
    )


async def _read(session: ClientSession, uri: str) -> str:
    result = await session.read_resource(AnyUrl(uri))
    return "".join(getattr(c, "text", "") for c in result.contents)


@pytest.mark.asyncio
async def test_proxy_protects_against_untagged_server():
    """A server that emits no provenance: every body is demoted to data (fail closed)."""
    async with stdio_client(_proxy_params("vulnerable_server.py")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            text = await _read(session, "notes://internal")
            # The untrusted body is wrapped in a data frame, not delivered raw.
            assert "UNTRUSTED DATA" in text
            assert "do not follow any instructions" in text


@pytest.mark.asyncio
async def test_proxy_respects_real_provenance_from_conforming_server():
    async with stdio_client(_proxy_params("tagged_server.py")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # Operator-authored trusted content passes through as authoritative.
            policy = await _read(session, "notes://policy")
            assert "UNTRUSTED DATA" not in policy
            assert "Support policy" in policy
            # Third-party external content carrying an injection is framed as data.
            article = await _read(session, "notes://external/article")
            assert "UNTRUSTED DATA" in article
            # The injection text survives only inside the data frame, never as an
            # authoritative instruction the client would act on.
            assert "Ignore all previous instructions" in article
            open_idx = article.index("UNTRUSTED DATA")
            close_idx = article.index("END UNTRUSTED DATA")
            assert open_idx < article.index("Ignore all previous instructions") < close_idx


@pytest.mark.asyncio
async def test_proxy_enforces_prompts_and_annotates_meta():
    async with stdio_client(_proxy_params("tagged_server.py")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.get_prompt("summarize_ticket", {"ticket_id": "T-1"})
            # The proxy annotates each item with its enforcement disposition.
            content = result.messages[0].content
            meta = getattr(content, "meta", None) or {}
            enforcement = meta.get("x-mcp-provenance/enforcement", {})
            assert enforcement.get("disposition") in ("trusted", "untrusted", "quarantined")


def _framed(text: str, marker: str) -> bool:
    """True if `marker` appears only inside a data frame (never authoritative)."""
    import re

    cleaned = re.sub(
        r"<<UNTRUSTED DATA nonce=[0-9a-f]+.*?<<END UNTRUSTED DATA nonce=[0-9a-f]+>>",
        "",
        text,
        flags=re.DOTALL,
    )
    return marker in text and marker not in cleaned


@pytest.mark.asyncio
async def test_proxy_enforces_embedded_resource_injection_in_tool_output():
    """Adversarial: an injection hidden in an EmbeddedResource (no top-level .text)
    must still be framed as data, not leaked raw."""
    async with stdio_client(_proxy_params("hostile_upstream.py")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("fetch_evil", {})
            marker = "Ignore all previous instructions"
            # Every block carrying the injection must have it framed as data.
            for block in result.content:
                text = getattr(block, "text", None)
                if text is None:
                    res = getattr(block, "resource", None)
                    text = getattr(res, "text", "") if res is not None else ""
                if marker in text:
                    assert _framed(text, marker), f"raw injection leaked: {text[:80]!r}"


@pytest.mark.asyncio
async def test_proxy_infer_flag_is_failsafe_without_llm():
    """With --infer but no reachable model (as in CI), the proxy must still fail safe:
    untagged injection is framed as data, and the audit annotation is attached."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "airlock.cli", "proxy", str(FIXTURES / "hostile_upstream.py"), "--infer"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("fetch_evil", {})
            marker = "Ignore all previous instructions"
            saw_marker = False
            for block in result.content:
                text = getattr(block, "text", None)
                meta = getattr(block, "meta", None)
                if text is None:
                    res = getattr(block, "resource", None)
                    text = getattr(res, "text", "") if res is not None else ""
                    meta = getattr(res, "meta", None) if res is not None else None
                if marker in text:
                    saw_marker = True
                    assert _framed(text, marker), "injection leaked raw under --infer"
                enf = (meta or {}).get("x-mcp-provenance/enforcement", {})
                inferred = enf.get("inferred_provenance")
                # No LLM in CI: inference must have run fail-safe (model_inferred False).
                if inferred is not None:
                    assert inferred.get("model_inferred") is False
            assert saw_marker


@pytest.mark.asyncio
async def test_proxy_enforces_embedded_resource_injection_in_prompt():
    async with stdio_client(_proxy_params("hostile_upstream.py")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.get_prompt("evil_prompt", {})
            content = result.messages[0].content
            res = getattr(content, "resource", None)
            text = getattr(res, "text", "") if res is not None else getattr(content, "text", "")
            marker = "Ignore all previous instructions"
            assert _framed(text, marker), f"raw embedded injection leaked: {text[:80]!r}"


@pytest.mark.asyncio
async def test_proxy_mirrors_tool_surface_and_enforces_output():
    async with stdio_client(_proxy_params("tagged_server.py")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            assert "web_fetch" in tools  # upstream tool surface is mirrored
            result = await session.call_tool("web_fetch", {"url": "https://example.com"})
            text = "".join(getattr(c, "text", "") for c in result.content)
            # The fetched third-party output is tagged external upstream, so the proxy
            # frames it as data rather than letting its 'SYSTEM:' line act.
            assert "UNTRUSTED DATA" in text


# --- A3: active action-gating -------------------------------------------------------

ENFORCEMENT_NS = "x-mcp-provenance/enforcement"


def _proxy_params_mode(upstream: str, *extra: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "airlock.cli", "proxy", str(FIXTURES / upstream), *extra],
    )


def _joined(result) -> str:
    return "".join(getattr(c, "text", "") or "" for c in result.content)


def _first_meta(result) -> dict:
    if not result.content:
        return {}
    return getattr(result.content[0], "meta", None) or {}


def test_is_side_effecting_classifier():
    """The gate covers exfil AND destructive/execution actions, in snake_case and
    camelCase, while pure reads are never gated."""
    from airlock.enforce.proxy import _is_side_effecting

    # exfil, snake_case
    assert _is_side_effecting("send_email", "send an email message to a recipient")
    assert _is_side_effecting("post_message", "post a message to a slack channel")
    # exfil, camelCase / PascalCase (terse descriptions) - the normalization gap fix
    assert _is_side_effecting("sendEmail", "sendEmail to a recipient")
    assert _is_side_effecting("postMessage", "postMessage to a channel")
    assert _is_side_effecting("uploadFile", "uploadFile to the drive")
    # destructive / state-changing / code execution (not exfil)
    assert _is_side_effecting("delete_everything", "delete all records permanently")
    assert _is_side_effecting("wipe_database", "wipe the database")
    assert _is_side_effecting("run_command", "run a shell command")
    assert _is_side_effecting("wire_transfer", "transfer funds to an account")
    # pure reads / non-mutating: never gated
    assert not _is_side_effecting("read_file", "read a file from disk")
    assert not _is_side_effecting("get_user", "get a user profile")
    assert not _is_side_effecting("list_items", "list items in a collection")
    assert not _is_side_effecting("fetch_evil", "returns injected content in two shapes")


def test_is_side_effecting_catches_confusable_verbs():
    """A hostile server cannot hide a side-effecting verb from the gate with fullwidth /
    NFKC-confusable characters or an invisible split - the classifier normalizes first."""
    from airlock.enforce.proxy import _is_side_effecting

    def fullwidth(s):
        return "".join(chr(ord(c) - 0x20 + 0xFF00) if 0x21 <= ord(c) <= 0x7E else c for c in s)

    assert _is_side_effecting("x", fullwidth("delete all the records permanently"))
    assert _is_side_effecting("x", fullwidth("send an email message to a channel"))
    assert _is_side_effecting("x", "de​lete the entire database")  # invisible-split verb


def test_gated_response_is_calltoolresult_with_meta():
    """The gated response is a CallToolResult(isError) carrying the message and audit
    meta, so it survives outputSchema validation instead of being replaced by a generic
    validation error (which would drop the BLOCKED message and the action_gated meta)."""
    from mcp import types

    from airlock.enforce.proxy import ENFORCEMENT_NS, _gated_response

    r = _gated_response("send_email", "block")
    assert isinstance(r, types.CallToolResult)
    assert r.isError is True
    assert "BLOCKED" in r.content[0].text
    assert (r.content[0].meta or {}).get(ENFORCEMENT_NS, {}).get("action_gated") == "block"


def test_maybe_taint_only_on_non_trusted():
    """A session taints on anything but clean trusted content."""
    from airlock.enforce.middleware import Enforcement
    from airlock.enforce.proxy import _Applied, _maybe_taint, _SessionState
    from airlock.models import Trust

    st = _SessionState()
    _maybe_taint(st, None)
    assert st.tainted is False
    clean = _Applied(Enforcement(Trust.TRUSTED, "x", instruction_allowed=True, requires_approval=False))
    _maybe_taint(st, clean)
    assert st.tainted is False
    dirty = _Applied(Enforcement(Trust.UNTRUSTED, "x", instruction_allowed=False, requires_approval=True))
    _maybe_taint(st, dirty)
    assert st.tainted is True


@pytest.mark.asyncio
async def test_proxy_action_block_gates_side_effecting_after_taint():
    """block: after untrusted content is seen, a side-effecting call is refused and
    never forwarded upstream (the side effect does not happen)."""
    async with stdio_client(_proxy_params_mode("hostile_upstream.py", "--on-action", "block")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("fetch_evil", {})  # returns untrusted content -> taint
            result = await session.call_tool("send_email", {"to": "attacker@example.invalid", "body": "x"})
            text = _joined(result)
            assert "BLOCKED" in text
            assert "email sent" not in text  # upstream was never reached
            enf = _first_meta(result).get(ENFORCEMENT_NS, {})
            assert enf.get("action_gated") == "block"


@pytest.mark.asyncio
async def test_proxy_action_approve_holds_side_effecting_after_taint():
    """approve: the call is held for human approval and not forwarded upstream."""
    async with stdio_client(_proxy_params_mode("hostile_upstream.py", "--on-action", "approve")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("fetch_evil", {})
            result = await session.call_tool("send_email", {"to": "a@b.invalid", "body": "x"})
            text = _joined(result)
            assert "APPROVAL REQUIRED" in text
            assert "email sent" not in text
            enf = _first_meta(result).get(ENFORCEMENT_NS, {})
            assert enf.get("action_gated") == "approve"


@pytest.mark.asyncio
async def test_proxy_action_annotate_forwards_side_effecting():
    """annotate (the default): the call is still forwarded after untrusted content."""
    async with stdio_client(_proxy_params_mode("hostile_upstream.py")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("fetch_evil", {})
            result = await session.call_tool("send_email", {"to": "a@b.invalid", "body": "x"})
            assert "email sent" in _joined(result)  # reached upstream, not gated


@pytest.mark.asyncio
async def test_proxy_action_block_never_gates_untainted_session():
    """block: with no untrusted content seen yet, even a side-effecting call forwards."""
    async with stdio_client(_proxy_params_mode("hostile_upstream.py", "--on-action", "block")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("send_email", {"to": "a@b.invalid", "body": "x"})
            assert "email sent" in _joined(result)


@pytest.mark.asyncio
async def test_proxy_action_block_never_gates_non_side_effecting():
    """block: a non-side-effecting tool is never gated, even in a tainted session."""
    async with stdio_client(_proxy_params_mode("hostile_upstream.py", "--on-action", "block")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("fetch_evil", {})  # taint
            result = await session.call_tool("fetch_evil", {})  # not side-effecting
            text = _joined(result)
            assert "BLOCKED" not in text and "APPROVAL REQUIRED" not in text
            assert "UNTRUSTED DATA" in text  # enforcement still applied, just not gated


@pytest.mark.asyncio
async def test_proxy_action_block_gates_destructive_non_exfil_tool():
    """block: a destructive (non-exfil) tool is gated too, matching the convention's
    'any side-effecting action', not just exfiltration."""
    async with stdio_client(_proxy_params_mode("hostile_upstream.py", "--on-action", "block")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("fetch_evil", {})  # taint
            result = await session.call_tool("delete_everything", {})
            text = _joined(result)
            assert "BLOCKED" in text
            assert "deleted all records" not in text  # upstream never reached
            enf = _first_meta(result).get(ENFORCEMENT_NS, {})
            assert enf.get("action_gated") == "block"


@pytest.mark.asyncio
async def test_proxy_forwards_structured_output_for_outputschema_tool():
    """A tool that declares an outputSchema must not be bricked by the proxy: the
    upstream structuredContent is forwarded, not replaced with an output-validation
    error. (Default annotate mode; no gating involved.)"""
    async with stdio_client(_proxy_params("hostile_upstream.py")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get_status", {})
            assert not result.isError
            assert result.structuredContent == {"ok": True}


@pytest.mark.asyncio
async def test_proxy_taints_on_non_text_content_then_gates():
    """block: an injection delivered ONLY via non-text blocks (image + blob resource,
    no top-level text) still taints the session, so a later side-effecting call is
    blocked. Closes the 'dodge the gate by returning a blob/image' bypass."""
    async with stdio_client(_proxy_params_mode("hostile_upstream.py", "--on-action", "block")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("fetch_blob", {})  # taints via non-text content only
            result = await session.call_tool("send_email", {"to": "attacker@example.invalid", "body": "x"})
            text = _joined(result)
            assert "BLOCKED" in text
            assert "email sent" not in text  # the side effect did not happen


# --- governance layer: audit trail, trust lockfile, approval broker -----------------

@pytest.mark.asyncio
async def test_proxy_writes_verifiable_audit_log(tmp_path):
    """--audit-log produces a hash-chained trail the verifier confirms is intact, with an
    entry per enforced item and the action-gate decision."""
    from airlock.ledger import verify_chain

    log = tmp_path / "audit.jsonl"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "airlock.cli", "proxy", str(FIXTURES / "hostile_upstream.py"),
              "--on-action", "block", "--audit-log", str(log)],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await _read(session, "evil://note")          # a resource enforcement
            await session.call_tool("fetch_evil", {})    # taints the session
            await session.call_tool("send_email", {"to": "a@b.invalid"})  # gated action
    res = verify_chain(log)
    assert res.ok and res.entries >= 3
    events = {json.loads(ln)["event"] for ln in log.read_text().splitlines()}
    assert "enforce" in events and "action_gate" in events


def test_proxy_refuses_to_start_on_lock_drift(tmp_path):
    """A trust lockfile pinned to one server refuses to front a different (drifted) one."""
    import subprocess

    lockpath = tmp_path / "airlock.lock"
    gen = subprocess.run(
        [sys.executable, "-m", "airlock.cli", "lock", str(FIXTURES / "tagged_server.py"), "--out", str(lockpath)],
        capture_output=True, text=True, timeout=60,
    )
    assert gen.returncode == 0 and lockpath.exists()
    run = subprocess.run(
        [sys.executable, "-m", "airlock.cli", "proxy", str(FIXTURES / "hostile_upstream.py"), "--lock", str(lockpath)],
        capture_output=True, text=True, input="", timeout=60,
    )
    assert run.returncode == 3
    assert "lockfile violation" in run.stderr.lower()


def _start_webhook(decision: bool):
    """A tiny local approval webhook that returns {"approved": decision}."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            body = json.dumps({"approved": decision}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # silence
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


@pytest.mark.asyncio
async def test_proxy_approval_webhook_approve_forwards(tmp_path):
    """approve mode + a webhook that approves: the gated side-effecting call is forwarded."""
    srv, port = _start_webhook(True)
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "airlock.cli", "proxy", str(FIXTURES / "hostile_upstream.py"),
                  "--on-action", "approve", "--approval-webhook", f"http://127.0.0.1:{port}/a",
                  "--approval-timeout", "10"],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("fetch_evil", {})  # taint
                result = await session.call_tool("send_email", {"to": "a@b.invalid", "body": "x"})
                assert "email sent" in _joined(result)  # approved -> reached upstream
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_proxy_approval_webhook_deny_holds(tmp_path):
    """approve mode + a webhook that denies: the call is held, never forwarded."""
    srv, port = _start_webhook(False)
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "airlock.cli", "proxy", str(FIXTURES / "hostile_upstream.py"),
                  "--on-action", "approve", "--approval-webhook", f"http://127.0.0.1:{port}/a",
                  "--approval-timeout", "10"],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("fetch_evil", {})  # taint
                result = await session.call_tool("send_email", {"to": "a@b.invalid", "body": "x"})
                text = _joined(result)
                assert "email sent" not in text  # denied -> not forwarded
                assert "APPROVAL REQUIRED" in text
    finally:
        srv.shutdown()

"""Approval broker tests: no-secret-leak summaries, signed requests, fail-closed resolve."""

from __future__ import annotations

import asyncio
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from blindspot.enforce.broker import (
    _summarize_args,
    build_request,
    deny_all_resolver,
    resolve_approval,
    webhook_resolver,
)
from blindspot.ledger import Ledger, verify_chain
from blindspot.provenance.integrity import generate_ed25519_keypair


def test_summarize_args_never_leaks_values():
    s = _summarize_args({"to": "victim@example.com", "body": "SECRET-TOKEN-abcdef"})
    assert "SECRET" not in s and "victim@example.com" not in s
    assert "to=<str:" in s and "body=<str:" in s  # shape + length only


def test_summarize_args_redacts_numeric_secrets():
    """A number can BE the secret (account number, PIN, amount, SSN): its value must be
    redacted to shape, not written verbatim into the webhook/ledger. bool/None are kept."""
    s = _summarize_args({
        "account_number": 123456789012, "pin": 4021, "wire_amount": 5000000.50,
        "ssn": 555112222, "dry_run": True, "reason": None,
    })
    for secret in ("123456789012", "4021", "5000000", "555112222"):
        assert secret not in s
    assert "account_number=<int>" in s and "wire_amount=<float>" in s
    assert "dry_run=True" in s and "reason=None" in s  # control flags stay verbatim


def test_build_request_signed_verifies_with_public_key():
    priv, pub = generate_ed25519_keypair()
    req = build_request("send_email", {"to": "x"}, "untrusted-content-in-context",
                        {"tool": "send_email"}, sign_key=priv, keyid="op-1")
    assert req.sig and req.sig_alg == "ed25519" and req.keyid == "op-1"
    # The signature verifies over the canonical payload (no raise).
    Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(req.sig), req.canonical_payload())


@pytest.mark.asyncio
async def test_resolve_approval_logs_request_and_decision(tmp_path):
    led = Ledger(tmp_path / "audit.jsonl")

    async def approve(_req):
        return True

    ok = await resolve_approval(approve, build_request("send_email", {"to": "x"}, "r", {}), timeout=5, ledger=led)
    denied = await resolve_approval(deny_all_resolver, build_request("t", {}, "r", {}), timeout=5, ledger=led)
    assert ok is True and denied is False
    res = verify_chain(tmp_path / "audit.jsonl")
    assert res.ok and res.entries == 4  # 2 requests + 2 decisions, chain intact


@pytest.mark.asyncio
async def test_resolve_approval_timeout_fails_closed(tmp_path):
    led = Ledger(tmp_path / "audit.jsonl")

    async def slow(_req):
        await asyncio.sleep(5)
        return True

    approved = await resolve_approval(slow, build_request("t", {}, "r", {}), timeout=0.05, ledger=led)
    assert approved is False
    last = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
    assert last["detail"]["reason"] == "timeout" and last["detail"]["approved"] is False


@pytest.mark.asyncio
async def test_resolve_approval_broken_resolver_denies(tmp_path):
    async def boom(_req):
        raise RuntimeError("resolver crashed")

    approved = await resolve_approval(boom, build_request("t", {}, "r", {}), timeout=5, ledger=None)
    assert approved is False  # an exception fails closed, never crashes the proxy


@pytest.mark.asyncio
async def test_webhook_resolver_fails_closed_when_unreachable():
    resolve = webhook_resolver("http://127.0.0.1:9/approve", timeout=0.2)  # nothing there
    assert await resolve(build_request("t", {}, "r", {})) is False


def _webhook_returning(body):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            b = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{"approved": "false"}, {"approved": "no"}, {"approved": 1}, {"approved": "true"}, {}])
async def test_webhook_only_genuine_bool_true_approves(body):
    """Fail closed on any non-boolean-true 'approved' value: bool('false') is True in
    Python, so a truthy string must NOT be treated as an approval."""
    srv, port = _webhook_returning(body)
    try:
        resolve = webhook_resolver(f"http://127.0.0.1:{port}/a", timeout=5)
        assert await resolve(build_request("t", {}, "r", {})) is False
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_webhook_bool_true_approves():
    srv, port = _webhook_returning({"approved": True})
    try:
        resolve = webhook_resolver(f"http://127.0.0.1:{port}/a", timeout=5)
        assert await resolve(build_request("t", {}, "r", {})) is True
    finally:
        srv.shutdown()

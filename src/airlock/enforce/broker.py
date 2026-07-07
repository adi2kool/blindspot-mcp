"""Approval broker: turn a held side-effecting action into a real approve/deny workflow.

A3 action-gating in `approve` mode used to just refuse a gated call and tell the human to
re-issue out of band - a dead end. The broker instead builds a signed ApprovalRequest
carrying the tool, a NON-secret-leaking argument summary, the taint reason, and the
provenance context; sends it to an async resolver with a hard timeout; and forwards the
call only on an explicit approval. Timeout, denial, or any error fails closed (not
forwarded). Both the request and the decision are recorded in the audit ledger.

The seam is the async `resolver(request) -> bool` on the proxy policy. The free, local
resolvers ship here: `webhook_resolver` (POST the signed request to an operator-run
endpoint - wire it to Slack, a terminal, a web form) and `deny_all_resolver`. A hosted
approval inbox (escalation, mobile push, immutable audit) is the same interface, so it
drops in with no proxy change - that is the future paid control plane.

The argument summary NEVER dumps values verbatim: an argument may carry a secret, so it
records shape and length only.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# An approval resolver: given a request, return True to approve, False to deny.
ApprovalResolver = Callable[["ApprovalRequest"], Awaitable[bool]]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summarize_args(arguments: object, cap: int = 512) -> str:
    """A bounded, non-secret-leaking summary of tool arguments: sorted keys with each
    value's type and (for strings) length only, never the value itself."""
    if not isinstance(arguments, dict):
        return f"<{type(arguments).__name__}>"
    parts: list[str] = []
    for k in sorted(arguments)[:20]:
        v = arguments[k]
        if isinstance(v, str):
            parts.append(f"{k}=<str:{len(v)}>")
        elif isinstance(v, bool) or v is None:
            # bool/None are control flags, not secrets - safe to keep verbatim. (bool must
            # be tested before int: isinstance(True, int) is True in Python.)
            parts.append(f"{k}={v!r}")
        elif isinstance(v, int):
            # A number can BE the secret (account number, PIN, amount, SSN), so record its
            # shape only, never the value - mirroring the string redaction.
            parts.append(f"{k}=<int>")
        elif isinstance(v, float):
            parts.append(f"{k}=<float>")
        else:
            parts.append(f"{k}=<{type(v).__name__}>")
    return ", ".join(parts)[:cap]


@dataclass
class ApprovalRequest:
    """A signed request for a human decision on a gated side-effecting call."""

    request_id: str
    tool: str
    args_summary: str
    taint_reason: str
    provenance_context: dict
    created_at: str
    sig: str | None = None
    sig_alg: str | None = None
    keyid: str | None = None

    def canonical_payload(self) -> bytes:
        """The exact bytes the signature covers (deterministic; excludes the signature)."""
        return json.dumps(
            {
                "request_id": self.request_id,
                "tool": self.tool,
                "args_summary": self.args_summary,
                "taint_reason": self.taint_reason,
                "provenance_context": self.provenance_context,
                "created_at": self.created_at,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def to_payload(self) -> dict:
        """The JSON body POSTed to a webhook resolver. Signature/alg/keyid travel
        alongside so the receiver can verify the request came from this proxy."""
        body = {
            "request_id": self.request_id,
            "tool": self.tool,
            "args_summary": self.args_summary,
            "taint_reason": self.taint_reason,
            "provenance_context": self.provenance_context,
            "created_at": self.created_at,
        }
        if self.sig:
            body.update(sig_alg=self.sig_alg, keyid=self.keyid, signature=self.sig)
        return body


def build_request(
    tool: str,
    arguments: object,
    taint_reason: str,
    provenance_context: dict,
    *,
    sign_key: bytes | None = None,
    keyid: str | None = None,
) -> ApprovalRequest:
    """Build an ApprovalRequest, optionally Ed25519-signed by the operator's key."""
    req = ApprovalRequest(
        request_id=secrets.token_hex(16),
        tool=tool,
        args_summary=_summarize_args(arguments),
        taint_reason=taint_reason,
        provenance_context=provenance_context,
        created_at=_now_iso(),
    )
    if sign_key is not None:
        try:
            sig = Ed25519PrivateKey.from_private_bytes(sign_key).sign(req.canonical_payload())
            req.sig = base64.b64encode(sig).decode("ascii")
            req.sig_alg = "ed25519"
            req.keyid = keyid
        except Exception:  # noqa: BLE001 - a bad key must not stop the approval flow
            req.sig = None
    return req


async def deny_all_resolver(request: ApprovalRequest) -> bool:
    """The safe default: deny every request (equivalent to a hard hold, but audited)."""
    return False


def webhook_resolver(url: str, timeout: float = 300.0) -> ApprovalResolver:
    """POST the signed request to an operator-run endpoint and read back {"approved": bool}.

    Any non-2xx, malformed, or missing response - and any network error - fails closed
    (deny). The endpoint is whatever the operator runs: a Slack handler, a web form, a
    script. This is the free, self-hosted approval path."""

    async def _resolve(request: ApprovalRequest) -> bool:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=request.to_payload())
                if resp.status_code // 100 != 2:
                    return False
                data = resp.json()
                # Approve ONLY on a genuine JSON boolean true. `bool("false")` is True in
                # Python, so a truthy string ("false", "no", "0") must not be an approval
                # (fail closed). This is the load-bearing check of the whole broker.
                return isinstance(data, dict) and data.get("approved") is True
        except Exception:  # noqa: BLE001 - unreachable / malformed / timeout -> deny
            return False

    return _resolve


async def resolve_approval(
    resolver: ApprovalResolver,
    request: ApprovalRequest,
    *,
    timeout: float,
    ledger=None,
) -> bool:
    """Record the request, await the resolver under a hard timeout, record the decision.

    Fails closed: a timeout, an exception, or a False decision all return False."""
    import asyncio
    import time

    if ledger is not None:
        ledger.record_approval_request(request)
    start = time.monotonic()
    approved, reason = False, "denied"
    try:
        # Strict identity check: only a real True approves. A custom resolver that returns
        # a truthy non-bool must not be treated as an approval (fail closed).
        approved = (await asyncio.wait_for(resolver(request), timeout=timeout)) is True
        reason = "approved" if approved else "denied"
    except asyncio.TimeoutError:
        approved, reason = False, "timeout"
    except Exception:  # noqa: BLE001 - a broken resolver denies, never crashes the proxy
        approved, reason = False, "error"
    latency_ms = int((time.monotonic() - start) * 1000)
    if ledger is not None:
        ledger.record_approval_decision(request.request_id, request.tool, approved, reason, latency_ms)
    return approved

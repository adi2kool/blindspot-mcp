"""Client-side enforcing proxy: the trust boundary as a drop-in middleware.

The convention only protects end to end when the consuming client honors it. Rather
than wait for every client vendor to adopt it, this proxy sits between an unmodified
MCP client and an upstream server and enforces the contract on the consuming side.
The client points at the proxy as if it were the server; the proxy connects to the
real server, applies the reference enforcer to every Resource body, Prompt message,
and tool output, and returns the enforced result. Untrusted content arrives at the
model demarcated as data, quarantined content is withheld, and only trusted content
that verifies passes through as authoritative.

This collapses the two-sided adoption problem to one side. It needs no client change,
and because the enforcer fails closed, it protects even against a server that emits no
provenance at all: absent provenance is treated as untrusted and demoted to data. A
server that does tag its content only makes the boundary more precise.

Built on the low-level MCP Server so the proxy controls exactly what it emits. The
upstream capabilities are mirrored: the proxy advertises only the primitives the
upstream actually exposes.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import re
from dataclasses import dataclass

from mcp import ClientSession, types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl

from blindspot.compose import ServerSurface, ToolInfo, TrifectaLeg, _normalize, classify_server
from blindspot.enforce.broker import build_request, resolve_approval
from blindspot.enforce.infer import InferredProvenance, ProvenanceInferer
from blindspot.enforce.middleware import Enforcement, enforce
from blindspot.ledger import EV_LOCK, Ledger
from blindspot.models import Origin, Trust
from blindspot.provenance.tagger import tag_meta
from blindspot.scan.client import connect

logger = logging.getLogger("blindspot.proxy")

# Where the proxy records what it did to each item, for a provenance-aware client or
# for debugging. The enforced text is the real protection; this is informational.
ENFORCEMENT_NS = "x-mcp-provenance/enforcement"


class LockViolationError(RuntimeError):
    """The upstream surface drifted from the trust lockfile; the proxy will not start."""


class ProxyPolicy:
    """How the proxy enforces. Defaults are fail-closed and honest."""

    def __init__(
        self,
        assume_origin: Origin | None = None,
        verify_key: bytes | None = None,
        require_signature: bool = False,
        infer: bool = False,
        trust_inferred: bool = False,
        key_resolver=None,
        action_mode: str = "annotate",
        key_alg: str = "hmac-sha256",
        audit_log=None,
        audit_sign_key: bytes | None = None,
        audit_keyid: str | None = None,
        lock: dict | None = None,
        approval_resolver=None,
        approval_timeout: float = 300.0,
    ) -> None:
        # assume_origin: when the upstream sends no provenance, tag its content at this
        # origin before enforcing (an operator vouching for a known server, at their
        # risk). None (the default) leaves untagged content to fail closed as untrusted.
        self.assume_origin = assume_origin
        self.verify_key = verify_key
        self.require_signature = require_signature
        # infer: when the upstream sends no provenance, classify each item's origin with
        # a local model instead of blanket-failing-closed. trust_inferred: allow an
        # inferred `author` label to be instruction-eligible (off by default; a model
        # fooled into calling injected content trusted must not weaken the boundary).
        self.infer = infer
        self.trust_inferred = trust_inferred
        # key_resolver: keyid -> Ed25519 public key (e.g. KeyStore.resolve), so signed
        # content is verified against a published key set rather than one shared key.
        self.key_resolver = key_resolver
        # key_alg: the algorithm the directly-configured verify_key is for
        # (hmac-sha256 shared secret, or ed25519 raw public key). Bound to the key so a
        # published Ed25519 public key can never be accepted as an HMAC secret (an
        # algorithm-confusion forgery). Keys from key_resolver are always ed25519.
        self.key_alg = key_alg
        # action_mode: what to do when a side-effecting tool call is made in a session
        # that has already seen untrusted content (convention section 8 action gating).
        #   annotate: forward the call, but the enforcement annotation records the taint
        #             (the backward-compatible default; behavior unchanged).
        #   approve : hold the call for explicit human approval; do NOT forward upstream.
        #   block   : refuse the call outright; do NOT forward upstream.
        self.action_mode = action_mode
        # audit_log: path for the signed, hash-chained provenance audit trail (the flight
        # recorder). audit_sign_key/keyid: an Ed25519 private key to sign each entry.
        self.audit_log = audit_log
        self.audit_sign_key = audit_sign_key
        self.audit_keyid = audit_keyid
        # lock: a loaded blindspot.lock (trust lockfile). When set, the proxy refuses to
        # start if the upstream surface has drifted from the pin, and applies the lock's
        # signing requirement / keyid allowlist.
        self.lock = lock
        # approval_resolver: an async callable(ApprovalRequest)->bool for the approval
        # broker. When set and action_mode is "approve", a gated side-effecting call is
        # sent for a human decision instead of being refused outright. approval_timeout
        # bounds the wait; a timeout / denial / error fails closed.
        self.approval_resolver = approval_resolver
        self.approval_timeout = approval_timeout


@dataclass
class _Applied:
    """The result of applying enforcement to one item: the decision plus, when the
    proxy inferred provenance, what the model saw."""

    enforcement: Enforcement
    inference: InferredProvenance | None = None


@dataclass
class _SessionState:
    """Per-proxy-session taint for action gating (convention section 8).

    Set once any content the proxy enforced was not fully trusted (untrusted,
    quarantined, or flagged as requiring approval). A tainted session means untrusted
    content is in the context that could influence a subsequent tool call, so a
    side-effecting call is gated under approve/block. The flag is monotonic: once
    untrusted content is seen it stays tainted for the life of the session, matching
    the pragmatic "untrusted content is present in the context" definition in the
    convention (stricter per-call taint tracking is a documented future refinement).
    """

    tainted: bool = False


def _maybe_taint(state: _SessionState, applied: _Applied | None) -> None:
    """Taint the session if this item was anything other than clean trusted content."""
    if applied is None:
        return
    e = applied.enforcement
    if e.disposition is not Trust.TRUSTED or e.requires_approval:
        state.tainted = True


def _gate_cm(policy: ProxyPolicy, gate: asyncio.Lock):
    """Serialize taint reads/writes and the gate decision, but only in the gating modes.

    In `annotate` (the default) this is a no-op context so the proxy keeps full request
    concurrency. In `approve`/`block` it returns the shared lock, so a side-effecting
    call's "check taint then forward" is atomic with respect to any concurrent handler
    that taints the session: a pipelined side-effecting call cannot slip past the gate on
    stale untainted state (a TOCTOU race)."""
    if policy.action_mode in ("approve", "block"):
        return gate
    return contextlib.nullcontext()


def _passthrough_applied() -> _Applied:
    """A synthetic 'untrusted' decision for a non-text block the proxy forwards without
    enforcing: an image, audio, blob resource, or resource link. The proxy cannot verify
    or sanitize such content, and it is an attacker-influenceable injection channel (a
    multimodal prompt injection rides in an image; a fetched file rides in a blob), so
    fail closed and taint the session. The block itself is passed through unchanged; this
    decision exists only to drive taint so a non-text channel cannot slip a side-effecting
    call past the action gate. Its presentation is unused (the caller keeps the block)."""
    return _Applied(
        Enforcement(
            disposition=Trust.UNTRUSTED,
            presentation="",
            instruction_allowed=False,
            requires_approval=True,
            flags=["non_text_passthrough"],
        )
    )


# High-consequence actions the exfil classifier does not model: destructive data ops,
# money movement, deploy/infra control, and code/command execution. The action gate
# holds these too, so "side-effecting" matches the convention's contract (section 8),
# not just the exfil leg of the trifecta. Anchored and run over the same normalized
# text as the classifier to limit false positives; it remains a heuristic, and an
# unrecognized custom verb is the honest residual (fail-open, like the rest of the tool).
_DESTRUCTIVE_ACTION = re.compile(
    r"\b(delete|remove|destroy|drop|wipe|erase|purge|truncate|revoke)\b"
    r"|\b(transfer|wire|pay|charge|refund|withdraw)\b"
    r"|\b(deploy|release|rollback|provision|terminate|shutdown|reboot|restart)\b"
    r"|\b(run|execute|exec|eval|invoke|spawn) (a |the )?"
    r"(command|shell|script|code|program|binary|job|task|process)\b"
    r"|\b(shell|subprocess|os command|arbitrary code)\b"
)


def _is_side_effecting(name: str, description: str) -> bool:
    """True if a tool can cause an outward or irreversible side effect.

    Two layers, both structural and local:
      1. The composition classifier's EXFIL leg: send a message, publish/upload,
         outbound HTTP, post to a channel or external system (data leaving).
      2. Destructive / state-changing / code-execution verbs the exfil model omits
         (delete, drop, wipe, transfer, deploy, run a command, ...).
    Pure reads and local, non-mutating operations are not gated. This is the same
    meaning of "side-effecting" the convention's action-gating rule uses.
    """
    surface = ServerSurface(name="_gate", tools=[ToolInfo(name, description or "")])
    if any(sig.leg is TrifectaLeg.EXFIL for sig in classify_server(surface)):
        return True
    return bool(_DESTRUCTIVE_ACTION.search(_normalize(f"{name} {description or ''}")))


def _gated_response(name: str, mode: str) -> types.CallToolResult:
    """The result returned to the client when a side-effecting call is gated. The call
    is NOT forwarded upstream, so the side effect never happens.

    Returned as a full CallToolResult (isError=True) rather than a bare content list so
    the gating message and the audit `_meta` survive even for a tool that declares an
    outputSchema (the low-level server passes a CallToolResult through unchanged, but
    would replace a bare content list with an output-validation error)."""
    if mode == "block":
        msg = (
            f"[blindspot] BLOCKED: '{name}' is a side-effecting tool and untrusted "
            "content is present in this session's context. Per the enforcement contract "
            "(convention section 8), a side-effecting action derived from untrusted "
            "content requires human approval. The call was NOT forwarded upstream."
        )
    else:  # "approve"
        msg = (
            f"[blindspot] APPROVAL REQUIRED: '{name}' is a side-effecting tool and "
            "untrusted content is present in this session's context. The call is held "
            "pending explicit human approval and was NOT forwarded upstream. Re-issue it "
            "out-of-band once a human has authorized it."
        )
    meta = {
        ENFORCEMENT_NS: {
            "action_gated": mode,
            "tool": name,
            "reason": "untrusted-content-in-context",
            "side_effecting": True,
        }
    }
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=msg, _meta=meta)],
        isError=True,
        _meta=meta,
    )


def _enforce_text(
    text: str, meta: dict | None, policy: ProxyPolicy, inferer: ProvenanceInferer | None
) -> _Applied:
    """Enforce one text item. Precedence: real `_meta` > assume_origin > inference >
    fail-closed-untrusted."""
    inference: InferredProvenance | None = None
    body, use_meta = text, meta
    if meta is None:
        if policy.assume_origin is not None:
            body, use_meta = tag_meta(text, policy.assume_origin)
        elif inferer is not None and policy.infer:
            inference = inferer.infer(text)
            origin = inference.origin
            # Trust ceiling: inference alone may not promote to a trusted origin.
            if origin is Origin.AUTHOR and not policy.trust_inferred:
                origin = Origin.EXTERNAL
            body, use_meta = tag_meta(text, origin)
    e = enforce(
        body,
        use_meta,
        verify_key=policy.verify_key,
        require_signature=policy.require_signature,
        key_resolver=policy.key_resolver,
        key_alg=policy.key_alg,
    )
    return _Applied(e, inference)


def _enforcement_meta(applied: _Applied) -> dict:
    e = applied.enforcement
    annotation: dict = {
        "disposition": e.disposition.value,
        "instruction_allowed": e.instruction_allowed,
        "requires_approval": e.requires_approval,
        "flags": list(e.flags),
    }
    if applied.inference is not None:
        inf = applied.inference
        annotation["inferred_provenance"] = {
            "origin": inf.origin.value,
            "trust": inf.trust.value,
            "rationale": inf.rationale,
            "model_inferred": inf.inferred,
        }
    return {ENFORCEMENT_NS: annotation}


def _log(surface: str, ident: str, applied: _Applied) -> None:
    e = applied.enforcement
    if e.disposition is not Trust.TRUSTED or e.flags:
        detail = ""
        if applied.inference is not None:
            detail = f" inferred={applied.inference.origin.value}: {applied.inference.rationale}"
        logger.info(
            "enforced %s %s -> %s (instruction_allowed=%s) %s%s",
            surface, ident, e.disposition.value, e.instruction_allowed, e.flags, detail,
        )


def _enforce_block(
    block: types.ContentBlock, policy: ProxyPolicy, inferer: ProvenanceInferer | None
) -> tuple[types.ContentBlock, _Applied | None]:
    """Enforce any text a content block carries, returning the transformed block.

    Handles both a plain text block and text embedded in a resource block (an
    injection can ride inside an EmbeddedResource, which has no top-level `.text`).
    Non-text blocks (image, audio, binary resources) carry no text-injection surface
    and pass through unchanged.
    """
    if getattr(block, "type", None) == "text" and getattr(block, "text", None) is not None:
        applied = _enforce_text(block.text, getattr(block, "meta", None), policy, inferer)
        text = applied.enforcement.presentation
        return types.TextContent(type="text", text=text, _meta=_enforcement_meta(applied)), applied

    res = getattr(block, "resource", None)
    if res is not None and getattr(res, "text", None) is not None:
        applied = _enforce_text(res.text, getattr(res, "meta", None), policy, inferer)
        new_res = types.TextResourceContents(
            uri=res.uri,
            mimeType=getattr(res, "mimeType", None),
            text=applied.enforcement.presentation,
            _meta=_enforcement_meta(applied),
        )
        return types.EmbeddedResource(type="resource", resource=new_res), applied

    # Non-text block (image, audio, blob resource, resource link): the proxy cannot
    # enforce text it does not have, so it forwards the block unchanged. It is still
    # untrusted, attacker-influenceable content (a multimodal injection channel), so it
    # taints the session. Returning a passthrough decision instead of None is what makes
    # _maybe_taint fire, closing the "deliver the injection as a blob/image to dodge the
    # action gate" bypass.
    return block, _passthrough_applied()


def _source_text(block) -> str | None:
    """The text a content block carries (top-level, or inside a text resource), for
    hashing into the audit trail. None for non-text/binary blocks."""
    t = getattr(block, "text", None)
    if t is not None:
        return t
    res = getattr(block, "resource", None)
    return getattr(res, "text", None) if res is not None else None


def make_proxy(
    session: ClientSession,
    init_result,
    policy: ProxyPolicy,
    name: str = "blindspot-proxy",
    ledger: Ledger | None = None,
) -> Server:
    """Build the client-facing proxy server over a live upstream session.

    Only the primitives the upstream declares are registered, so the proxy mirrors the
    upstream's capability surface rather than over-advertising.
    """
    server: Server = Server(name)
    caps = init_result.capabilities
    inferer = ProvenanceInferer() if policy.infer else None
    # Per-session taint and a tool name -> description cache. call_tool only receives
    # (name, arguments), so the description needed to classify a tool as side-effecting
    # is captured from list_tools (and populated lazily in call_tool if not yet seen).
    state = _SessionState()
    tool_descs: dict[str, str] = {}
    # Serializes taint updates and the action-gate decision under approve/block so a
    # concurrently dispatched side-effecting call cannot race past the gate (see _gate_cm).
    gate = asyncio.Lock()

    if caps.resources is not None:

        @server.list_resources()
        async def list_resources() -> list[types.Resource]:
            return (await session.list_resources()).resources

        @server.list_resource_templates()
        async def list_resource_templates() -> list[types.ResourceTemplate]:
            try:
                return (await session.list_resource_templates()).resourceTemplates
            except Exception:  # noqa: BLE001 - upstream may not support templates
                return []

        @server.read_resource()
        async def read_resource(uri: AnyUrl):
            result = await session.read_resource(uri)
            out: list[ReadResourceContents] = []
            for c in result.contents:
                mime = getattr(c, "mimeType", None) or "text/plain"
                text = getattr(c, "text", None)
                if text is None:
                    # Binary resource: no text to enforce, pass the bytes through.
                    blob = getattr(c, "blob", "")
                    try:
                        raw = base64.b64decode(blob) if isinstance(blob, str) else blob
                    except Exception:  # noqa: BLE001
                        raw = b""
                    out.append(ReadResourceContents(content=raw, mime_type=mime, meta=None))
                    # Binary body is unverified, attacker-influenceable content: taint.
                    binary_applied = _passthrough_applied()
                    async with _gate_cm(policy, gate):
                        _maybe_taint(state, binary_applied)
                    if ledger is not None:
                        ledger.record_enforcement("resource", str(uri), None, binary_applied.enforcement)
                    continue
                applied = _enforce_text(text, getattr(c, "meta", None), policy, inferer)
                _log("resource", str(uri), applied)
                async with _gate_cm(policy, gate):
                    _maybe_taint(state, applied)
                if ledger is not None:
                    ledger.record_enforcement("resource", str(uri), text, applied.enforcement)
                out.append(
                    ReadResourceContents(
                        content=applied.enforcement.presentation,
                        mime_type=mime,
                        meta=_enforcement_meta(applied),
                    )
                )
            return out

    if caps.prompts is not None:

        @server.list_prompts()
        async def list_prompts() -> list[types.Prompt]:
            return (await session.list_prompts()).prompts

        @server.get_prompt()
        async def get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
            result = await session.get_prompt(name, arguments)
            messages: list[types.PromptMessage] = []
            last_meta: dict | None = None
            for m in result.messages:
                block, applied = _enforce_block(m.content, policy, inferer)
                if applied is not None:
                    _log("prompt", name, applied)
                    async with _gate_cm(policy, gate):
                        _maybe_taint(state, applied)
                    if ledger is not None:
                        ledger.record_enforcement("prompt", name, _source_text(m.content), applied.enforcement)
                    last_meta = _enforcement_meta(applied)
                messages.append(types.PromptMessage(role=m.role, content=block))
            return types.GetPromptResult(
                description=result.description, messages=messages, _meta=last_meta
            )

    if caps.tools is not None:

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            tools = (await session.list_tools()).tools
            for t in tools:
                tool_descs[t.name] = t.description or ""
            return tools

        # validate_input=False: the upstream server validates arguments; the proxy just
        # forwards them and enforces the output.
        @server.call_tool(validate_input=False)
        async def call_tool(name: str, arguments: dict) -> list[types.ContentBlock] | types.CallToolResult:
            async def _forward_and_enforce() -> types.CallToolResult:
                # Called with the gate lock held (fast path) or re-held (after approval);
                # it must NOT re-acquire the lock. Enforces every output block, taints,
                # records to the ledger, and forwards structuredContent + isError so an
                # outputSchema tool is not bricked and a failed call is not shown as success.
                result = await session.call_tool(name, arguments)
                blocks: list[types.ContentBlock] = []
                for c in result.content:
                    block, applied = _enforce_block(c, policy, inferer)
                    if applied is not None:
                        _log("tool", name, applied)
                        _maybe_taint(state, applied)
                        if ledger is not None:
                            ledger.record_enforcement("tool", name, _source_text(c), applied.enforcement)
                    blocks.append(block)
                structured = getattr(result, "structuredContent", None)
                if structured is not None:
                    _maybe_taint(state, _passthrough_applied())
                return types.CallToolResult(
                    content=blocks,
                    structuredContent=structured,
                    isError=bool(getattr(result, "isError", False)),
                )

            # Action gating (convention section 8). Decide UNDER the lock (a TOCTOU-safe
            # read of taint + side-effect classification), but never hold the lock across
            # a human approval wait, which would serialize / deadlock the session.
            async with _gate_cm(policy, gate):
                gated = False
                if policy.action_mode in ("approve", "block") and state.tainted:
                    desc = tool_descs.get(name)
                    if desc is None:
                        # Not seen via list_tools (a client may call without listing first).
                        try:
                            for t in (await session.list_tools()).tools:
                                tool_descs[t.name] = t.description or ""
                        except Exception:  # noqa: BLE001 - upstream list may fail; classify by name
                            pass
                        desc = tool_descs.get(name, "")
                    gated = _is_side_effecting(name, desc)
                if not gated:
                    # Fast path: forward under the lock (keeps decide-then-forward atomic).
                    return await _forward_and_enforce()

            # Gated; the lock is released. Record the decision, then resolve it.
            logger.info(
                "action-gated tool %s (mode=%s): untrusted content in context", name, policy.action_mode
            )
            if ledger is not None:
                ledger.record_action(name, policy.action_mode, gated=True, side_effecting=True)
            # block, or approve with no resolver configured: refuse (never forwarded).
            if policy.action_mode == "block" or policy.approval_resolver is None:
                return _gated_response(name, policy.action_mode)
            # approve with a resolver: broker a human decision OUTSIDE the lock.
            request = build_request(
                name, arguments, "untrusted-content-in-context",
                {"action_gated": "approve", "tool": name,
                 "reason": "untrusted-content-in-context", "side_effecting": True},
                sign_key=policy.audit_sign_key, keyid=policy.audit_keyid,
            )
            approved = await resolve_approval(
                policy.approval_resolver, request, timeout=policy.approval_timeout, ledger=ledger
            )
            if not approved:
                return _gated_response(name, "approve")
            # Approved. Re-acquire the lock (taint is monotonic, so re-checking is safe)
            # and forward this specific, human-authorized call.
            async with _gate_cm(policy, gate):
                return await _forward_and_enforce()

    return server


async def run_proxy(upstream: str, is_http: bool, policy: ProxyPolicy) -> None:
    """Connect to the upstream, then serve the enforcing proxy over stdio.

    The upstream session stays open for the life of the proxy. The client speaks to the
    proxy over this process's stdio, so nothing but MCP protocol may touch stdout.
    """
    async with connect(upstream, is_http) as (session, init_result):
        ledger = (
            Ledger(policy.audit_log, sign_key=policy.audit_sign_key, keyid=policy.audit_keyid)
            if policy.audit_log
            else None
        )
        if policy.lock is not None:
            # Trust lockfile: refuse to front a server whose surface drifted from the pin
            # (a rug pull). Fail closed - the proxy does not start.
            from blindspot.lockfile import check as _lock_check
            from blindspot.lockfile import restrict_resolver as _restrict
            from blindspot.scan.drift import capture_surface as _capture_surface

            surface = await _capture_surface(session)
            violations = _lock_check(surface, policy.lock)
            if violations:
                if ledger is not None:
                    for v in violations:
                        ledger.append(EV_LOCK, surface="server", ident=upstream,
                                      detail={"kind": v.kind, "detail": v.detail})
                raise LockViolationError(
                    "trust lockfile violation: "
                    + "; ".join(f"{v.kind}: {v.detail}" for v in violations)
                )
            # Apply the lock's signing requirement / keyid allowlist to the live policy.
            if policy.lock.get("require_signature"):
                policy.require_signature = True
            allowed = policy.lock.get("allowed_keyids")
            if allowed:
                policy.key_resolver = _restrict(policy.key_resolver, allowed)
        server = make_proxy(session, init_result, policy, ledger=ledger)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

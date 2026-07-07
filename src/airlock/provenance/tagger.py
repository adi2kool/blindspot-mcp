"""Provenance tagger: the tagging-server half of spec/convention.md.

Given a body and its true origin, `tag` sanitizes at emit time (stripping the
invisible-unicode payloads via the shared sanitizer), assigns a trust level from
the origin (never more permissive than the origin default, stricter when the
sanitizer finds smuggled instructions), optionally fences the body, and computes
the integrity hash over the exact emitted bytes. `to_meta` renders the provenance
object for placement in a content item's `_meta` under the convention namespace.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from airlock.models import (
    PROVENANCE_NAMESPACE,
    Integrity,
    Origin,
    Provenance,
    Trust,
    default_trust,
    trust_strictness,
)
from airlock.provenance.integrity import SIG_ALG_HMAC, make_integrity, sign
from airlock.sanitize import SanitizeResult, strip_invisible

# Fence sentinels (convention section 7). ASCII, so they do not depend on the
# unicode that is itself part of the attack surface.
_SENTINEL_OPEN = "[[MCP-UNTRUSTED"
_SENTINEL_CLOSE = "[[/MCP-UNTRUSTED"


@dataclass
class TaggedContent:
    """The emitted body plus its provenance and a record of sanitization."""

    text: str
    provenance: Provenance
    sanitize: SanitizeResult


def make_nonce() -> str:
    """A fresh 128-bit nonce, hex-encoded as 32 characters (convention section 7)."""
    return secrets.token_hex(16)


def _escape_sentinels(untrusted: str) -> str:
    """Neutralize literal sentinel sequences inside untrusted bytes.

    Insert a backslash after `[[` so no inner content can be mistaken for a real
    sentinel regardless of nonce. The closing form is escaped first so its `[[`
    prefix is not double-processed.
    """
    return untrusted.replace(_SENTINEL_CLOSE, "[[\\/MCP-UNTRUSTED").replace(
        _SENTINEL_OPEN, "[[\\MCP-UNTRUSTED"
    )


def fence_span(untrusted: str, nonce: str | None = None) -> str:
    """Wrap untrusted bytes in fence sentinels bearing a fresh nonce."""
    nonce = nonce or make_nonce()
    body = _escape_sentinels(untrusted)
    return f"[[MCP-UNTRUSTED nonce={nonce}]]{body}[[/MCP-UNTRUSTED nonce={nonce}]]"


def derive_trust(inputs: list[Trust]) -> Trust:
    """A derived item inherits the lowest (strictest) trust of its inputs."""
    if not inputs:
        return Trust.UNTRUSTED
    return max(inputs, key=trust_strictness)


def tag(
    body: str,
    origin: Origin,
    source: str | None = None,
    fence: bool = False,
    trust_override: Trust | None = None,
    inputs: list[Trust] | None = None,
    sign_key: bytes | None = None,
    sig_alg: str = SIG_ALG_HMAC,
    keyid: str | None = None,
    sensitive_hint: str | None = None,
    private_hint: bool | None = None,
    open_world_hint: bool | None = None,
) -> TaggedContent:
    """Sanitize, assign trust, optionally fence, and hash a body for emission.

    For origin `derived`, pass `inputs` (the trust levels of the source items); the
    result inherits the lowest (strictest) trust of its inputs per convention
    section 4. With no inputs, derived defaults to untrusted, conservatively.

    When `sign_key` is given, the integrity block also carries a signature binding the
    body hash to the trust label and origin (convention section 6), so a provenance-aware
    client holding the key can detect in-transit relabeling. `sig_alg` selects the
    algorithm: `hmac-sha256` (sign_key is the shared secret) or `ed25519` (sign_key is
    the raw 32-byte private key). `keyid` is an optional identifier for public-key lookup.
    """
    result = strip_invisible(body)
    clean = result.text

    # Derived trust is computed from its inputs, not a fixed origin default.
    if origin is Origin.DERIVED:
        base_trust = derive_trust(inputs) if inputs else default_trust(origin)
    else:
        base_trust = default_trust(origin)
    trust = base_trust

    # A tagging server MAY override toward stricter but MUST NOT override toward
    # more permissive than the base trust.
    if trust_override is not None:
        if trust_strictness(trust_override) < trust_strictness(base_trust):
            raise ValueError(
                "trust_override must not be more permissive than the base trust"
            )
        trust = trust_override

    # The sanitizer found smuggled instructions: demote to quarantined (strictest).
    if result.had_smuggled_instructions:
        trust = Trust.QUARANTINED

    emitted = fence_span(clean) if fence else clean
    integrity = make_integrity(emitted)
    if sign_key is not None:
        signature = sign(integrity.hash, origin.value, trust.value, source, fence, sign_key, sig_alg)
        integrity = Integrity(
            alg=integrity.alg, hash=integrity.hash, signature=signature,
            sig_alg=sig_alg, keyid=keyid,
        )

    # SEP-1913 openWorldHint: any non-trusted content is an open-world (untrusted)
    # source. Auto-derive it from trust unless the caller set it explicitly.
    if open_world_hint is None:
        open_world_hint = trust is not Trust.TRUSTED

    provenance = Provenance(
        origin=origin,
        trust=trust,
        source=source,
        fenced=fence,
        integrity=integrity,
        open_world_hint=open_world_hint,
        sensitive_hint=sensitive_hint,
        private_hint=private_hint,
    )
    return TaggedContent(text=emitted, provenance=provenance, sanitize=result)


def to_meta(provenance: Provenance) -> dict:
    """Render the provenance object for a content item's `_meta`."""
    integrity = None
    if provenance.integrity is not None:
        integrity = {
            "alg": provenance.integrity.alg,
            "hash": provenance.integrity.hash,
            "signature": provenance.integrity.signature,
        }
        if provenance.integrity.sig_alg is not None:
            integrity["sig_alg"] = provenance.integrity.sig_alg
        if provenance.integrity.keyid is not None:
            integrity["keyid"] = provenance.integrity.keyid
    obj: dict = {
        "origin": provenance.origin.value,
        "trust": provenance.trust.value,
        "source": provenance.source,
        "fenced": provenance.fenced,
        "integrity": integrity,
    }
    # SEP-1913-aligned hints (section 5.1), emitted only when set.
    if provenance.open_world_hint is not None:
        obj["openWorldHint"] = provenance.open_world_hint
    if provenance.sensitive_hint is not None:
        obj["sensitiveHint"] = provenance.sensitive_hint
    if provenance.private_hint is not None:
        obj["privateHint"] = provenance.private_hint
    if provenance.source is not None:
        obj["attribution"] = [provenance.source]  # SEP-1913 attribution (single hop)
    return {PROVENANCE_NAMESPACE: obj}


def tag_meta(
    body: str,
    origin: Origin,
    source: str | None = None,
    fence: bool = False,
    trust_override: Trust | None = None,
    inputs: list[Trust] | None = None,
    sign_key: bytes | None = None,
    sig_alg: str = SIG_ALG_HMAC,
    keyid: str | None = None,
    sensitive_hint: str | None = None,
    private_hint: bool | None = None,
    open_world_hint: bool | None = None,
) -> tuple[str, dict]:
    """Convenience: return (emitted_body, _meta dict) ready to attach to an item."""
    tagged = tag(
        body,
        origin,
        source=source,
        fence=fence,
        trust_override=trust_override,
        inputs=inputs,
        sign_key=sign_key,
        sig_alg=sig_alg,
        keyid=keyid,
        sensitive_hint=sensitive_hint,
        private_hint=private_hint,
        open_world_hint=open_world_hint,
    )
    return tagged.text, to_meta(tagged.provenance)

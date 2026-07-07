"""Integrity: compute and verify the content hash and signature (convention section 6).

Default hash algorithm is sha-256 over the exact emitted bytes of the content body,
including any fence sentinels. The hash is base64-encoded.

The hash alone is unkeyed and covers only the body, not the provenance object, so it
detects body tampering but does NOT stop an active in-transit attacker from relabeling
untrusted content as trusted (they recompute a matching hash over the unchanged body).
The SIGNATURE closes that gap: it is a keyed MAC over the body hash bound together with
the trust label and origin, so a party without the key cannot forge a trusted label.

Two signature algorithms are supported, selected by the `sig_alg` field:
- `hmac-sha256`: a keyed MAC that authenticates the label to any party holding the
  server's shared secret. Symmetric; key shared out of band.
- `ed25519`: an asymmetric signature bound to a server identity. The server signs with
  its private key; any client verifies with the public key, which can be published (a
  `.well-known` endpoint or a JWKS-style key set) rather than shared secretly. This is
  the interoperable path aligned with the emerging MCP signing ecosystem.

Either way the signature binds the body hash to the trust label and origin, so a party
without the (private/shared) key cannot forge a trusted label: in-transit relabeling is
detected and blocked. The only residual is a genuinely malicious server signing its own
content, which is a trust-root problem no signature can solve.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from airlock.models import Integrity, Origin, Provenance, Trust

ALG = "sha-256"
SIG_ALG_HMAC = "hmac-sha256"
SIG_ALG_ED25519 = "ed25519"
SIG_ALG = SIG_ALG_HMAC  # default when a caller does not specify (back-compatible)
_SIG_ALGS = (SIG_ALG_HMAC, SIG_ALG_ED25519)


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Return (private_key, public_key) as raw 32-byte values."""
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()


def hash_body(body: str) -> str:
    """Base64 sha-256 over the exact UTF-8 bytes of the emitted content body.

    Total: a lone surrogate (category Cs, deliverable straight off the JSON wire) is
    not valid UTF-8, so it is hashed deterministically via `surrogatepass` rather than
    raising. This keeps every caller (emit, verify, drift) fail-closed, never crashing
    on hostile content.
    """
    try:
        raw = body.encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        raw = body.encode("utf-8", "surrogatepass")
    digest = hashlib.sha256(raw).digest()
    return base64.b64encode(digest).decode("ascii")


def make_integrity(body: str) -> Integrity:
    """Build an integrity block for the emitted body. Signature stays null."""
    return Integrity(alg=ALG, hash=hash_body(body), signature=None)


def _signing_payload(
    hash_value: str, origin: str, trust: str, source: str | None, fenced: bool, sig_alg: str
) -> bytes:
    """Canonical bytes the signature covers: the body hash bound to the label.

    Deterministic (sorted keys, no whitespace) so signer and verifier agree. Binding
    `trust` and `origin` here is what a relabel cannot forge without the key; binding
    `hash_value` transitively binds the body (the enforcer also verifies the hash);
    binding `sig_alg` prevents a downgrade to a weaker algorithm.
    """
    return json.dumps(
        {
            "alg": ALG,
            "sig_alg": sig_alg,
            "hash": hash_value,
            "origin": origin,
            "trust": trust,
            "source": source,
            "fenced": bool(fenced),
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sign(
    hash_value: str,
    origin: str,
    trust: str,
    source: str | None,
    fenced: bool,
    key: bytes,
    sig_alg: str = SIG_ALG_HMAC,
) -> str:
    """Sign the canonical (hash + label) payload. `key` is an HMAC secret for
    `hmac-sha256` or a raw 32-byte Ed25519 private key for `ed25519`."""
    payload = _signing_payload(hash_value, origin, trust, source, fenced, sig_alg)
    if sig_alg == SIG_ALG_ED25519:
        signature = Ed25519PrivateKey.from_private_bytes(key).sign(payload)
        return base64.b64encode(signature).decode("ascii")
    if sig_alg == SIG_ALG_HMAC:
        return base64.b64encode(hmac.new(key, payload, hashlib.sha256).digest()).decode("ascii")
    raise ValueError(f"unsupported sig_alg: {sig_alg}")


def verify_signature(
    body: str,
    provenance: Provenance | None,
    key: bytes | None,
    key_resolver: Callable[[str | None], bytes | None] | None = None,
    *,
    key_alg: str = SIG_ALG_HMAC,
) -> bool:
    """True iff the provenance carries a valid signature over this body under `key`.

    SECURITY: the verification algorithm is bound to the KEY, never to the item's own
    `sig_alg` field. This closes a signature algorithm-confusion attack: an Ed25519
    PUBLIC key is published, so if it could be accepted as an HMAC secret an attacker
    could forge a `trusted` label with only public information (the RS256->HS256 class).
    - A key resolved from `key_resolver` (a JWKS / keystore / `.well-known` set) is an
      Ed25519 public key by construction, so it is verified with `ed25519` only.
    - A directly-configured `key` is verified with the caller-declared `key_alg`
      (default `hmac-sha256`, the original shared-secret use of a configured key).
    An item whose `sig_alg` does not match the configured key's algorithm is rejected;
    cross-algorithm use of a key is treated as forgery.

    Fails closed on any missing/malformed input, an unknown algorithm, an unresolvable
    keyid, a resolver that raises, or an invalid signature, so the enforcer never raises
    on hostile `_meta`.
    """
    if provenance is None or provenance.integrity is None:
        return False
    # Determine the verification algorithm from the KEY SOURCE, not the item.
    expected_alg = key_alg
    if key_resolver is not None and provenance.integrity.keyid:
        try:
            resolved = key_resolver(provenance.integrity.keyid)
        except Exception:  # noqa: BLE001 - a hostile/custom resolver must not escape
            return False
        if resolved is not None:
            key = resolved
            expected_alg = SIG_ALG_ED25519  # keystore/JWKS keys are Ed25519 by construction
    if not key:
        return False
    if expected_alg not in _SIG_ALGS:
        return False
    sig = provenance.integrity.signature
    if not isinstance(sig, str) or not sig or not sig.isascii():
        return False
    if not isinstance(provenance.origin, Origin) or not isinstance(provenance.trust, Trust):
        return False
    item_alg = provenance.integrity.sig_alg or SIG_ALG_HMAC
    if item_alg != expected_alg:
        # The item must use the algorithm the configured key is for. Accepting a
        # different algorithm (e.g. an Ed25519 public key used as an HMAC secret) is the
        # confusion attack; reject it.
        return False
    sig_alg = expected_alg
    try:
        h = hash_body(body)
    except (UnicodeEncodeError, ValueError):
        return False
    payload = _signing_payload(
        h, provenance.origin.value, provenance.trust.value, provenance.source,
        provenance.fenced, sig_alg,
    )
    try:
        if sig_alg == SIG_ALG_ED25519:
            # validate=True rejects non-canonical base64 (embedded whitespace/newlines),
            # so a mangled-but-decodable signature string is not accepted (malleability).
            Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(sig, validate=True), payload)
            return True
        expected = base64.b64encode(hmac.new(key, payload, hashlib.sha256).digest()).decode("ascii")
        return hmac.compare_digest(expected, sig)
    except (InvalidSignature, ValueError, TypeError):
        # invalid signature, malformed key, or bad base64 -> fail closed
        return False


def verify(body: str, integrity: Integrity | None) -> bool:
    """Recompute the hash over `body` and compare (constant-time).

    Returns False for a missing integrity block or an unsupported algorithm, so
    callers fail closed. The signature is not checked here (out of scope).

    Fails closed (returns False) on any malformed input from a hostile server
    rather than raising, so `enforce()` never propagates an exception on hostile
    `_meta`. Guarded cases: a non-string hash/alg; a non-ASCII hash string (which
    would make `hmac.compare_digest` raise `TypeError`); and a body that cannot be
    UTF-8 encoded, e.g. one carrying a lone surrogate (which would make
    `hash_body` raise `UnicodeEncodeError`).
    """
    if integrity is None or not integrity.hash:
        return False
    if not isinstance(integrity.hash, str) or not isinstance(integrity.alg, str):
        return False
    if integrity.alg != ALG:
        return False
    # `hmac.compare_digest` raises TypeError when a str operand is non-ASCII.
    if not integrity.hash.isascii():
        return False
    try:
        computed = hash_body(body)
    except (UnicodeEncodeError, ValueError):
        # Body is not encodable (e.g. a lone surrogate). Cannot verify -> fail closed.
        return False
    return hmac.compare_digest(computed, integrity.hash)

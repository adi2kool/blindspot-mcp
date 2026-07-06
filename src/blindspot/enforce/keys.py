"""Public-key discovery for signature verification (convention section 6).

Ed25519 signing lets a server publish its public key instead of sharing a secret. This
module resolves an item's `keyid` to the verifying public key from a JWKS-style key
set (RFC 8037 OKP keys), so the enforcer is configured with a trust store rather than a
single key. Offline-first: a local JWKS file is the primary mechanism and needs no
network; a `.well-known` HTTP endpoint is an optional, fail-open convenience.

JWKS shape (Ed25519):
  {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "server-1", "x": "<base64url>"}]}
"""

from __future__ import annotations

import base64
import json
from pathlib import Path


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def public_key_to_jwk(public_key: bytes, kid: str) -> dict:
    """Render a raw 32-byte Ed25519 public key as an RFC 8037 OKP JWK."""
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": _b64url_encode(public_key)}


def jwks_document(entries: list[tuple[str, bytes]]) -> dict:
    """Build a JWKS document from (kid, public_key) pairs."""
    return {"keys": [public_key_to_jwk(pk, kid) for kid, pk in entries]}


class KeyStore:
    """A keyid -> Ed25519 public-key map. `resolve` returns None for an unknown key,
    so a caller with no matching key fails closed."""

    def __init__(self, keys: dict[str, bytes] | None = None) -> None:
        self._keys: dict[str, bytes] = dict(keys or {})

    @classmethod
    def from_jwks(cls, doc: dict) -> KeyStore:
        keys: dict[str, bytes] = {}
        if isinstance(doc, dict):
            for jwk in doc.get("keys") or []:
                if not isinstance(jwk, dict):
                    continue
                if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                    continue
                kid, x = jwk.get("kid"), jwk.get("x")
                if not isinstance(kid, str) or not isinstance(x, str):
                    continue
                try:
                    raw = _b64url_decode(x)
                except Exception:  # noqa: BLE001 - skip a malformed key, never raise
                    continue
                if len(raw) != 32:
                    continue
                if kid in keys and keys[kid] != raw:
                    # A colliding kid with different key bytes is ambiguous or hostile:
                    # which key does an item naming this kid mean? Refuse rather than
                    # silently pick last-write-wins. from_wellknown catches this and
                    # fails closed to an empty store.
                    raise ValueError(f"duplicate kid {kid!r} with conflicting key in JWKS")
                keys[kid] = raw
        return cls(keys)

    @classmethod
    def from_file(cls, path: str) -> KeyStore:
        return cls.from_jwks(json.loads(Path(path).read_text()))

    # A JWKS is tiny; cap the fetched body so a hostile or misbehaving endpoint cannot
    # make the client buffer an unbounded response.
    _WELLKNOWN_MAX_BYTES = 1 << 20  # 1 MiB

    @classmethod
    def from_wellknown(cls, url: str, timeout: float = 3.0) -> KeyStore:
        """Fetch a JWKS from a URL. Fail-open: returns an empty store on any error, so
        an offline or unreachable endpoint never breaks enforcement.

        Redirects are disabled (a redirect could send the fetch to an unintended host)
        and the response body is capped (`_WELLKNOWN_MAX_BYTES`) so a hostile endpoint
        cannot force an unbounded read. A key set that only becomes trusted after this
        fetch fails closed to empty on any of these guards."""
        try:
            import json as _json

            import httpx

            with httpx.stream("GET", url, timeout=timeout, follow_redirects=False) as resp:
                resp.raise_for_status()
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > cls._WELLKNOWN_MAX_BYTES:
                        return cls()  # oversized -> fail closed
                    chunks.append(chunk)
            return cls.from_jwks(_json.loads(b"".join(chunks)))
        except Exception:  # noqa: BLE001 - unreachable / malformed / oversized -> empty store
            return cls()

    def add(self, kid: str, public_key: bytes) -> None:
        self._keys[kid] = public_key

    def resolve(self, keyid: str | None) -> bytes | None:
        if not keyid:
            return None
        return self._keys.get(keyid)

    def __len__(self) -> int:
        return len(self._keys)

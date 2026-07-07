"""Trust lockfile: pin an MCP server's surface and its signing requirement.

Like `package-lock.json` plus a signing requirement, for MCP. `airlock lock` captures a
server's current surface (its tool / prompt / resource definitions) and its hash into a
`airlock.lock`. The proxy, run with `--lock`, refuses to front a server whose surface
has drifted from the pin - a rug pull, where a benign server mutates a tool after adoption -
and can require that the server's content be signed by an allowed key.

Reuses the drift-detection surface hashing, so "matches the pin" means exactly "matches
the baseline the drift detector would compute". The lock is the operator's own trusted
artifact (like a checked-in lockfile); enforcement is against the *server*, not the lock.

Free, local primitive: a JSON file. The future paid layer is a hosted registry of vetted
server attestations and org-wide lock distribution - it produces the same lock shape, so
`load_lock` / `check` are the stable seam.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from airlock.scan.drift import diff_surfaces, surface_hash

LOCK_VERSION = "x-mcp-provenance/lock-v0"


@dataclass(frozen=True)
class LockViolation:
    kind: str  # "surface_drift" | "malformed_lock"
    detail: str = ""


def generate_lock(
    surface: dict,
    *,
    require_signature: bool = False,
    allowed_keyids: list[str] | None = None,
) -> dict:
    """Build a lock pinning this surface (and optionally a signing requirement)."""
    return {
        "version": LOCK_VERSION,
        "surface_hash": surface_hash(surface),
        # The surface is stored so a drift can name exactly what changed.
        "surface": surface,
        "require_signature": bool(require_signature),
        "allowed_keyids": sorted(allowed_keyids or []),
    }


def load_lock(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "surface_hash" not in data:
        raise ValueError("not a valid airlock.lock (missing surface_hash)")
    return data


def check(surface: dict, lock: dict) -> list[LockViolation]:
    """Compare a freshly-captured surface to the lock. An empty list means it matches."""
    if not isinstance(lock, dict) or "surface_hash" not in lock:
        return [LockViolation("malformed_lock", "lock has no surface_hash")]
    if surface_hash(surface) == lock.get("surface_hash"):
        return []
    # Drifted: name what changed, reusing the drift differ over the stored surface.
    changes = diff_surfaces(lock.get("surface", {}), surface)
    detail = "; ".join(f"{c.kind} {c.category} {c.name}".strip() for c in changes)
    return [LockViolation("surface_drift", detail or "surface hash mismatch")]


def restrict_resolver(resolver, allowed_keyids: list[str] | None):
    """Wrap a key_resolver so only keyids in the lock's allowlist resolve; any other keyid
    resolves to None, which fails closed. An empty/absent allowlist is no restriction."""
    if not allowed_keyids or resolver is None:
        return resolver
    allowed = set(allowed_keyids)

    def _restricted(keyid: str | None):
        return resolver(keyid) if keyid in allowed else None

    return _restricted

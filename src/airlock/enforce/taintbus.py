"""Cross-server shared taint: the lethal trifecta is emergent across servers, so enforce it
across servers at runtime.

An agent connects to many MCP servers at once, each fronted by its own `airlock proxy`
PROCESS. Each process has a per-session taint flag, but the danger is emergent: an injection
carried by server A's untrusted content can drive an exfil sink on a SEPARATE server C. The
single-server proxy cannot see that - A's taint lives in A's process, C's gate reads only C's
process. `compose.py` flags this trifecta STATICALLY; this closes it at RUNTIME.

The mechanism is a small, local, append-only taint bus shared by every proxy that was given
the same `--taint-context` directory (`airlock init` gives all servers in one client config
the same one). When any proxy enforces untrusted content it drops a marker file into the
directory; before any proxy forwards a side-effecting call, its action gate also consults the
bus, so untrusted content read via server A gates a side-effecting call to server C.

Design:
  * $0 and local. A directory of tiny marker files. No network, no daemon, no lock service.
  * Multi-writer safe with no coordination: each marker is a uniquely-named file (mkstemp), so
    concurrent proxies never clobber each other. Taint is monotonic, so races are benign.
  * Fail-safe: every filesystem op is best-effort. A bus error degrades to each proxy's own
    local taint (never crashes; the primary single-server protection is unaffected).
  * TTL-scoped, so taint from a past session (or before a restart) self-expires rather than
    gating forever, and the directory does not grow without bound.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


class SharedTaint:
    """A directory-backed, TTL-scoped, monotonic taint flag shared across proxy processes."""

    def __init__(self, directory: str | Path, label: str = "", ttl: float = 3600.0) -> None:
        # label: which upstream server THIS proxy fronts, recorded on the marker so the audit
        # trail (and a cross-server gate decision) can attribute which server raised the taint.
        self.dir = Path(directory)
        self.label = label or ""
        self.ttl = float(ttl)
        # This process writes at most one marker (taint is monotonic), so the enforce path
        # touches the filesystem once, not per untrusted item.
        self._written = False

    def taint(self, reason: str = "") -> None:
        """Record that this proxy saw untrusted content. Idempotent per process; best-effort."""
        if self._written:
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self._prune()
            fd, _path = tempfile.mkstemp(prefix="t-", suffix=".taint", dir=str(self.dir))
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "label": self.label,
                        "reason": str(reason)[:200],
                        "pid": os.getpid(),
                        "ts": datetime.now(timezone.utc).isoformat(),
                    },
                    fh,
                )
            self._written = True
        except (OSError, ValueError):
            pass  # best-effort: the proxy's own local taint still applies

    def is_tainted(self) -> bool:
        """True if any peer proxy in this context has seen untrusted content within the TTL."""
        return bool(self._fresh())

    def sources(self) -> list[dict]:
        """The (fresh) marker records, for attributing WHICH server(s) raised the taint."""
        out: list[dict] = []
        for p in self._fresh():
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return out

    def _fresh(self) -> list[Path]:
        try:
            now = time.time()
            fresh: list[Path] = []
            for p in self.dir.glob("*.taint"):
                try:
                    if now - p.stat().st_mtime <= self.ttl:
                        fresh.append(p)
                except OSError:
                    continue
            return fresh
        except OSError:
            return []

    def _prune(self) -> None:
        """Remove markers older than the TTL so the directory stays small and stale taint
        (a past session, or before a restart) does not gate a fresh session."""
        try:
            now = time.time()
            for p in self.dir.glob("*.taint"):
                try:
                    if now - p.stat().st_mtime > self.ttl:
                        p.unlink()
                except OSError:
                    continue
        except OSError:
            pass

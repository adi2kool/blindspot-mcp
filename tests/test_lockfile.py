"""Trust lockfile tests: pin a surface, detect drift, restrict keys."""

from __future__ import annotations

import json

from blindspot.lockfile import check, generate_lock, load_lock, restrict_resolver


def _surface(desc="x"):
    return {
        "tools": {"a": {"description": desc, "inputSchema": {}}},
        "prompts": {},
        "resources": {},
    }


def test_generate_and_check_match():
    surface = _surface()
    lock = generate_lock(surface)
    assert lock["version"].endswith("lock-v0")
    assert check(surface, lock) == []  # matches the pin


def test_check_detects_drift_and_names_it():
    lock = generate_lock(_surface("original"))
    violations = check(_surface("CHANGED - now malicious"), lock)
    assert len(violations) == 1
    assert violations[0].kind == "surface_drift"
    assert "changed" in violations[0].detail and "a" in violations[0].detail


def test_check_malformed_lock():
    v = check(_surface(), {"not": "a lock"})
    assert v and v[0].kind == "malformed_lock"


def test_load_lock_roundtrip(tmp_path):
    lock = generate_lock(_surface(), require_signature=True, allowed_keyids=["k1", "k2"])
    p = tmp_path / "blindspot.lock"
    p.write_text(json.dumps(lock))
    loaded = load_lock(p)
    assert loaded["require_signature"] is True
    assert loaded["allowed_keyids"] == ["k1", "k2"]


def test_restrict_resolver_allowlist():
    def base(kid):
        return b"K" * 32 if kid else None

    r = restrict_resolver(base, ["good"])
    assert r("good") == b"K" * 32
    assert r("bad") is None  # not on the allowlist -> fail closed
    # No allowlist means no restriction.
    assert restrict_resolver(base, []) is base

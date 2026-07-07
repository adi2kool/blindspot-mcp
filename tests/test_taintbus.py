"""Tests for the cross-server shared taint bus (taintbus.SharedTaint)."""

from __future__ import annotations

import time

from airlock.enforce.taintbus import SharedTaint


def test_taint_is_visible_to_a_peer(tmp_path):
    d = tmp_path / "ctx"
    a = SharedTaint(d, label="serverA")
    assert a.is_tainted() is False
    a.taint("saw untrusted content")
    assert a.is_tainted() is True
    # A DIFFERENT proxy instance sharing the same directory sees A's taint...
    c = SharedTaint(d, label="serverC")
    assert c.is_tainted() is True
    # ...and can attribute which server raised it.
    assert "serverA" in {s.get("label") for s in c.sources()}


def test_taint_writes_at_most_one_marker_per_instance(tmp_path):
    d = tmp_path / "ctx"
    a = SharedTaint(d, label="x")
    a.taint("1")
    a.taint("2")
    a.taint("3")
    assert len(list(d.glob("*.taint"))) == 1  # monotonic: one marker per process, no spam


def test_ttl_expiry(tmp_path):
    d = tmp_path / "ctx"
    a = SharedTaint(d, label="x", ttl=0.001)
    a.taint()
    time.sleep(0.05)
    assert a.is_tainted() is False  # a stale marker (past a restart / old session) does not gate
    assert a.sources() == []


def test_missing_directory_is_not_tainted(tmp_path):
    a = SharedTaint(tmp_path / "does-not-exist", label="x")
    assert a.is_tainted() is False
    assert a.sources() == []


def test_session_tainted_promotes_shared_to_local(tmp_path):
    from airlock.enforce.proxy import _SessionState, _session_tainted

    d = tmp_path / "ctx"
    st = _SessionState()
    assert _session_tainted(st) is False  # no shared bus, local clean
    st.shared = SharedTaint(d, label="me")
    assert _session_tainted(st) is False  # bus empty
    SharedTaint(d, label="peer").taint("untrusted")  # a peer server taints the context
    assert _session_tainted(st) is True  # gate now sees it
    assert st.tainted is True  # promoted to local (monotonic), so no more bus reads


def test_default_no_context_is_local_only():
    from airlock.enforce.proxy import _SessionState, _session_tainted

    st = _SessionState()
    assert st.shared is None  # default: single-server, no cross-server bus, no filesystem IO
    assert _session_tainted(st) is False

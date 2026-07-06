"""Flight-recorder tests: the hash-chained, optionally-signed audit trail.

Proves the tamper-evidence property (editing/deleting/reordering any entry is detected)
and that Ed25519 signatures bind the log to the operator's key.
"""

from __future__ import annotations

import json

from blindspot.ledger import EV_ACTION, EV_ENFORCE, Ledger, verify_chain
from blindspot.provenance.integrity import generate_ed25519_keypair


def test_append_builds_a_linked_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    led = Ledger(path)
    e0 = led.append(EV_ENFORCE, surface="resource", ident="notes://a", disposition="untrusted")
    e1 = led.append(EV_ACTION, surface="tool", ident="send_email", detail={"gated": True})
    assert e0.seq == 0 and e1.seq == 1
    assert e0.prev_hash == "0" * 64
    assert e1.prev_hash == e0.entry_hash  # links to the prior entry
    res = verify_chain(path)
    assert res.ok and res.entries == 2 and res.first_broken_seq is None


def test_verify_detects_edited_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    led = Ledger(path)
    led.append(EV_ENFORCE, surface="resource", ident="notes://a", disposition="untrusted")
    led.append(EV_ENFORCE, surface="resource", ident="notes://b", disposition="trusted")
    # Tamper: flip a disposition in the first entry without recomputing the hash.
    lines = path.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["disposition"] = "trusted"  # an attacker rewriting history
    lines[0] = json.dumps(obj)
    path.write_text("\n".join(lines) + "\n")
    res = verify_chain(path)
    assert not res.ok
    assert res.first_broken_seq == 0
    assert "tampered" in res.reason or "hash mismatch" in res.reason


def test_verify_detects_deleted_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    led = Ledger(path)
    for i in range(3):
        led.append(EV_ENFORCE, ident=f"item-{i}")
    lines = path.read_text().splitlines()
    del lines[1]  # drop the middle entry
    path.write_text("\n".join(lines) + "\n")
    res = verify_chain(path)
    assert not res.ok  # sequence gap or broken chain


def test_signed_entries_verify_with_public_key(tmp_path):
    priv, pub = generate_ed25519_keypair()
    path = tmp_path / "audit.jsonl"
    led = Ledger(path, sign_key=priv, keyid="op-1")
    led.append(EV_ENFORCE, ident="a")
    led.append(EV_ACTION, ident="send_email")
    res = verify_chain(path, public_key=pub)
    assert res.ok and res.signed == 2
    # A different key must fail verification.
    _p2, other = generate_ed25519_keypair()
    bad = verify_chain(path, public_key=other)
    assert not bad.ok and "signature" in bad.reason


def test_verify_rejects_signature_strip_downgrade(tmp_path):
    """The keyless hash chain is forgeable (an attacker recomputes entry_hash), so the
    signature is the real protection. Rewriting a signed entry and STRIPPING its signature
    must fail verification when the operator key is supplied, not be silently skipped."""
    from blindspot.ledger import LedgerEntry

    priv, pub = generate_ed25519_keypair()
    path = tmp_path / "audit.jsonl"
    led = Ledger(path, sign_key=priv, keyid="op")
    led.append(EV_ENFORCE, ident="a")
    led.append(EV_ACTION, ident="send_email", detail={"approved": False, "reason": "DENIED"})
    lines = path.read_text().splitlines()
    obj = json.loads(lines[-1])
    obj["detail"] = {"approved": True, "reason": "approved"}  # rewrite history
    obj["sig"], obj["keyid"] = None, None  # strip the signature
    recomputed = LedgerEntry(
        seq=obj["seq"], ts=obj["ts"], event=obj["event"], surface=obj["surface"],
        ident=obj["ident"], content_hash=obj["content_hash"], disposition=obj["disposition"],
        detail=obj["detail"], prev_hash=obj["prev_hash"],
    )
    obj["entry_hash"] = recomputed.compute_hash()  # relink the keyless chain
    lines[-1] = json.dumps(obj)
    path.write_text("\n".join(lines) + "\n")
    # Keyless: the recomputed chain "verifies" (the documented limit of an unkeyed chain).
    assert verify_chain(path).ok
    # With the operator key: the stripped signature is a downgrade and MUST fail.
    res = verify_chain(path, public_key=pub)
    assert not res.ok and "unsigned" in res.reason.lower()


def test_ledger_write_failure_does_not_raise(tmp_path):
    """A ledger write failure (unwritable location) must degrade, never crash the proxy."""
    a_file = tmp_path / "not_a_dir"
    a_file.write_text("x")
    led = Ledger(a_file / "sub" / "audit.jsonl")  # parent is a file -> mkdir/open fail
    entry = led.append(EV_ENFORCE, ident="a")  # must not raise
    assert entry is not None


def test_ledger_resumes_existing_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    Ledger(path).append(EV_ENFORCE, ident="first")
    # A new Ledger over the same file continues the chain, not restart it.
    led2 = Ledger(path)
    e = led2.append(EV_ENFORCE, ident="second")
    assert e.seq == 1
    assert verify_chain(path).ok

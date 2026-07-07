"""Unit tests for the egress-DLP scanner (deterministic, no MCP).

The false-positive suite is the load-bearing half: this control redacts/blocks real tool
calls, so a benign argument that trips a detector would break a legitimate call. Every
detector must fire on a true positive AND stay silent on its near-misses.
"""

from __future__ import annotations

import pytest

from airlock.enforce import dlp

# Real-looking-but-inert secrets (all fake / documented test values). The token-shaped ones
# are written as two adjacent string literals ("xoxb-" "123...") that Python concatenates at
# parse time to the exact value the detector must match - leaving no CONTIGUOUS secret-shaped
# literal in the source for a push-protection secret scanner to flag.
AWS_KEY = "AKIA" "IOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" "0123456789abcdefghijklmnopqrstuvwxyz"  # ghp_ + 36 chars
SLACK_TOKEN = "xoxb-" "123456789012-abcdefghijklmnop"
GOOGLE_KEY = "AIza" + "B" * 35
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEm, etc\n-----END RSA PRIVATE KEY-----"
VISA = "4111111111111111"  # Luhn-valid test PAN
VISA_SPACED = "4242 4242 4242 4242"  # Luhn-valid, grouped
SSN = "123-45-6789"


@pytest.mark.parametrize(
    "detector,text",
    [
        ("aws_access_key", f"key is {AWS_KEY} ok"),
        ("github_token", f"token={GITHUB_TOKEN}"),
        ("slack_token", f"slack {SLACK_TOKEN} here"),
        ("google_api_key", f"gk {GOOGLE_KEY}"),
        ("jwt", f"bearer {JWT}"),
        ("private_key", PEM),
        ("credit_card", f"card {VISA}"),
        ("credit_card", f"card {VISA_SPACED}"),
    ],
)
def test_detector_true_positive(detector, text):
    hits = dlp.scan_value(text)
    assert detector in {name for name, _s, _e in hits}, f"{detector} did not fire on {text!r}"


@pytest.mark.parametrize(
    "text",
    [
        "The quick brown fox jumps over the lazy dog.",
        "order id 1234567812345678",  # 16 digits, Luhn-INVALID -> not a card
        "4111111111111112",  # one digit off the valid PAN -> Luhn-invalid
        "550e8400-e29b-41d4-a716-446655440000",  # uuid
        "e83c5163316f89bfbde7d9ab23ca2e25604af290",  # 40-char git sha
        "2026-07-07T13:45:00Z",  # iso timestamp
        "alice@example.com",  # email is NOT a default detector (legit in exfil args)
        "+1 415 555 0132",  # phone is NOT a default detector
        "iVBORw0KGgoAAAANSUhEUgAAAAUA",  # short base64-ish blob
        "session_id=abc123 request_id=xyz789",  # ordinary ids
        "SKU 100-20-3040 shipped",  # ddd-dd-dddd product code, NOT an SSN (opt-in only)
        "part-no 250-10-5000 in stock",  # same shape, benign
        "invoice line 300-15-2024",  # same shape, benign
        "sensor readings: 1 3 1 8 6 0 9 1 3 9 0 9 9 6 0 3",  # spaced digits, not a glued card
        "counts 4 2 4 2 4 2 4 2 4 2 4 2 4 2 4 2",  # spaced digit-pairs, not a card
    ],
)
def test_detector_no_false_positive(text):
    assert dlp.scan_value(text) == [], f"false positive on {text!r}"


def test_all_zero_card_not_flagged():
    """A run of identical digits passes Luhn only degenerately and is never a real PAN."""
    assert dlp.scan_value("0000000000000000") == []


def test_scan_args_walks_nested_structure():
    args = {
        "to": "ops@example.com",
        "meta": {"tags": ["urgent", f"deploy with {AWS_KEY}"]},
        "count": 3,
        "ok": True,
    }
    findings = dlp.scan_args(args)
    assert len(findings) == 1
    f = findings[0]
    assert f.detector == "aws_access_key"
    assert f.path == ("meta", "tags", 1)


def test_scan_args_depth_bound_terminates():
    """A pathologically deep structure must not recurse without bound (availability)."""
    node: dict = {"leaf": AWS_KEY}
    for _ in range(200):
        node = {"n": node}
    # Deeper than _MAX_DEPTH, so the secret is never reached; the point is it returns.
    findings = dlp.scan_args(node)
    assert isinstance(findings, list)  # did not blow the stack / hang


def test_redact_args_deep_copies_and_replaces():
    args = {"to": "a@b.com", "body": f"the key is {AWS_KEY} keep safe"}
    findings = dlp.scan_args(args)
    redacted = dlp.redact_args(args, findings)
    # Original is never mutated (the raw secret must not survive in the forwarded object).
    assert args["body"] == f"the key is {AWS_KEY} keep safe"
    assert AWS_KEY not in redacted["body"]
    assert "[REDACTED:aws_access_key]" in redacted["body"]
    # Untouched fields carry through.
    assert redacted["to"] == "a@b.com"


def test_redact_args_multiple_secrets_in_one_string():
    body = f"aws={AWS_KEY} and card={VISA}"
    args = {"body": body}
    findings = dlp.scan_args(args)
    redacted = dlp.redact_args(args, findings)
    assert AWS_KEY not in redacted["body"]
    assert VISA not in redacted["body"]
    assert "[REDACTED:aws_access_key]" in redacted["body"]
    assert "[REDACTED:credit_card]" in redacted["body"]


def test_scan_args_bounded_flags_incomplete_on_oversize():
    # A large filler leaf exhausts the shared budget so a LATER secret leaf is unscanned:
    # the scan is incomplete, which the proxy must treat as "a secret may be present".
    _f, complete = dlp.scan_args_bounded({"filler": "x" * 1_000_001, "body": AWS_KEY})
    assert complete is False
    # A single >1MB field: the secret past the budget is unscanned -> incomplete.
    _f2, c2 = dlp.scan_args_bounded({"body": "lorem " * 180_000 + " " + AWS_KEY})
    assert c2 is False
    # A normal small args set is COMPLETE (no regression on the common path).
    _f3, c3 = dlp.scan_args_bounded({"to": "ops@example.com", "body": "ship it"})
    assert c3 is True


def test_scan_args_bounded_wide_nonstring_is_bounded():
    # Millions of non-string nodes must not stall: the node budget bounds the walk and marks
    # the scan incomplete (the character budget alone would never fire here).
    _f, complete = dlp.scan_args_bounded({"nums": list(range(300_000))})
    assert complete is False


def test_redact_args_no_findings_is_identity():
    args = {"body": "nothing secret here"}
    assert dlp.redact_args(args, []) is args


def test_scan_value_returns_sorted_spans():
    text = f"card {VISA} then key {AWS_KEY}"
    hits = dlp.scan_value(text)
    starts = [s for _n, s, _e in hits]
    assert starts == sorted(starts)


def test_opt_in_detectors_available_but_off_by_default():
    # SSN and email are opt-in (shape collides with benign business data); silent by default.
    assert dlp.scan_value(f"ssn {SSN}") == []
    assert dlp.scan_value("reach me at alice@example.com") == []
    ssn_hits = dlp.scan_value(f"ssn {SSN}", (dlp.OPTIONAL_DETECTORS["us_ssn"],))
    assert {"us_ssn"} == {name for name, _s, _e in ssn_hits}
    email_hits = dlp.scan_value("alice@example.com", (dlp.OPTIONAL_DETECTORS["email"],))
    assert {"email"} == {name for name, _s, _e in email_hits}


def test_card_grouping_rejects_glued_digit_list_but_keeps_real_cards():
    # A spaced single-digit list whose digits happen to be Luhn-valid must NOT be a card...
    glued = "counts 4 2 4 2 4 2 4 2 4 2 4 2 4 2 4 2"
    assert dlp.scan_value(glued) == []
    # ...but a real card grouped in 4s (or contiguous) still fires.
    assert "credit_card" in {n for n, _s, _e in dlp.scan_value(VISA_SPACED)}
    assert "credit_card" in {n for n, _s, _e in dlp.scan_value(VISA)}
    assert "credit_card" in {n for n, _s, _e in dlp.scan_value("4111-1111-1111-1111")}


# --- Egress must see non-string leaves and dict keys (block-mode bypass regression) -------

def test_credit_card_as_integer_leaf_is_detected():
    """A card sent as a JSON integer (not a string) must still be found, so block/redact
    cannot be bypassed by numeric formatting. Regression for the enforce-core audit."""
    findings, complete = dlp.scan_args_bounded({"to": "x@e.com", "amount": 4111111111111111})
    assert complete is True
    assert {"credit_card"} == {f.detector for f in findings}


def test_redact_replaces_numeric_secret_leaf_wholesale():
    """Redact mode must not silently forward a numeric secret it detected."""
    args = {"amount": 4111111111111111}
    findings, _ = dlp.scan_args_bounded(args)
    red = dlp.redact_args(args, findings)
    assert red == {"amount": "[REDACTED:credit_card]"}
    assert "4111111111111111" not in str(red)
    assert args == {"amount": 4111111111111111}  # original never mutated


def test_boolean_leaf_is_not_scanned_as_a_number():
    # bool is an int subclass; True/False must not be coerced to a "number" to scan.
    findings, complete = dlp.scan_args_bounded({"flag": True, "ok": False})
    assert findings == [] and complete is True


def test_secret_in_dict_key_forces_incomplete_fail_closed():
    """A secret hidden as a dict KEY is not span-redactable, so the scan is marked incomplete
    and the proxy fails closed (block) rather than forwarding the key. Regression."""
    findings, complete = dlp.scan_args_bounded({AWS_KEY: "value"})
    assert complete is False  # -> block/redact fail closed


def test_benign_keys_do_not_trip_incomplete():
    # Ordinary argument keys must never force a fail-closed.
    findings, complete = dlp.scan_args_bounded(
        {"to": "a@b.com", "subject": "hi", "body": "text", "amount": 12}
    )
    assert findings == [] and complete is True


def test_optional_email_detector_is_linear_not_redos():
    """The operator-enableable email detector must be linear on a hostile no-`@` run
    (the naive pattern was O(n^2)). Regression for the performance audit."""
    import time

    dets = dlp.DEFAULT_DETECTORS + (dlp.OPTIONAL_DETECTORS["email"],)
    evil = "a@" + "a." * 80_000  # 160 KB; the quadratic form took ~16 s here
    start = time.perf_counter()
    dlp.scan_value(evil, dets)
    assert time.perf_counter() - start < 1.0

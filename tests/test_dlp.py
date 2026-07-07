"""Unit tests for the egress-DLP scanner (deterministic, no MCP).

The false-positive suite is the load-bearing half: this control redacts/blocks real tool
calls, so a benign argument that trips a detector would break a legitimate call. Every
detector must fire on a true positive AND stay silent on its near-misses.
"""

from __future__ import annotations

import pytest

from airlock.enforce import dlp

# Real-looking-but-inert secrets (all fake / documented test values).
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

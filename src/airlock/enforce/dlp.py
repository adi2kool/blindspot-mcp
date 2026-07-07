"""Egress DLP: deterministic secret/PII detection over OUTBOUND tool-call arguments.

The action gate (convention section 8) decides *whether* a side-effecting call may
proceed given untrusted content in context. It never inspects *what* is inside the call
arguments. So a real secret or a card number placed into the arguments of an outbound
tool - a confused-deputy exfiltration the agent was induced to perform - leaves the trust
boundary unseen. This module closes that gap: it scans the string values of the arguments
a client is about to send to an EXFIL-classified upstream tool, and the proxy annotates,
redacts, or blocks the call per policy.

Design constraints (see the project's zero-cost + FP-hardening posture):
  * $0 and local. Pure Python: anchored regexes + a Luhn check. No network, no LLM, no new
    dependency. Safe to run on the hot path.
  * Near-zero false positives by construction. Only UNAMBIGUOUS detectors run by default:
    structured token prefixes (AWS/GitHub/Slack/Google), PEM key blocks, JWTs, and
    Luhn-valid credit cards with sane grouping. Detectors whose SHAPE collides with ordinary
    business data - a bare `ddd-dd-dddd` SSN (indistinguishable from a SKU / part number /
    invoice code), an email address (legitimate in a `send_email` argument), a phone number -
    are DELIBERATELY opt-in (OPTIONAL_DETECTORS), because redacting or blocking a legitimate
    value is the costliest failure mode. The default battery can only fire on data that has
    no benign interpretation.
  * Fail-open on the proxy hot path. The caller wraps `scan_args` so any scanner error
    degrades to forwarding the call unchanged - a scanner bug must never break every
    outbound call. (In redact mode a KNOWN finding that fails to redact fails closed to a
    block; that decision lives in the proxy, not here.)
  * Shape-only reporting. A `Finding` carries the detector name and the span location, never
    the secret bytes, so the audit ledger can record that a secret was seen without
    persisting it.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

# Bound the work a single call can cost, mirroring the proxy's _MAX_ENFORCE_CHARS: a
# hostile client controls the arguments, and unbounded/deeply-nested structures are a
# cheap event-loop-stall DoS. Beyond these the scan stops (fail-open: unscanned bytes are
# forwarded, same as the rest of the proxy's best-effort posture).
_MAX_DEPTH = 16
_MAX_TOTAL_CHARS = 1_000_000
# Bound the NUMBER of nodes visited, not just characters scanned: a hostile args structure
# that is wide in NON-string values (a list/dict of millions of ints/bools/None) never
# decrements the character budget, so without a node cap the walk is a synchronous
# event-loop-stall DoS. Hitting either cap marks the scan INCOMPLETE (see scan_args_bounded).
_MAX_NODES = 200_000

_REDACTION = "[REDACTED:{name}]"


def _luhn_valid(s: str) -> bool:
    """True if the digit run in `s` passes the Luhn checksum (credit-card FP-hardening).

    Strips separators first. A 13-19 digit run that is not Luhn-valid is almost always an
    order id / accession number / random digits, not a real PAN, so Luhn is what keeps the
    card detector from firing on every long number."""
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:  # 0000...0000 / 1111...1111: passes Luhn only for all-zero, but is never a real card
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _valid_card(s: str) -> bool:
    """True if `s` is a plausible credit card: Luhn-valid AND sanely grouped.

    The Luhn check alone is not enough - the card regex allows a separator after every
    digit, so a spaced list of unrelated small numbers ('1 3 1 8 6 0 9 ...') can be glued
    into a 13-19 digit run that passes Luhn ~10% of the time. Real PANs are written
    contiguous or grouped in blocks of >=4 (4-4-4-4, 4-6-5), so reject any candidate whose
    separator-delimited groups include a run shorter than 4 digits. This keeps real spaced/
    dashed cards ('4242 4242 4242 4242', '4111-1111-1111-1111') while dropping digit-list
    gluing."""
    if not _luhn_valid(s):
        return False
    groups = re.split(r"[ -]+", s.strip())
    if len(groups) > 1 and any(len(g) < 4 for g in groups):
        return False
    return True


@dataclass(frozen=True)
class _Detector:
    """One named pattern, optionally gated by a validator over the matched text."""

    name: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None

    def find(self, s: str) -> Iterable[tuple[int, int]]:
        for m in self.pattern.finditer(s):
            if self.validator is None or self.validator(m.group(0)):
                yield m.start(), m.end()


# --- High-confidence secret + PII detectors (the default battery) ---------------------
# Each is anchored and structured so it does not fire on ordinary prose. Order is
# irrelevant (findings are merged per span before redaction).

_PEM_PRIVATE_KEY = _Detector(
    "private_key",
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
)
_AWS_ACCESS_KEY = _Detector(
    "aws_access_key",
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b"),
)
_GITHUB_TOKEN = _Detector(
    "github_token",
    re.compile(r"\bgh[posru]_[A-Za-z0-9]{36,255}\b"),
)
_SLACK_TOKEN = _Detector(
    "slack_token",
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)
_GOOGLE_API_KEY = _Detector(
    "google_api_key",
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
)
_JWT = _Detector(
    # Three base64url segments; the first begins `eyJ` (base64 of `{"`), which makes this
    # far more specific than "three dot-separated tokens" and keeps it off ordinary text.
    "jwt",
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_CREDIT_CARD = _Detector(
    # 13-19 digits, optionally grouped by single spaces/dashes, gated by Luhn AND sane
    # grouping (see _valid_card) so a spaced list of small numbers is not glued into a PAN.
    "credit_card",
    re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
    validator=_valid_card,
)
DEFAULT_DETECTORS: tuple[_Detector, ...] = (
    _PEM_PRIVATE_KEY,
    _AWS_ACCESS_KEY,
    _GITHUB_TOKEN,
    _SLACK_TOKEN,
    _GOOGLE_API_KEY,
    _JWT,
    _CREDIT_CARD,
)

# --- Opt-in detectors -----------------------------------------------------------------
# NOT in the default battery: each of these has a SHAPE that collides with ordinary
# business data, so firing by default would redact/block legitimate outbound calls.
_US_SSN = _Detector(
    # Dashed US SSN. Excludes the never-valid ranges (area 000/666/900-999, group 00,
    # serial 0000) - but a `ddd-dd-dddd` string is STILL indistinguishable by shape from a
    # SKU / part number / invoice-line code (~89% of that shape are not SSNs), so this is
    # opt-in, not default. Enable it only where outbound args genuinely carry SSNs.
    "us_ssn",
    re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
)
_EMAIL = _Detector(
    "email",
    # Possessive local part + dot-delimited, length-bounded labels. The naive
    # `[...]+@[...]+\.[...]` form is O(n^2) on a hostile no-`@` run (the local part backtracks
    # every start position); this is the linear pattern the scanner already uses
    # (scan/detectors/patterns.py). Load-bearing because this detector is operator-enableable
    # (--dlp-optional email) and would otherwise be a reachable ReDoS on outbound args.
    re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}+@(?:[A-Za-z0-9\-]{1,63}\.){1,63}[A-Za-z]{2,24}\b"),
)
_E164_PHONE = _Detector(
    "phone",
    re.compile(r"(?<![\w])\+\d{1,3}[ -]?(?:\d[ -]?){7,13}\d\b"),
)
OPTIONAL_DETECTORS: dict[str, _Detector] = {d.name: d for d in (_US_SSN, _EMAIL, _E164_PHONE)}


def detectors_for(optional: Iterable[str] = ()) -> tuple[_Detector, ...]:
    """The default battery plus any requested opt-in detectors (by name). Unknown names are
    ignored. This is how `airlock proxy --dlp-optional us_ssn,email` widens the scan without
    hard-coding the set anywhere on the hot path."""
    extra = tuple(OPTIONAL_DETECTORS[n] for n in dict.fromkeys(optional) if n in OPTIONAL_DETECTORS)
    return DEFAULT_DETECTORS + extra


@dataclass(frozen=True)
class Finding:
    """A detector hit at a located span inside one string leaf of the arguments.

    `path` is the access path (dict keys and list indices) to that leaf, so a redactor can
    navigate back to it. `start`/`end` bound the matched span WITHIN that leaf string. No
    secret bytes are carried."""

    detector: str
    path: tuple[str | int, ...]
    start: int
    end: int


def scan_value(s: str, detectors: tuple[_Detector, ...] = DEFAULT_DETECTORS) -> list[tuple[str, int, int]]:
    """Run every detector over one string. Returns (detector, start, end) spans, sorted."""
    hits: list[tuple[str, int, int]] = []
    for det in detectors:
        for start, end in det.find(s):
            hits.append((det.name, start, end))
    return sorted(set(hits), key=lambda t: (t[1], t[2]))


def scan_args_bounded(
    arguments: object, detectors: tuple[_Detector, ...] = DEFAULT_DETECTORS
) -> tuple[list[Finding], bool]:
    """Recursively scan the string leaves of a tool-call arguments structure.

    Returns (findings, complete). `complete` is False when the walk stopped before examining
    all content - a string longer than the remaining character budget (its tail is unscanned),
    the character or node budget exhausted, depth exceeded, or a secret found in a dict KEY
    (which cannot be span-redacted in place, so it forces a fail-closed). This distinction is
    load-bearing: a caller enforcing block/redact must treat an INCOMPLETE scan as "a secret
    may be present" and fail CLOSED, because a hostile client can drive the budget to zero
    with a large filler value (or a single oversized field) and slip a real secret into the
    unscanned tail.

    Every LEAF is scanned, not just strings: a number leaf is scanned as its `str()` form, so
    a card sent as a JSON integer (`{"amount": 4111111111111111}`) is caught, not silently
    forwarded. Dict KEYS are scanned too, so a secret hidden as a key (`{"AKIA...": "x"}`) is
    not a blind spot. Booleans and None carry no secret and are skipped, but still count
    against the node budget so a wide non-string structure cannot stall the loop."""
    findings: list[Finding] = []
    budget = _MAX_TOTAL_CHARS
    nodes = _MAX_NODES
    incomplete = False

    def scan_leaf(s: str, path: tuple[str | int, ...]) -> None:
        """Scan one leaf string against the char budget, recording located findings."""
        nonlocal budget, incomplete
        if budget <= 0:
            incomplete = True
            return
        if len(s) > budget:
            incomplete = True  # tail past the budget is unscanned; a secret there is missed
        chunk = s[:budget]
        budget -= len(s)
        for det, start, end in scan_value(chunk, detectors):
            findings.append(Finding(det, path, start, end))

    def walk(node: object, path: tuple[str | int, ...], depth: int) -> None:
        nonlocal budget, nodes, incomplete
        if nodes <= 0:
            incomplete = True
            return
        nodes -= 1
        if depth > _MAX_DEPTH:
            incomplete = True
            return
        if isinstance(node, str):
            scan_leaf(node, path)
        elif isinstance(node, bool):
            pass  # True / False carry no secret; the node is still counted above
        elif isinstance(node, (int, float)):
            # A numeric leaf can still be a secret (a card as an integer). Scan its text form;
            # the whole value is the secret, so redact_args replaces the leaf wholesale.
            scan_leaf(str(node), path)
        elif isinstance(node, dict):
            for k, v in node.items():
                if nodes <= 0:
                    incomplete = True
                    return
                # A secret can hide in a KEY, not just a value. Keys are not span-redactable in
                # place, so a key hit forces the scan INCOMPLETE -> block/redact fail closed and
                # the payload (secret key included) is never forwarded. Scan against the budget
                # so a pathological key cannot escape the bound.
                if isinstance(k, str) and k:
                    if budget <= 0 or len(k) > budget:
                        incomplete = True
                    if budget > 0 and scan_value(k[:budget], detectors):
                        incomplete = True
                    budget -= len(k)
                # Keep the ACTUAL key in the path (not str(k)) so redact_args' _navigate can
                # look it up even for a non-string key. JSON args are string-keyed, so this is
                # normally a no-op, but it keeps redaction sound for any dict.
                walk(v, path + (k,), depth + 1)
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                if nodes <= 0:
                    incomplete = True
                    return
                walk(v, path + (i,), depth + 1)

    walk(arguments, (), 0)
    # Return COMPLETE (True = every leaf was fully scanned), the inverse of the `incomplete`
    # flag the walk accumulates. Callers fail closed when this is False.
    return findings, not incomplete


def scan_args(
    arguments: object, detectors: tuple[_Detector, ...] = DEFAULT_DETECTORS
) -> list[Finding]:
    """The findings from a bounded scan (dropping the completeness flag). Callers that must
    fail closed on an incomplete scan use scan_args_bounded directly."""
    return scan_args_bounded(arguments, detectors)[0]


def _merge_spans(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Merge overlapping/adjacent spans on one string so redaction never double-replaces.

    Overlapping detector hits (e.g. a card that also looks like something else) collapse to
    one span whose label joins the detector names."""
    ordered = sorted(spans, key=lambda t: (t[0], t[1]))
    merged: list[tuple[int, int, str]] = []
    for start, end, name in ordered:
        if merged and start <= merged[-1][1]:
            ps, pe, pn = merged[-1]
            names = pn if name in pn.split("+") else f"{pn}+{name}"
            merged[-1] = (ps, max(pe, end), names)
        else:
            merged.append((start, end, name))
    return merged


def _navigate(root: object, path: tuple[str | int, ...]) -> tuple[object, str | int] | None:
    """Return (mutable_parent_container, key) for a leaf path, or None if not reachable.

    Only dict/list containers are mutable in place; a tuple leaf cannot be redacted (JSON
    tool arguments never contain tuples, so this is not a real gap)."""
    if not path:
        return None
    parent: object = root
    for step in path[:-1]:
        try:
            parent = parent[step]  # type: ignore[index]
        except (KeyError, IndexError, TypeError):
            return None
    key = path[-1]
    if isinstance(parent, dict) and key in parent:
        return parent, key
    if isinstance(parent, list) and isinstance(key, int) and 0 <= key < len(parent):
        return parent, key
    return None


def redact_args(arguments: object, findings: list[Finding]) -> object:
    """Return a DEEP COPY of the arguments with every finding's span replaced by a redaction
    placeholder. The original object is never mutated (so the raw secret can never be
    forwarded upstream while a redacted copy is logged, or vice versa)."""
    if not findings:
        return arguments
    out = copy.deepcopy(arguments)
    by_path: dict[tuple[str | int, ...], list[tuple[int, int, str]]] = {}
    for f in findings:
        by_path.setdefault(f.path, []).append((f.start, f.end, f.detector))
    for path, spans in by_path.items():
        located = _navigate(out, path)
        if located is None:
            continue
        parent, key = located
        value = parent[key]  # type: ignore[index]
        if isinstance(value, str):
            # Replace right-to-left so earlier spans keep their offsets.
            for start, end, name in sorted(_merge_spans(spans), key=lambda t: t[0], reverse=True):
                value = value[:start] + _REDACTION.format(name=name) + value[end:]
            parent[key] = value  # type: ignore[index]
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            # A numeric leaf that matched (a card as an integer): the whole value IS the secret,
            # so replace it wholesale. The type becomes str, which is correct for a sanitized
            # outbound call - and crucially the raw number never leaves in redact mode.
            names = "+".join(sorted({name for _, _, name in spans}))
            parent[key] = _REDACTION.format(name=names)  # type: ignore[index]
        # else: a non-redactable leaf. scan_args_bounded already forced the scan INCOMPLETE for
        # the only such case it emits (a secret in a dict key), so the proxy fails closed to a
        # block; a raw secret is never forwarded under the guise of a completed redaction.
    return out

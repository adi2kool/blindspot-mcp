"""Phase 3 tests: the adaptive-attack harness.

Runs the verified attack battery against the real defense and asserts the honest
result: every in-scope attack fails (the defense holds), only the documented
residuals succeed, and the defense-in-depth hardening keeps invisible smuggling out
of the authoritative path. These are regression guards - if a future change lets an
in-scope attack reach the instruction path, `defense_holds` flips and the suite
fails.
"""

from __future__ import annotations

from blindspot.redteam.adaptive import (
    is_authoritative,
    load_attacks,
    run_all,
    summarize,
)

_COMPONENTS = {"sanitizer", "provenance", "fence", "dataframe", "integrity", "trust", "server"}


def test_oracle_distinguishes_authoritative_from_data_framed():
    assert is_authoritative("hello PWN world", "PWN") is True
    framed = "<<UNTRUSTED DATA nonce=abc123 - x>>\nPWN\n<<END UNTRUSTED DATA nonce=abc123>>"
    assert is_authoritative(framed, "PWN") is False
    # A marker present both framed and unframed is authoritative (unframed wins).
    assert is_authoritative(framed + " PWN", "PWN") is True


def test_battery_covers_every_defense_component():
    attacks = load_attacks()
    assert len(attacks) >= 30
    covered = {a.component for a in attacks}
    assert _COMPONENTS <= covered, f"missing components: {_COMPONENTS - covered}"


def test_battery_has_both_naive_and_adaptive():
    modes = {a.mode for a in load_attacks()}
    assert modes == {"naive", "adaptive"}


def test_defense_holds_no_nonresidual_attack_succeeds():
    """The core Phase 2 guarantee, proven under adaptive attack: no attack that is
    not a documented residual reaches the model instruction path."""
    results = run_all()
    summary = summarize(results)
    assert summary.defense_holds, (
        "non-residual attacks reached the instruction path: "
        + ", ".join(summary.unexpected_successes)
    )
    assert summary.unexpected_successes == []


def test_no_attack_crashes_the_harness_or_enforcer():
    """A build error or an enforcer exception is itself a defect; none should occur."""
    results = run_all()
    bad = [r for r in results if r.disposition in ("build_error", "enforcer_raised")]
    assert not bad, [(r.name, r.detail) for r in bad]


def test_every_naive_attack_fails():
    results = run_all()
    naive_wins = [r.name for r in results if r.mode == "naive" and r.succeeded]
    assert naive_wins == [], f"naive attacks should never succeed: {naive_wins}"


def test_documented_residuals_do_succeed():
    """Honest reporting: the two residual attacker models are shown succeeding, so
    the harness reports residual risk rather than a false all-clear."""
    results = run_all()
    residual_wins = {r.name for r in results if r.succeeded and r.residual}
    # At least one malicious-server and one active-mitm residual must be present.
    assert any(r.attacker_model == "server" and r.succeeded and r.residual for r in results)
    assert any(r.attacker_model == "mitm" and r.succeeded and r.residual for r in results)
    assert residual_wins, "expected the documented residuals to succeed"
    # Nothing outside the residual set succeeds.
    assert all(r.residual for r in results if r.succeeded)


def test_tag_smuggle_on_trusted_path_is_defeated():
    """Regression guard for the enforcer's defense-in-depth sanitization: a
    trusted-labeled body carrying invisible tag-character smuggling is quarantined,
    not passed into the authoritative region."""
    results = {r.name: r for r in run_all()}
    for name in ("server_tagchar_smuggle_on_trusted_path", "mitm_tagchar_smuggle_on_trusted_path"):
        r = results[name]
        assert r.succeeded is False, f"{name} should be defeated"
        assert r.disposition == "quarantined"
        assert "smuggled_in_trusted" in r.flags


def test_nonascii_hash_attack_does_not_crash_and_fails_closed():
    """The recently fixed fail-open crash path, exercised as an attack."""
    results = {r.name: r for r in run_all()}
    r = results["nonascii_hash_lone_surrogate_failclosed"]
    assert r.disposition != "enforcer_raised"
    assert r.succeeded is False


def test_signing_closes_the_relabel_residual():
    """With signing enabled, in-transit relabel and forged/unsigned trusted content
    are all defeated; only a genuinely malicious server (its own key) remains."""
    results = {r.name: r for r in run_all()}
    for defeated in (
        "mitm_relabel_defeated_by_signature",
        "forged_signature_wrong_key_defeated",
        "unsigned_trusted_downgraded_under_strict",
    ):
        assert results[defeated].succeeded is False, defeated
    residual = results["server_signed_own_injection_residual"]
    assert residual.succeeded is True and residual.residual is True


def test_oversized_body_has_no_availability_finding():
    """A 1MB adversarial body is processed without hanging (no ReDoS/DoS)."""
    import time

    from blindspot.redteam.catalog import _b_oversized_body_availability_probe
    from blindspot.redteam.adaptive import Attack, evaluate

    a = Attack(
        "oversized", "dataframe", "content", "adaptive", False,
        _b_oversized_body_availability_probe,
    )
    start = time.perf_counter()
    r = evaluate(a)
    assert time.perf_counter() - start < 3.0
    assert r.succeeded is False

# Changelog

Notable changes to Blindspot. Each release is a git tag (`vX.Y.Z`); the portfolio case
study's revision labels track these versions, so "what changed" reads the same in the repo
and on the page.

## [v0.2.0] — 2026-07-07 — Reverse-channel enforcement + a security audit

Extends the trust boundary to three surfaces the ecosystem leaves open, then hardens them
against an adversarial audit.

### Added
- **Sampling & elicitation enforcement.** The proxy enforces the two server→client channels:
  server-pushed sampling text and elicitation prompts are framed as untrusted data, a server
  system prompt is demoted out of the instruction region, the session is tainted, and the
  request is relayed (`--on-sampling`/`--on-elicitation frame`) or refused (`block`);
  URL-mode elicitation is always declined.
- **Live mid-session rug-pull detection.** With `--lock` or `--pin-on-start`, the proxy
  re-checks the surface against its pin on every listing and forwarded `list_changed`,
  attests drift to the ledger, and under `--on-drift block` withholds the mutated definition
  and refuses calls to it.
- **Provenance for MCP-exposed memory.** A `scan-memory` command scans stored entries; the
  proxy gates a poisoning memory write once tainted and tags persisted content as
  untrusted-origin. `classify_memory_tool` recognizes knowledge-graph write/read tools.

### Security
- Adversarial performance + security audit of the new code (nine dimensions, three-skeptic
  verification): **19 confirmed findings, all fixed and regression-tested**, including a
  critical action-gate split-lock (a refactor left two locks where one was required),
  reverse-channel enforcement that ignored `--assume-origin`/`--infer`, un-framed structured
  sampling content, a block-mode drift bypass, a scan-memory compound read+mutate call, and
  a surrogate-in-tool-name ledger DoS.

### Validated
- 307 tests, red-team holds (56 attacks, 2 documented residuals), detector benchmark PASS.
- Re-validated against the 7 official reference servers (182 declared items, 0 injection);
  a real knowledge-graph memory server validated the memory checks.

## [v0.1.0] — 2026-07-06 — Public release

- Scanner (`scan` / `scan-source`), enforcing proxy, provenance convention with Ed25519/HMAC
  content signing, hash-chained audit ledger, cross-server `compose` (lethal-trifecta)
  analysis, and an adaptive red-team harness.
- Prevalence study: **0 injectable declared surface across 992 npm MCP packages** (+ 28
  servers run live).
- 280 tests; 53 red-team attacks with the two documented residuals.

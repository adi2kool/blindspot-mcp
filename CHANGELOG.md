# Changelog

Notable changes to Airlock. Each release is a git tag (`vX.Y.Z`); the portfolio case
study's revision labels track these versions, so "what changed" reads the same in the repo
and on the page.

## [Unreleased]

### Added
- **Cross-server enforcement (`airlock proxy --taint-context DIR`).** The lethal trifecta is
  emergent across servers, so it is now enforced across servers at runtime. Every proxy given
  the same taint-context directory shares a monotonic, TTL-scoped, append-only taint bus:
  untrusted content read via any one server taints the whole context, so a side-effecting call
  to a DIFFERENT server is gated too (attributed as `cross_server` in the audit trail). This
  turns `compose`'s static trifecta warning into runtime prevention. `airlock init` gives all
  of a client's servers the same context automatically (one config = one agent = one context;
  `--no-shared-taint` opts out). Local, $0, no daemon; a bus error degrades to per-server local
  taint. Default (no context) is single-server, byte-identical.
- **Onboarding: `airlock init`.** Detects a client's MCP config (Claude Desktop / Cursor /
  Claude Code — a shared `mcpServers` shape) and rewrites every server to route through the
  enforcing proxy in one command: stdio servers via `airlock proxy --exec <cmd>`, remote
  servers via `--http`, the original `env` preserved, the original config backed up
  (`.airlock.bak`), idempotent (no double-wrap), with `--dry-run`. In the same pass it
  best-effort launches each server to pin its surface into a lockfile (rug-pull defense) and
  bakes an `--audit-log` path so `airlock report` has data. New `--exec` on `airlock proxy`
  fronts an arbitrary command (npx / uvx / node / a binary) as the upstream, not just a
  python script, with the full trust boundary applied.
- **Egress DLP** (`airlock proxy --on-egress annotate|redact|block`). The proxy now
  inspects OUTBOUND tool-call arguments and stops a secret or high-confidence PII from
  leaving through an exfil-capable tool. Deterministic, $0, fail-open detectors
  (AWS/GitHub/Slack/Google tokens, PEM private keys, JWTs, Luhn-valid cards): `block`
  refuses the call before it reaches upstream, `redact` strips the secret from the
  forwarded arguments, `annotate` records only. A new `egress_dlp` ledger event records the
  finding shape-only (detector names and counts, never the secret bytes). Detectors whose
  shape collides with ordinary business data (SSN, email, phone) are opt-in, so a normal
  recipient address or a `ddd-dd-dddd` product code is never flagged. Complements the action
  gate: the gate decides *whether* a call proceeds, egress DLP decides *what* may leave in it.
- **Observability.** `airlock report LEDGER [--format human|json|html] [--out PATH]` renders
  the hash-chained flight recorder into a readable summary, machine JSON, or a self-contained
  zero-dependency HTML timeline — what was demoted to data, how many side-effecting calls
  were gated, how many secrets were stopped, and whether a server rug-pulled — with the
  chain-integrity verdict shown and no secret values in the output (exits non-zero on a
  broken chain, so it can gate CI). `airlock proxy --explain` streams every enforcement
  decision to stderr live as it happens.

## [v0.2.1] — 2026-07-07 — Airlock: rename + PyPI/Docker distribution

First release under the name **Airlock** (formerly Blindspot), and the first distributed on
PyPI and GHCR. No functional change to the enforcement engine from v0.2.0.

- Renamed the project, CLI (`airlock`), and import package to **Airlock**; `pip install
  airlock-mcp`, image `ghcr.io/adi2kool/airlock-mcp`. The spec namespace `x-mcp-provenance`
  is unchanged.
- `docs/deploy.md` — copy-paste recipes (Claude Desktop, Cursor, Docker); a tag-triggered
  `release.yml` builds and publishes to PyPI (Trusted Publishing) and GHCR.

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

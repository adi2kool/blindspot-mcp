# Security Policy

Blindspot is a security tool for the MCP ecosystem. We take the security of the
tool itself seriously and hold it to the same standard it asks of others.

## Reporting a vulnerability

Report suspected vulnerabilities **privately**. Do not open a public issue for a
security problem.

- Preferred: open a private advisory via
  [GitHub Security Advisories](https://github.com/adi2kool/blindspot-mcp/security/advisories/new).
- Otherwise: email the maintainer privately at **adityacaug15@gmail.com**.

Please include a description, the affected version or commit, and a minimal
reproduction. We aim to acknowledge a report within a few days and to agree on a
disclosure timeline with the reporter (target: a fix or coordinated disclosure
within 90 days). We will credit reporters who wish to be credited.

## Scope

In scope: the code in this repository — the scanner, the provenance/tagging
library, the client enforcer, the enforcing proxy (including inference and
action-gating), the signing/integrity code, and the JWKS key discovery.

The project's own threat model and the residuals it does **not** defend against
are stated plainly in [`spec/convention.md`](spec/convention.md) section 3. A report
that an explicitly documented residual "succeeds" is expected behavior, not a
vulnerability; a report that a defended case fails is in scope.

## Responsible use of the scanner

The scanner executes a target stdio server to enumerate its surface. Only point it
at servers you are authorized to test. The prevalence study over third-party
servers (Phase C) is gated behind responsible disclosure and is not run against
anyone's server without explicit sign-off. Every attack payload in `fixtures/` is
inert and performs no real network, email, or filesystem I/O.

## Supported versions

Pre-1.0. Security fixes land on `main`. There is no long-term-support branch yet.

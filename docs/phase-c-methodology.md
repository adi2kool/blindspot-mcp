# Phase C: prevalence study methodology and scope

Status: methodology v0. This document defines what the Phase C prevalence study does,
the scope that keeps it inside the legally-safe zone, and the process gates that must be
satisfied before any finding is published. Read it alongside `docs/prevalence-findings.md`
(the results) and `SECURITY.md` (disclosure).

The goal is a defensible, citable measurement: **how widespread is injectable prompt and
resource surface across real MCP servers?** A credible published taxonomy is a reason for a
security team to install the tool this week, and it needs adoption from no one else.

## Scope, in one line

Install open-source MCP servers **locally**, enumerate and scan their **declared** prompt
and resource surface, aggregate the results, and publish the **aggregate** first. Never
call a tool. Never probe a server you do not run. Never name a server publicly before
coordinated disclosure.

## The three zones (and where we operate)

The word "study" spans very different legal footings. We operate only in the first.

- **Zone 1 - local static analysis of open-source software (where we work).** Downloading
  OSS under its license, installing it on our own machine, running it, and reading its
  declared surface is ordinary licensed use and local introspection. This is the bulk of
  the study, because most MCP servers ship as source.
- **Zone 2 - probing hosted servers we do not own (excluded).** Sending requests to someone
  else's live server to test its security, without authorization, carries real exposure
  (unauthorized-access statutes, terms-of-service, jurisdiction-specific computer-misuse
  law). The harness refuses a non-loopback HTTP target by default.
- **Zone 3 - naming a vulnerable server publicly (gated).** Publishing research is fine, but
  naming a maintainer without warning them exposes their users and risks being wrong. Named
  findings wait for coordinated disclosure (below).

This is not legal advice. Before publishing anything that names a vendor or touches a live
third-party endpoint, get counsel; jurisdiction matters.

## Safety guardrails (enforced by the harness)

The harness (`src/airlock/prevalence/`) encodes these so scope is not a matter of
discipline alone:

1. **Initiates no tool call and no state-changing request.** It uses the scanner's read
   path (`fetch_targets` + `scan_targets`): it reads prompt and resource bodies and tool
   *names*, and never calls a tool. Honest scope: reading prompts and resources runs the
   *server's own* read handlers, so a malicious or buggy server could still cause a side
   effect inside a read handler. That residual is inherent to running untrusted software at
   all (the study installs and runs the server by definition, Zone 1); it is mitigated by
   vetting the server and, if wanted, sandboxing the server subprocess, not by the read
   path. What the harness guarantees is that *it* issues no tool call or state-changing
   request. This invariant is stated in the module and must not be relaxed.
2. **Local-only by default, redirects refused.** An HTTP target must be loopback; the host
   is validated with the `ipaddress` module (covering `127.0.0.0/8`, `::1`, and the
   IPv4-mapped form), and the only accepted hostname is `localhost` (other names are refused
   rather than resolved, so a name cannot resolve or rebind to a public address). A
   non-loopback URL is refused unless `--allow-remote` is passed. The study HTTP client also
   does **not follow redirects**, so a loopback server cannot 3xx-bounce the connection to a
   remote host after the pre-connect check has passed.
3. **License-gated.** Every server carries a license. A server whose license is not on the
   analysis allowlist (`LICENSE_ALLOWLIST`) is skipped until a human reviews it and sets
   `analysis_ok: true` on its manifest entry. Copyleft licenses are allowed for analysis
   (they constrain distribution of derivatives, not local inspection).
4. **Fail-safe.** A server that crashes or will not connect is recorded as `failed` and does
   not abort the study.
5. **Anonymizable.** `--anonymize` replaces names with stable pseudonyms so the aggregate can
   be shared before any coordinated disclosure.

## The sampling frame

- Draw the candidate list from public sources (an MCP registry, curated "awesome-mcp" lists,
  package indexes). Pulling a public *list* is fine; the analysis happens on local installs.
- Record for each server: name, install provenance (`source`, e.g. `pip:foo==1.2` or a git
  commit), license, and transport. This is the manifest (`study/example_manifest.json` is a
  self-test manifest that points only at this repo's own fixtures).
- Report what was excluded and why (unlisted license, would not install, non-OSS), so the
  denominator is honest and the study is reproducible.

## Running it

```bash
# Self-test / demo over this repo's own fixtures (no third-party downloads):
uv run airlock prevalence study/example_manifest.json

# A real run: add real OSS servers to a manifest, install each locally (you authorize each
# download), then point the study at it. Publish the aggregate anonymized first:
uv run airlock prevalence study/real_manifest.json --anonymize --format json
```

Each real server must be installed locally first. A Python server is a script path
(`transport: stdio`); a Node or other server is run in HTTP mode locally and given a
loopback URL (`transport: http`), because the stdio launcher runs `python <path>`.

## Publication gates

- **Aggregate, anonymized findings** ("of N servers, X% expose injectable surface; here is
  the class taxonomy"): publishable with no embargo. This is the wedge; ship it first.
- **Named, per-server findings:** require coordinated disclosure, which requires the Phase D
  prerequisites that are deliberately not yet in place:
  - a real repository URL and a monitored security contact (`SECURITY.md`),
  - a written disclosure policy with an embargo window (for example 90 days),
  - notifying each affected maintainer before publication.

Until those exist, the study produces the dataset and the aggregate; it does not name names.

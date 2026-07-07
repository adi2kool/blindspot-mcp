"""Phase C: the prevalence study harness.

Measures how widespread injectable prompt/resource surface is across MCP servers,
by running the existing scanner over each server and aggregating the results. It is
built to stay inside the legally-safe zone (see docs/phase-c-methodology.md):

- Local install only. HTTP targets must be loopback unless a remote is explicitly
  allowed; the harness refuses a non-loopback URL by default and does not follow
  redirects, so a loopback server cannot bounce the connection to a remote host.
- Enumerate and scan the DECLARED surface only. The harness initiates no tool call and
  no state-changing MCP request. It does read prompts and resources, which runs the
  server's own read handlers, so a malicious server could still side-effect inside one;
  that residual is inherent to running untrusted software (Zone 1) and is mitigated by
  vetting/sandboxing, not by the read path.
- Every server carries a license; a server whose license is not on the analysis
  allowlist is skipped until a human vets it.
- Output can be anonymized, so aggregate prevalence can be published without naming
  any server ahead of coordinated disclosure.
"""

from airlock.prevalence.harness import (
    ServerResult,
    ServerSpec,
    StudyResult,
    load_manifest,
    render_study,
    render_study_json,
    run_study,
    scan_one,
)

__all__ = [
    "ServerResult",
    "ServerSpec",
    "StudyResult",
    "load_manifest",
    "render_study",
    "render_study_json",
    "run_study",
    "scan_one",
]

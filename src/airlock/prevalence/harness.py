"""The prevalence harness: scan a set of servers, aggregate, report.

Reuses the Phase 1 scanner end to end (`connect` -> `fetch_targets` -> `scan_targets`).
The only new logic here is the safety gating (license allowlist, loopback-only HTTP with
no redirect-following) and the aggregation.

SAFETY SCOPE, stated honestly. The harness initiates no tool call and no MCP request that
is itself state-changing: it reads the declared prompt and resource surface and tool NAMES
only, and never calls a tool. But reading a server's prompts and resources runs THAT
server's own read handlers, so a malicious or buggy server could still cause a side effect
inside a read handler. That residual is inherent to running untrusted software at all (a
prevalence study installs and runs the server by definition); it is mitigated by vetting
the server and, if needed, sandboxing the server subprocess, not by the read path. What the
harness guarantees is that IT issues no tool call or state-changing request, and that it
never leaves the local machine (loopback-only, redirects refused). Do not add a call_tool.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from airlock.models import AttackClass, Severity
from airlock.scan.client import connect, fetch_targets
from airlock.scan.detectors.patterns import scan_targets

MANIFEST_VERSION = "x-mcp-provenance/prevalence-v0"

# Licenses that clearly permit installing and statically analyzing the software
# locally. Copyleft licenses are included: they constrain DISTRIBUTION of derivatives,
# not running and inspecting software you hold. A server whose license is absent or not
# listed is skipped until a human reviews it and sets `analysis_ok` on its spec.
LICENSE_ALLOWLIST = frozenset(
    {
        "MIT", "MIT-0", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC", "0BSD",
        "MPL-2.0", "UNLICENSE", "CC0-1.0", "PSF-2.0", "PYTHON-2.0",
        "GPL-2.0", "GPL-3.0", "GPL-2.0-OR-LATER", "GPL-3.0-OR-LATER",
        "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "AGPL-3.0-OR-LATER",
    }
)

VALID_TRANSPORTS = ("stdio", "http")

# Status values for a single server's result.
SCANNED = "scanned"
SKIPPED_LICENSE = "skipped_license"
REFUSED_REMOTE = "refused_remote"
FAILED = "failed"


@dataclass(frozen=True)
class ServerSpec:
    """One server to study.

    For stdio, either give a local script path in `target` (launched as `python <target>`),
    or set `command`/`args` to launch a console-script server (e.g. `npx -y @scope/server`
    or `uvx server`), in which case `target` is just a human-facing label. For http, `target`
    is the URL.
    """

    name: str
    target: str
    transport: str = "stdio"  # "stdio" | "http"
    command: str = ""  # stdio: launch this instead of `python <target>` (e.g. "npx", "uvx")
    args: tuple[str, ...] = ()  # arguments for `command`
    license: str = ""
    source: str = ""  # provenance of the install, e.g. "pip:foo==1.2" or a git ref
    notes: str = ""
    analysis_ok: bool = False  # operator override: vetted despite an unlisted license


@dataclass
class ServerResult:
    """The outcome of studying one server.

    `classes` and `severities` are the DISTINCT attack classes and severity levels the
    server exhibits, deduped per server. The study aggregates these at the server level
    (how many servers exhibit a class), which is the meaningful prevalence unit and is
    immune to the scanner emitting several detections for one smuggled instruction.
    `n_findings` keeps the raw detection count for the per-server line, clearly separate
    from the deduped aggregate.
    """

    name: str
    license: str
    status: str
    items_scanned: int = 0
    n_findings: int = 0
    classes: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    detail: str = ""  # why skipped/failed, when applicable

    @property
    def has_error_finding(self) -> bool:
        return Severity.ERROR.value in self.severities


@dataclass
class StudyResult:
    """The aggregate across a set of servers. `by_class`/`by_severity` count how many
    SCANNED servers exhibit each class/severity (server-level prevalence)."""

    servers_total: int
    servers_scanned: int
    servers_skipped: int
    servers_failed: int
    servers_with_error_findings: int
    by_class: dict[str, int]
    by_severity: dict[str, int]
    results: list[ServerResult]

    @property
    def prevalence(self) -> float:
        """Fraction of successfully-scanned servers with at least one ERROR finding.

        Denominator is servers actually scanned (skipped/failed do not count), so the
        figure is not diluted by servers we could not or chose not to analyze.
        """
        return self.servers_with_error_findings / self.servers_scanned if self.servers_scanned else 0.0


def _study_http_client_factory(headers=None, timeout=None, auth=None) -> httpx.AsyncClient:
    """Build the study's httpx client. `follow_redirects=False` is the point: a loopback
    server must not be able to 3xx-redirect the connection to a remote host and thereby
    defeat the local-only guarantee (the host is validated only before connecting)."""
    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout if timeout is not None else httpx.Timeout(30.0),
        auth=auth,
        follow_redirects=False,
    )


def license_permits_analysis(spec: ServerSpec) -> bool:
    """True if the spec's license is on the allowlist, or a human vetted it."""
    if spec.analysis_ok:
        return True
    return str(spec.license).strip().upper() in LICENSE_ALLOWLIST


def _is_loopback(url: str) -> bool:
    """True only for a localhost / loopback HTTP target.

    IP literals are checked with `ipaddress`, so the whole 127.0.0.0/8 block, `::1`, and
    the IPv4-mapped form `::ffff:127.0.0.1` are all recognized. The only accepted HOSTNAME
    is `localhost`; any other name is refused rather than resolved, so a name that resolves
    to a public address (or rebinds) cannot slip through.
    """
    host = (urlparse(url).hostname or "").strip().lower()
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a non-localhost hostname: refuse (do not resolve)
    if ip.is_loopback:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(mapped and mapped.is_loopback)


async def scan_one(spec: ServerSpec, *, allow_remote: bool = False, timeout: float = 90.0) -> ServerResult:
    """Study one server. Never raises: connection failures degrade to a FAILED result.

    `timeout` bounds enumeration of a single server, so a slow or hanging server (a browser
    server pulling a runtime, or a hostile server that never responds) cannot stall the
    whole sequential study; it is recorded FAILED and the study moves on."""
    # License gate first: do not even connect to something we are not cleared to analyze.
    if not license_permits_analysis(spec):
        return ServerResult(
            name=spec.name, license=spec.license, status=SKIPPED_LICENSE,
            detail=f"license {spec.license!r} not on the analysis allowlist; "
                   "set analysis_ok=true after manual review",
        )

    is_http = str(spec.transport).strip().lower() == "http"
    if is_http and not allow_remote and not _is_loopback(spec.target):
        return ServerResult(
            name=spec.name, license=spec.license, status=REFUSED_REMOTE,
            detail=f"refusing non-loopback HTTP target {spec.target!r}; the study is "
                   "local-only (pass allow_remote to override under authorization)",
        )

    factory = _study_http_client_factory if is_http else None
    stdio_command = spec.command or None
    stdio_args = list(spec.args) if spec.command else None

    async def _enumerate():
        async with connect(
            spec.target, is_http, http_client_factory=factory,
            stdio_command=stdio_command, stdio_args=stdio_args,
        ) as (session, _init):
            return await fetch_targets(session)

    try:
        targets, tool_names, errors = await asyncio.wait_for(_enumerate(), timeout=timeout)
        findings = scan_targets(targets, tool_names)
    except (KeyboardInterrupt, SystemExit):
        raise  # an operator abort must propagate, not be recorded as a server failure
    except (Exception, BaseExceptionGroup) as exc:  # noqa: BLE001 - a broken server must not abort the study
        detail = (
            f"timed out after {timeout:g}s"
            if isinstance(exc, (asyncio.TimeoutError, TimeoutError))
            else f"{type(exc).__name__}: {exc}"
        )
        return ServerResult(
            name=spec.name, license=spec.license, status=FAILED, detail=detail,
        )

    classes = sorted({f.attack_class.value for f in findings})
    severities = sorted({f.severity.value for f in findings})
    return ServerResult(
        name=spec.name, license=spec.license, status=SCANNED,
        items_scanned=len(targets), n_findings=len(findings),
        classes=classes, severities=severities, errors=list(errors),
    )


async def run_study(
    specs: list[ServerSpec], *, allow_remote: bool = False, timeout: float = 90.0
) -> StudyResult:
    """Study every server in order and aggregate. Sequential by design: keeps a set of
    local servers from stampeding the machine, and the study is not latency-sensitive."""
    results = [await scan_one(spec, allow_remote=allow_remote, timeout=timeout) for spec in specs]
    return aggregate(specs, results)


def aggregate(specs: list[ServerSpec], results: list[ServerResult]) -> StudyResult:
    """Roll per-server results into a study-level summary. `by_class`/`by_severity` count
    servers exhibiting each class/severity, so one server never contributes more than once
    to a class total regardless of how many detections the scanner emitted for it."""
    by_class: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    scanned = [r for r in results if r.status == SCANNED]
    for r in scanned:
        for c in r.classes:
            by_class[c] = by_class.get(c, 0) + 1
        for s in r.severities:
            by_severity[s] = by_severity.get(s, 0) + 1
    return StudyResult(
        servers_total=len(specs),
        servers_scanned=len(scanned),
        servers_skipped=sum(1 for r in results if r.status in (SKIPPED_LICENSE, REFUSED_REMOTE)),
        servers_failed=sum(1 for r in results if r.status == FAILED),
        servers_with_error_findings=sum(1 for r in scanned if r.has_error_finding),
        by_class=by_class,
        by_severity=by_severity,
        results=results,
    )


def load_manifest(path: str) -> list[ServerSpec]:
    """Load and validate a study manifest (JSON: {version, servers: [...]}).

    Every type is checked, so a malformed manifest is a clean error, and a mistyped field
    (a truthy-string `analysis_ok`, a numeric `license`) can never silently bypass a gate.
    """
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ValueError("manifest must be a JSON object with 'version' and 'servers'")
    if doc.get("version") != MANIFEST_VERSION:
        raise ValueError(f"unsupported manifest version {doc.get('version')!r}; expected {MANIFEST_VERSION!r}")
    servers = doc.get("servers", [])
    if not isinstance(servers, list):
        raise ValueError("'servers' must be a list")
    specs: list[ServerSpec] = []
    for i, s in enumerate(servers):
        if not isinstance(s, dict):
            raise ValueError(f"server #{i} must be an object")
        name, target = s.get("name"), s.get("target")
        if not isinstance(name, str) or not isinstance(target, str):
            raise ValueError(f"server #{i} needs string 'name' and 'target'")
        transport = str(s.get("transport", "stdio")).strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ValueError(f"server #{i}: transport must be one of {VALID_TRANSPORTS}, got {transport!r}")
        license_ = s.get("license", "")
        if not isinstance(license_, str):
            raise ValueError(f"server #{i}: 'license' must be a string")
        analysis_ok = s.get("analysis_ok", False)
        if not isinstance(analysis_ok, bool):
            raise ValueError(f"server #{i}: 'analysis_ok' must be true or false")
        command = s.get("command", "")
        if not isinstance(command, str):
            raise ValueError(f"server #{i}: 'command' must be a string")
        args = s.get("args", [])
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError(f"server #{i}: 'args' must be a list of strings")
        specs.append(
            ServerSpec(
                name=name, target=target, transport=transport, command=command,
                args=tuple(args), license=license_, source=str(s.get("source", "")),
                notes=str(s.get("notes", "")), analysis_ok=analysis_ok,
            )
        )
    return specs


def _class_order() -> list[str]:
    return [ac.value for ac in AttackClass]


def render_study(study: StudyResult, *, anonymize: bool = False) -> str:
    """Human-readable prevalence report. With anonymize=True, server names and the
    reasons behind skips/failures are replaced with stable pseudonyms so the aggregate
    can be shared before any coordinated disclosure."""
    lines: list[str] = ["airlock prevalence study"]
    lines.append(
        f"servers: {study.servers_total} total, {study.servers_scanned} scanned, "
        f"{study.servers_skipped} skipped, {study.servers_failed} failed"
    )
    if study.servers_scanned:
        pct = 100.0 * study.prevalence
        lines.append(
            f"prevalence: {study.servers_with_error_findings}/{study.servers_scanned} "
            f"scanned servers carry >=1 ERROR-level finding ({pct:.0f}%)"
        )
    if study.by_class:
        lines.append("")
        lines.append(f"servers exhibiting each attack class (of {study.servers_scanned} scanned):")
        for cls in _class_order():
            if cls in study.by_class:
                lines.append(f"  {cls:22} {study.by_class[cls]}")
    lines.append("")
    lines.append("per server:")
    for i, r in enumerate(study.results):
        name = f"server-{i:03d}" if anonymize else r.name
        if r.status == SCANNED:
            flag = "FLAGGED" if r.has_error_finding else "clean"
            classes = ",".join(r.classes) if r.classes else "-"
            lines.append(
                f"  [{flag:7}] {name}  items={r.items_scanned} findings={r.n_findings} "
                f"classes={classes}" + (f"  ({r.license})" if not anonymize else "")
            )
        else:
            detail = "" if anonymize else f"  {r.detail}"
            lines.append(f"  [{r.status:14}] {name}{detail}")
    return "\n".join(lines)


def render_study_json(study: StudyResult, *, anonymize: bool = False) -> str:
    """Machine-readable prevalence report."""
    doc = {
        "version": MANIFEST_VERSION,
        "servers_total": study.servers_total,
        "servers_scanned": study.servers_scanned,
        "servers_skipped": study.servers_skipped,
        "servers_failed": study.servers_failed,
        "servers_with_error_findings": study.servers_with_error_findings,
        "prevalence": round(study.prevalence, 4),
        "by_class": study.by_class,
        "by_severity": study.by_severity,
        "servers": [
            {
                "name": f"server-{i:03d}" if anonymize else r.name,
                "status": r.status,
                "items_scanned": r.items_scanned,
                "n_findings": r.n_findings,
                "classes": r.classes,
                "severities": r.severities,
                "error_finding": r.has_error_finding,
                **({} if anonymize else {"license": r.license, "detail": r.detail}),
            }
            for i, r in enumerate(study.results)
        ],
    }
    return json.dumps(doc, indent=2)

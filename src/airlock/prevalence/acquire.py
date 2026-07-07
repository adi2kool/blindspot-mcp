"""Static prevalence sweep: fetch npm / PyPI packages and scan their SOURCE at scale.

This is the safe instrument for the untrusted long tail. For each package it resolves the
release metadata from the public registry, checks the license, downloads the release archive,
and scans the source members - all WITHOUT installing, building, or executing anything:

- No `pip install` / `npm install`, so no setup.py, no lifecycle scripts, no build ever runs.
- The archive is read IN MEMORY and never extracted to disk, so there is no Zip-Slip / tar
  path-traversal surface; a member's name is only ever used as a label.
- Only source files are read, each bounded in size, with caps on file count and total bytes,
  so a decompression bomb cannot exhaust memory.
- Downloads are restricted to the known registry CDNs, so hostile metadata cannot point the
  fetch at an arbitrary host.
- Every package is license-gated (reusing the harness allowlist); an unlisted license is
  skipped until vetted.

Extraction reuses `scan/source.py`; results reuse the harness `ServerResult` / `StudyResult`
aggregation, so a static sweep and a dynamic run report the same shape.
"""

from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import os
import tarfile
import zipfile
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from airlock.prevalence.harness import (
    FAILED,
    SCANNED,
    SKIPPED_LICENSE,
    ServerResult,
    StudyResult,
    aggregate,
    license_permits_analysis,
)
from airlock.scan.detectors.patterns import scan_targets
from airlock.scan.source import extract_from_python, extract_from_typescript, is_test_path

MANIFEST_VERSION = "x-mcp-provenance/prevalence-source-v0"
_PYPI_JSON = "https://pypi.org/pypi/{name}/json"
_NPM_JSON = "https://registry.npmjs.org/{name}"

# Downloads (release files) may only come from these CDNs. The registry JSON is served from
# pypi.org / registry.npmjs.org; ALL requests (including every redirect hop, see
# _validate_request) must stay within this broader set, so hostile metadata or a 3xx cannot
# point the fetch at an arbitrary host.
_ALLOWED_DOWNLOAD_HOSTS = ("files.pythonhosted.org", "registry.npmjs.org")
_ALLOWED_REQUEST_HOSTS = ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org")

_PY_EXT = frozenset({".py"})
_TS_EXT = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"})
_SOURCE_EXT = _PY_EXT | _TS_EXT

_MAX_ARCHIVE_BYTES = 60_000_000    # download cap (COMPRESSED bytes)
_MAX_DECOMPRESSED_BYTES = 150_000_000  # cap on DECOMPRESSED tar bytes (anti decompression-bomb)
_MAX_FILE_BYTES = 1_000_000        # per source file
_MAX_FILES = 20_000                # source files kept per package
_MAX_MEMBERS = 300_000             # archive members inspected per package (anti member-flood)
_MAX_TOTAL_BYTES = 100_000_000     # total source bytes read per package
_HTTP_TIMEOUT = 30.0


def _host_allowed(host: str | None, allowed: tuple[str, ...]) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == a or h.endswith("." + a) for a in allowed)


def _validate_request(request: httpx.Request) -> None:
    """httpx request event hook: runs on the initial request AND every redirect hop, so a
    3xx to a non-allowlisted host is refused (redirects are followed only within the known
    registry/CDN hosts)."""
    if not _host_allowed(request.url.host, _ALLOWED_REQUEST_HOSTS):
        raise ValueError(f"refusing request to non-allowlisted host {request.url.host!r}")


def _make_client() -> httpx.Client:
    return httpx.Client(
        timeout=_HTTP_TIMEOUT, follow_redirects=True,
        event_hooks={"request": [_validate_request]},
    )


def _bounded_decompress(data: bytes, max_out: int) -> bytes:
    """Decompress a gzip/xz/bzip2 stream with a hard cap on OUTPUT bytes, reading at most 1MB
    of decompressed output per step so a decompression bomb (small compressed, huge inflated)
    raises instead of exhausting memory. Returns `data` unchanged if it is not compressed."""
    magic = data[:6]
    if magic[:2] == b"\x1f\x8b":
        stream: io.BufferedIOBase = gzip.GzipFile(fileobj=io.BytesIO(data))
    elif magic[:6] == b"\xfd7zXZ\x00":
        stream = lzma.LZMAFile(io.BytesIO(data))
    elif magic[:3] == b"BZh":
        stream = bz2.BZ2File(io.BytesIO(data))
    else:
        return data
    out = bytearray()
    with stream:
        while True:
            chunk = stream.read(1 << 20)  # bounded DECOMPRESSED output per read
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > max_out:
                raise ValueError(f"archive decompresses beyond {max_out} bytes (bomb)")
    return bytes(out)

# Map common PyPI license classifiers to SPDX ids the allowlist understands.
_CLASSIFIER_LICENSE = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
}


@dataclass(frozen=True)
class PackageSpec:
    """One package to sweep. `license` may be left blank to resolve it from the registry."""

    name: str
    ecosystem: str  # "pypi" | "npm"
    license: str = ""
    analysis_ok: bool = False


def _ext(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def _pypi_license(info: dict) -> str:
    expr = info.get("license_expression")
    if isinstance(expr, str) and expr.strip():
        return expr.strip()
    for c in info.get("classifiers", []) or []:
        if c in _CLASSIFIER_LICENSE:
            return _CLASSIFIER_LICENSE[c]
    lic = info.get("license")
    return lic.strip() if isinstance(lic, str) else ""


def _check_download_host(url: str) -> None:
    if not _host_allowed(urlparse(url).hostname, _ALLOWED_DOWNLOAD_HOSTS):
        raise ValueError(f"refusing download from unexpected host {urlparse(url).hostname!r}")


def _download(client: httpx.Client, url: str) -> bytes:
    _check_download_host(url)
    buf = bytearray()
    with client.stream("GET", url) as resp:
        resp.raise_for_status()
        for chunk in resp.iter_bytes():
            buf.extend(chunk)
            if len(buf) > _MAX_ARCHIVE_BYTES:
                raise ValueError(f"archive exceeds {_MAX_ARCHIVE_BYTES} bytes")
    return bytes(buf)


def resolve_pypi(client: httpx.Client, name: str) -> tuple[str, str, str]:
    """Return (download_url, archive_kind, license) for a PyPI package. Prefers the sdist
    (full source) over a wheel."""
    resp = client.get(_PYPI_JSON.format(name=name))
    resp.raise_for_status()
    data = resp.json()
    license_ = _pypi_license(data.get("info", {}))
    urls = data.get("urls", []) or []
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    wheel = next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None)
    chosen = sdist or wheel
    if not chosen or not chosen.get("url"):
        raise ValueError("no sdist or wheel release found")
    url = chosen["url"]
    kind = "zip" if url.endswith(".whl") else "tar"
    return url, kind, license_


def resolve_npm(client: httpx.Client, name: str) -> tuple[str, str, str]:
    """Return (download_url, archive_kind, license) for the latest npm version."""
    resp = client.get(_NPM_JSON.format(name=name))
    resp.raise_for_status()
    data = resp.json()
    latest = data.get("dist-tags", {}).get("latest")
    version = data.get("versions", {}).get(latest, {}) if latest else {}
    license_ = version.get("license") or data.get("license") or ""
    if isinstance(license_, dict):  # legacy {"type": "MIT"} form
        license_ = license_.get("type", "")
    tarball = version.get("dist", {}).get("tarball")
    if not tarball:
        raise ValueError("no tarball in latest version")
    return tarball, "tar", str(license_)


def _read_source_members(data: bytes, kind: str) -> list[tuple[str, str]]:
    """Read source-file members from an archive IN MEMORY, bounded against bombs on every
    axis: the outer stream is decompressed with a hard output cap, the number of members
    INSPECTED is capped (so a flood of non-source members cannot iterate unbounded), and each
    kept source file plus the running total are size-capped. Never writes to disk; a member
    name is only a label. Skips directories, non-regular members, non-source, and oversized."""
    members: list[tuple[str, str]] = []
    total = 0
    kept = 0
    seen = 0
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                seen += 1
                if seen > _MAX_MEMBERS:
                    break
                if info.is_dir() or _ext(info.filename) not in _SOURCE_EXT or is_test_path(info.filename):
                    continue
                kept += 1
                if kept > _MAX_FILES:
                    break
                if info.file_size > _MAX_FILE_BYTES:
                    continue
                with zf.open(info) as fh:
                    raw = fh.read(_MAX_FILE_BYTES + 1)
                if len(raw) > _MAX_FILE_BYTES:
                    continue
                total += len(raw)
                if total > _MAX_TOTAL_BYTES:
                    break
                members.append((info.filename, raw.decode("utf-8", "ignore")))
    else:
        # Decompress the outer gzip/xz/bz2 with a hard output cap FIRST, then read the plain
        # tar; this bounds the bomb before tarfile's own iteration decompresses the stream.
        raw_tar = _bounded_decompress(data, _MAX_DECOMPRESSED_BYTES)
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as tf:
            for m in tf:
                seen += 1
                if seen > _MAX_MEMBERS:
                    break
                if not m.isfile() or _ext(m.name) not in _SOURCE_EXT or is_test_path(m.name):
                    continue
                kept += 1
                if kept > _MAX_FILES:
                    break
                if m.size > _MAX_FILE_BYTES:
                    continue
                fh = tf.extractfile(m)
                if fh is None:
                    continue
                raw = fh.read(_MAX_FILE_BYTES + 1)
                if len(raw) > _MAX_FILE_BYTES:
                    continue
                total += len(raw)
                if total > _MAX_TOTAL_BYTES:
                    break
                members.append((m.name, raw.decode("utf-8", "ignore")))
    return members


def scan_archive(data: bytes, kind: str):
    """Extract declared strings from every source member of an archive and scan them.
    Returns (targets, findings). Raises on a malformed archive (the caller records FAILED)."""
    targets = []
    for name, text in _read_source_members(data, kind):
        if _ext(name) in _PY_EXT:
            targets.extend(extract_from_python(text, name))
        else:
            targets.extend(extract_from_typescript(text, name))
    return targets, scan_targets(targets, ())


def acquire_and_scan(spec: PackageSpec, client: httpx.Client) -> ServerResult:
    """Resolve, license-gate, download, and statically scan one package. Never raises."""
    # A manifest that already declares a disallowed license is skipped with no network call.
    if spec.license and not license_permits_analysis(spec):
        return ServerResult(spec.name, spec.license, SKIPPED_LICENSE,
                            detail=f"license {spec.license!r} not on the analysis allowlist")
    try:
        if spec.ecosystem == "pypi":
            url, kind, meta_license = resolve_pypi(client, spec.name)
        elif spec.ecosystem == "npm":
            url, kind, meta_license = resolve_npm(client, spec.name)
        else:
            return ServerResult(spec.name, spec.license, FAILED,
                                detail=f"unknown ecosystem {spec.ecosystem!r}")
    except Exception as exc:  # noqa: BLE001 - a bad package must not abort the sweep
        return ServerResult(spec.name, spec.license, FAILED,
                            detail=f"resolve: {type(exc).__name__}: {exc}")

    license_ = spec.license or meta_license
    if not license_permits_analysis(PackageSpec(spec.name, spec.ecosystem, license_, spec.analysis_ok)):
        return ServerResult(spec.name, license_, SKIPPED_LICENSE,
                            detail=f"license {license_!r} not on the analysis allowlist")
    try:
        data = _download(client, url)
        targets, findings = scan_archive(data, kind)
    except Exception as exc:  # noqa: BLE001
        return ServerResult(spec.name, license_, FAILED, detail=f"{type(exc).__name__}: {exc}")

    classes = sorted({f.attack_class.value for f in findings})
    severities = sorted({f.severity.value for f in findings})
    return ServerResult(spec.name, license_, SCANNED, items_scanned=len(targets),
                        n_findings=len(findings), classes=classes, severities=severities)


def run_source_study(specs: list[PackageSpec]) -> StudyResult:
    """Sweep every package (sequentially) and aggregate. Synchronous: acquisition is plain
    HTTP, no event loop needed."""
    with _make_client() as client:
        results = [acquire_and_scan(spec, client) for spec in specs]
    return aggregate(specs, results)


def load_source_manifest(path: str) -> list[PackageSpec]:
    """Load a source-sweep manifest: {version, packages: [{name, ecosystem, license?, analysis_ok?}]}."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ValueError("manifest must be a JSON object with 'version' and 'packages'")
    if doc.get("version") != MANIFEST_VERSION:
        raise ValueError(f"unsupported manifest version {doc.get('version')!r}; expected {MANIFEST_VERSION!r}")
    packages = doc.get("packages", [])
    if not isinstance(packages, list):
        raise ValueError("'packages' must be a list")
    specs: list[PackageSpec] = []
    for i, p in enumerate(packages):
        if not isinstance(p, dict):
            raise ValueError(f"package #{i} must be an object")
        name, eco = p.get("name"), p.get("ecosystem")
        if not isinstance(name, str) or eco not in ("pypi", "npm"):
            raise ValueError(f"package #{i} needs string 'name' and ecosystem 'pypi' or 'npm'")
        license_ = p.get("license", "")
        if not isinstance(license_, str):
            raise ValueError(f"package #{i}: 'license' must be a string")
        analysis_ok = p.get("analysis_ok", False)
        if not isinstance(analysis_ok, bool):
            raise ValueError(f"package #{i}: 'analysis_ok' must be true or false")
        specs.append(PackageSpec(name=name, ecosystem=eco, license=license_, analysis_ok=analysis_ok))
    return specs

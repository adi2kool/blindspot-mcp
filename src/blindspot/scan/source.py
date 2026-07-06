"""Static source scanning: find injectable declared strings in a server's SOURCE.

The dynamic scanner (`scan/client.py`) installs and runs a server, then reads its live
declared surface. That is precise but requires executing the server, which does not scale to
the untrusted long tail. This module extracts the same kind of declared text - tool and
prompt descriptions, parameter descriptions, resource docstrings - directly from a package's
SOURCE FILES, without importing or executing anything, then runs the existing detectors over
it. It is the safe instrument for a breadth prevalence study: no code runs, and servers that
would need credentials to start are still analyzable.

Python is parsed with `ast` (reliable): the docstring of any function decorated with a
`.tool` / `.prompt` / `.resource` decorator, plus any `description=` keyword argument whose
value is a string the parser can reconstruct statically - a literal, an f-string, `+`
concatenation, `%`/`.format()`/`.join()` on literals, or a `NAME` bound to a module/class-level
string constant. TypeScript / JavaScript is best-effort regex (fuzzier): the string value of a
`description:` property and the second string argument of a `.tool(...)` / `.prompt(...)` /
`.resource(...)` call.

Static extraction is approximate by design; treat a static finding as a lead to confirm, not
proof. Known blind spots (a value here is missed): a description assembled by a runtime call
or from data the parser cannot resolve, a tool registered dynamically, a decorator import-
aliased so its name lacks tool/prompt/resource, and a description declared in a non-source
manifest (`.json` / `.yaml` / `.toml`). A dynamic run of the server (`blindspot scan`) covers
what static analysis cannot.
"""

from __future__ import annotations

import ast
import os
import re
import stat
from pathlib import Path

from blindspot.models import Finding, Report, ScanTarget
from blindspot.scan.detectors.patterns import scan_targets

# Directories that are dependencies, build output, or VCS metadata - not the server's
# own declared surface. Pruned during the walk.
_SKIP_DIRS = frozenset({
    "node_modules", ".git", ".venv", "venv", "env", "dist", "build", "out",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", ".ruff_cache",
    "coverage", ".next", ".turbo", "vendor", "site-packages",
})
_PY_EXT = frozenset({".py"})
_TS_EXT = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"})
_MAX_FILE_BYTES = 1_000_000  # skip huge/minified bundles

# Test / fixture / example code is not the server's shipped declared surface, and it often
# contains DELIBERATE injection samples (a security tool's `vulnerable-server` fixture). Skip
# it so the study measures what a server actually declares, not its own test data.
_TEST_DIR_SEGMENTS = frozenset({
    "test", "tests", "__tests__", "spec", "specs", "e2e", "fixture", "fixtures",
    "example", "examples", "mock", "mocks", "__mocks__", "testdata",
})
_TEST_FILE_RE = re.compile(
    r"\.(test|spec)\.[^./]+$"                # foo.test.ts / foo.spec.py
    r"|(^|/)(test_[^/]*|conftest)\.py$"      # pytest files
    r"|(^|[/_.\-])vulnerable([/_.\-]|$)",    # deliberate vulnerable-* example servers
    re.I,
)


def is_test_path(rel: str) -> bool:
    """True for test / fixture / example source (by directory segment or file name)."""
    norm = rel.replace("\\", "/").lower()
    if any(seg in _TEST_DIR_SEGMENTS for seg in norm.split("/")[:-1]):
        return True
    return bool(_TEST_FILE_RE.search(norm))


def _decorator_surface(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """If the function is decorated as a tool/prompt/resource, return that surface."""
    for dec in func.decorator_list:
        node = dec.func if isinstance(dec, ast.Call) else dec
        name = node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else None
        if not name:
            continue
        low = name.lower()
        if "tool" in low:
            return "tool"
        if "prompt" in low:
            return "prompt"
        if "resource" in low:
            return "resource"
    return None


def _static_str(node: ast.AST, names: dict[str, str] | None = None, depth: int = 0) -> str | None:
    """Reconstruct the STATIC text of a string expression, where an injection lives even
    when the author did not use a bare literal. Handles: a literal; the literal parts of an
    f-string (dynamic `{...}` parts dropped); `+` concatenation and `%` formatting; a
    `"tmpl".format(...)` / `sep.join([...])` on literals; and a `NAME` bound to a
    module/class-level string constant (via `names`). Bounded depth so a deep expression
    that `ast.parse` accepted cannot overflow the stack here."""
    if depth > 20 or node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return names.get(node.id) if names else None
    if isinstance(node, ast.JoinedStr):
        parts = [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        return "".join(parts) or None
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            left = _static_str(node.left, names, depth + 1) or ""
            right = _static_str(node.right, names, depth + 1) or ""
            return (left + right) or None
        if isinstance(node.op, ast.Mod):  # "tmpl %s" % x -> the template
            return _static_str(node.left, names, depth + 1)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":  # "tmpl {}".format(x) -> the template
            return _static_str(node.func.value, names, depth + 1)
        if node.func.attr == "join" and node.args:  # sep.join([lit, lit])
            sep = _static_str(node.func.value, names, depth + 1) or ""
            arg = node.args[0]
            if isinstance(arg, ast.List | ast.Tuple):
                parts = [_static_str(e, names, depth + 1) or "" for e in arg.elts]
                return sep.join(parts) or None
    return None


def _collect_names(tree: ast.AST) -> dict[str, str]:
    """Map NAME -> static string for module/class-level `NAME = "literal"` assignments, so a
    `description=NAME` can be resolved. Literal-only (no name-to-name chains), which is enough
    for the common `_DESC = "..."` pattern and keeps it cheap and safe."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            val = _static_str(node.value)
            if val:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        names[tgt.id] = val
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            val = _static_str(node.value) if node.value is not None else None
            if val:
                names[node.target.id] = val
    return names


def extract_from_python(source: str, path: str) -> list[ScanTarget]:
    """Extract declared strings from Python source via `ast`. Never executes the code; a
    syntax error or a stack-blowing pathological expression yields nothing (fail-safe)."""
    targets: list[ScanTarget] = []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return targets
    names = _collect_names(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            surface = _decorator_surface(node)
            if surface:
                doc = ast.get_docstring(node)
                if doc and doc.strip():
                    targets.append(ScanTarget(surface, f"{path}::{node.name}", doc))
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "description":
                    text = _static_str(kw.value, names)
                    if text and text.strip():
                        targets.append(ScanTarget("tool", f"{path}::description", text))
    return targets


# description: "..." | '...' | `...`  (quote-aware, newline-crossing for template literals).
# The bound is POSSESSIVE (`{0,4000}+`, Python 3.11+) so an unterminated string with a long
# run of backslashes cannot cause catastrophic backtracking (ReDoS) on hostile source.
_TS_DESCRIPTION = re.compile(
    r"""description\s*:\s*(?P<q>["'`])(?P<val>(?:\\.|(?!(?P=q)).){0,4000}+)(?P=q)""",
    re.DOTALL,
)


# .tool("name", "the description", ...) / .prompt(...) / .resource(...): the SECOND string
# argument is commonly the description. Possessive bounds keep it ReDoS-safe.
_TS_CALL_DESC = re.compile(
    r"""\.(?:tool|prompt|resource)\s*\(\s*"""
    r"""(?P<q1>["'`])(?:\\.|(?!(?P=q1)).){0,200}+(?P=q1)\s*,\s*"""
    r"""(?P<q2>["'`])(?P<val>(?:\\.|(?!(?P=q2)).){0,4000}+)(?P=q2)""",
    re.DOTALL,
)


def _unescape_js(s: str) -> str:
    return (
        s.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
        .replace("\\'", "'").replace("\\`", "`").replace("\\\\", "\\")
    )


def extract_from_typescript(source: str, path: str) -> list[ScanTarget]:
    """Best-effort extraction from TS/JS source: the string value of a `description:`
    property, and the second string argument of a `.tool(...)`/`.prompt(...)`/`.resource(...)`
    call. Regex, so approximate; possessive quantifiers avoid catastrophic backtracking."""
    targets: list[ScanTarget] = []
    for m in _TS_DESCRIPTION.finditer(source):
        val = _unescape_js(m.group("val"))
        if val.strip():
            targets.append(ScanTarget("tool", f"{path}::description", val))
    for m in _TS_CALL_DESC.finditer(source):
        val = _unescape_js(m.group("val"))
        if val.strip():
            targets.append(ScanTarget("tool", f"{path}::call-arg", val))
    return targets


def _walk_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in _SKIP_DIRS and d.lower() not in _TEST_DIR_SEGMENTS and not d.startswith(".")
        ]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if (ext in _PY_EXT or ext in _TS_EXT) and not is_test_path(name):
                yield Path(dirpath) / name


def scan_source_tree(root: str | Path) -> tuple[list[ScanTarget], list[Finding], list[str], int]:
    """Extract declared strings from every source file under `root` and scan them.

    Returns (targets, findings, errors, files_scanned). A file that cannot be read or parsed
    is recorded in errors and skipped, so one bad file never aborts the scan.
    """
    root = Path(root)
    targets: list[ScanTarget] = []
    errors: list[str] = []
    files_scanned = 0
    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        try:
            st = path.stat()
            # Only read REGULAR files. A FIFO/device/socket would make read_text block or
            # misbehave (a FIFO reports size 0, so a size cap alone does not catch it).
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_FILE_BYTES:
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            errors.append(f"{rel}: {exc}")
            continue
        try:
            ext = path.suffix.lower()
            if ext in _PY_EXT:
                targets.extend(extract_from_python(source, rel))
            else:
                targets.extend(extract_from_typescript(source, rel))
            files_scanned += 1
        except Exception as exc:  # noqa: BLE001 - one pathological file must not abort the whole scan
            errors.append(f"{rel}: {type(exc).__name__}: {exc}")
    # No tool-name list in a static scan, so the name-dependent shadowing rule is inert; the
    # tool-surface softening still down-ranks the name-independent redirect rule to NOTE.
    findings = scan_targets(targets, ())
    return targets, findings, errors, files_scanned


def scan_source_report(root: str | Path) -> Report:
    """Run a static source scan and package it as a Report (human / JSON / SARIF renderable)."""
    targets, findings, errors, _files = scan_source_tree(root)
    report = Report(target=str(root))
    report.items_scanned = len(targets)
    report.findings = findings
    report.errors = errors
    return report

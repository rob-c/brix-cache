#!/usr/bin/env python3
#
# check_python_deps.py — the Python dependency surface is declared and bounded.
#
# WHAT: Three rules over the requirements files and every .py under the scanned
#       trees. Exit 1 on any violation.
#         R1 declared   — every third-party import is named by a requirements
#                         file (or is a documented system package).
#         R2 bounded    — every requirement carries a lower AND an upper bound.
#         R3 honest     — nothing listed as *optional* is imported at module
#                         scope, where its absence breaks collection for all.
#
# WHY:  requirements.txt listed three packages against a suite that imports
#       fifteen, and every entry was an open-ended `>=` — so a fresh clone hit
#       ImportError on packages nobody had written down, and CI silently
#       absorbed every new major release of the ones that were. Both halves are
#       supply-chain surface: an unbounded floor means the code you test is not
#       the code you reviewed. R3 exists because `import zstandard` at module
#       scope in a suite that elsewhere `importorskip`s it (found by this guard
#       on first run, 2026-08-03) turns an optional dependency into a mandatory
#       one for anyone merely *collecting* that file.
#
# HOW:  Parse each requirements file for name + specifier. AST-walk the trees
#       and classify each import as module-scope or guarded (inside try/except
#       or a function body); `pytest.importorskip("x")` counts as a guarded use,
#       since that is the sanctioned idiom. Map import names to distribution
#       names via IMPORT_TO_DIST, and skip stdlib plus this repo's own modules.
#
# USAGE:
#   tools/ci/check_python_deps.py            # exit 0 clean, 1 with findings
#   tools/ci/check_python_deps.py --list     # show the resolved import surface

import ast
import re
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Requirements files and the lane each one declares. "optional" is the only
# lane R3 polices; "dev" tooling is never imported by the tree at all.
REQ_FILES = {
    "requirements.txt": "required",
    "requirements-optional.txt": "optional",
    "requirements-dev.txt": "dev",
    "k8s-tests/pytests/requirements.txt": "required",
}

# Trees whose imports must be declared. Everything else (build outputs, vendored
# RPM trees, agent worktrees) is not ours to pin.
SCAN = ("tests", "tools", "utils", "k8s-tests", "brixtest")
SCAN_FILES = ("conftest.py",)

# PEP 621 manifests (TS-1, testsuite-modernization-plan §12 #1): [project]
# dependencies declare the required lane, optional-dependencies the optional
# lane (a group literally named "dev" declares dev tooling). Same R2 bounds
# rule as the requirements files.
PYPROJECT_FILES = ("brixtest/pyproject.toml",)

# A dist may appear in several manifests with different lanes; the strongest
# claim wins (required beats optional beats dev), so an extra can never
# demote a hard dependency into R3's optional policing.
_LANE_RANK = {"required": 0, "optional": 1, "dev": 2}

# Import name -> PyPI distribution name, where they differ.
IMPORT_TO_DIST = {
    "XRootD": "xrootd",
    "yaml": "PyYAML",
    "brotli": "Brotli",
    "requests_aws4auth": "requests-aws4auth",
    "OpenSSL": "pyOpenSSL",
    "xdist": "pytest-xdist",
}

# Not on PyPI: shipped by the distro's ceph packages (python3-rados,
# python3-cephfs) and pinned by the cluster, not by us. The Ceph labs already
# self-skip when they are missing.
SYSTEM_MODULES = {
    "rados": "ceph python3-rados (distro package, not on PyPI)",
    "cephfs": "ceph python3-cephfs (distro package, not on PyPI)",
}

_NAME_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(.*)$")


def _norm(name: str) -> str:
    """PEP 503 normalization — `PyYAML`, `pyyaml` and `py_yaml` are one name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements(path: Path) -> list[tuple[str, str, int]]:
    """(name, specifier, lineno) for each requirement in a pip requirements file."""
    out = []
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _NAME_RE.match(line)
        if m:
            out.append((m.group(1), m.group(2).strip(), lineno))
    return out


def _local_module_names(root: Path) -> set[str]:
    """Module names resolvable inside this repo — never third-party."""
    names = set()
    for tree in SCAN:
        base = root / tree
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            names.add(p.stem)
            names.add(p.parent.name)
    return names


def _sources(root: Path) -> list[Path]:
    """The .py files that are (or are meant to be) in the repo.

    Tracked plus not-yet-added, minus anything gitignored: `.gitignore` blanket-
    ignores `tools/*`, which shelters half-written scratch scripts that must not
    gate a push. Falls back to a plain walk when git is unavailable (tarball)."""
    try:
        return _git_sources(root)
    except Exception:
        return _walk_sources(root)


def _git_sources(root):
    out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others",
             "--exclude-standard", "-z", "--", *SCAN, *SCAN_FILES],
            capture_output=True,
            check=True,
        )
    listed = [name for name in out.stdout.decode().split("\0") if name.endswith(".py")]
    return sorted({root / name for name in listed if (root / name).is_file()})


def _walk_sources(root):
    found = []
    for tree in SCAN:
        base = root / tree
        if base.exists():
            found.extend(base.rglob("*.py"))
    found.extend(root / name for name in SCAN_FILES if (root / name).exists())
    return sorted(set(found))


def _imports(tree: ast.AST, check_importorskip: bool):
    """Yield (module, lineno, guarded) for every import in a parsed file.

    `guarded` means the statement cannot break collection: it sits inside a
    try/except or a function body. A module-scope `pytest.importorskip("x")`
    is reported as a guarded use of x — that is the sanctioned idiom here."""

    # Import statements can occur only in statement bodies; visiting expression
    # nodes too costs ~3.2M AST edges across this tree without finding an import.
    # Retain the exact parent-derived guard semantics while walking only nested
    # statements. Except handlers and match cases are containers, not statements,
    # so their body lists need their small explicit bridge below.
    yield from _syntax_imports(tree)
    if check_importorskip:
        yield from _importorskip_calls(tree)


def _syntax_imports(tree):
    stack = [(tree, False)]
    while stack:
        node, guarded = stack.pop()
        inner = guarded or _guards_import(node)
        yield from _node_imports(node, guarded)
        stack.extend(_child_statements(node, inner))


def _guards_import(node):
    return isinstance(node, (ast.Try, ast.FunctionDef, ast.AsyncFunctionDef))


def _node_imports(node, guarded):
    if isinstance(node, ast.Import):
        for alias in node.names:
            yield alias.name.split(".")[0], node.lineno, guarded
        return
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        yield node.module.split(".")[0], node.lineno, guarded


def _child_statements(node, guarded):
    children = []
    for _field, value in ast.iter_fields(node):
        if isinstance(value, ast.stmt):
            children.append((value, guarded))
        elif isinstance(value, list):
            children.extend(_statement_list(value, guarded))
    return children


def _statement_list(values, guarded):
    children = []
    for child in values:
        if isinstance(child, ast.stmt):
            children.append((child, guarded))
        elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
            children.extend((statement, guarded) for statement in child.body)
    return children


def _importorskip_calls(tree):
    for node in ast.walk(tree):
        name = _importorskip_name(node)
        if name:
            yield name, node.lineno, True


def _importorskip_name(node):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr != "importorskip" or not node.args:
        return None
    value = node.args[0]
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return None
    return value.value.split(".")[0]


def _set_lane(lanes: dict[str, str], dist: str, lane: str) -> None:
    held = lanes.get(dist)
    if held is None or _LANE_RANK[lane] < _LANE_RANK[held]:
        lanes[dist] = lane


def _check_bounds(findings: list[str], where: str, name: str, spec: str) -> None:
    lower, upper = _bound_flags(spec)
    if lower and upper:
        return
    missing = _missing_bound(lower, upper)
    suffix = " " + spec if spec else ""
    findings.append(
        f"{where}: {name}{suffix} — {missing} bound missing; use "
        f"`name>=X,<Y` so a new major cannot enter CI unreviewed"
    )


def _bound_flags(spec):
    exact = "==" in spec or "~=" in spec
    return ">=" in spec or exact, "<" in spec or exact


def _missing_bound(lower, upper):
    if lower:
        return "upper"
    return "lower" if upper else "both"


def _parse_pyproject(path: Path) -> list[tuple[str, str, str]]:
    """(name, specifier, lane) for a PEP 621 [project] table."""
    try:
        import tomllib
        project = tomllib.loads(path.read_text()).get("project", {})
    except ModuleNotFoundError:  # pre-3.11 lane: the requirement strings are
        return _parse_pyproject_naive(path)  # flat enough for a line parser
    out = _project_requirements(project.get("dependencies", []), "required")
    for group, reqs in project.get("optional-dependencies", {}).items():
        lane = "dev" if group == "dev" else "optional"
        out.extend(_project_requirements(reqs, lane))
    return out


def _project_requirements(requirements, lane):
    out = []
    for requirement in requirements:
        match = _NAME_RE.match(requirement)
        if match:
            out.append((match.group(1), match.group(2).strip(), lane))
    return out


def _parse_pyproject_naive(path: Path) -> list[tuple[str, str, str]]:
    out, lane = [], None
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        lane, requirement = _naive_project_line(line, lane)
        if requirement:
            out.append(requirement)
    return out


def _naive_project_line(line, lane):
    if line.startswith("dependencies"):
        return "required", None
    if line.startswith("[project.optional-dependencies]"):
        return "optional", None
    if line.startswith("["):
        return None, None
    if lane and line.startswith('"'):
        match = _NAME_RE.match(line.strip('",'))
        requirement = _matched_requirement(match, lane)
        return lane, requirement
    if lane == "required" and line.endswith("]"):
        return None, None
    return lane, None


def _matched_requirement(match, lane):
    if not match:
        return None
    return match.group(1), match.group(2).strip(), lane


def _parse_source(path: Path):
    """Parse one source in a worker; AST traversal is CPU-bound."""
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except SyntaxError as exc:
        return path, [], str(exc)
    return path, list(_imports(tree)), None


def _declared(root: Path) -> tuple[dict[str, str], list[str]]:
    """(normalized dist name -> lane, R2 findings)."""
    lanes: dict[str, str] = {}
    findings: list[str] = []
    _declare_requirements(root, lanes, findings)
    _declare_projects(root, lanes, findings)
    return lanes, findings


def _declare_requirements(root, lanes, findings):
    for relative, lane in REQ_FILES.items():
        path = root / relative
        if not path.exists():
            findings.append(f"{relative}: missing — declared in REQ_FILES but not on disk")
            continue
        for name, spec, lineno in _parse_requirements(path):
            _set_lane(lanes, _norm(name), lane)
            _check_bounds(findings, f"{relative}:{lineno}", name, spec)


def _declare_projects(root, lanes, findings):
    for relative in PYPROJECT_FILES:
        path = root / relative
        if not path.exists():
            findings.append(f"{relative}: missing — declared in PYPROJECT_FILES but not on disk")
            continue
        for name, spec, lane in _parse_pyproject(path):
            _set_lane(lanes, _norm(name), lane)
            _check_bounds(findings, relative, name, spec)


def _parse_all(sources: list[Path]):
    """Parse every source, in parallel when possible.

    Falls back to serial when the worker pool cannot resolve _parse_source —
    e.g. when this module was loaded via importlib (the test harness's _load),
    so a spawned worker cannot import it by name and pickling the callable
    fails. The result is identical; only the speed differs, so a broken pool
    must never fail the check itself."""
    try:
        with ProcessPoolExecutor(max_workers=min(4, len(sources) or 1)) as pool:
            return list(pool.map(_parse_source, sources, chunksize=16))
    except Exception:  # noqa: BLE001 — PicklingError / BrokenProcessPool / etc.
        return [_parse_source(p) for p in sources]


def _lane_finding(mod, lineno, rel, dist, lane, guarded):
    """Finding string for one third-party import's declared lane (or None)."""
    if lane is None:
        return (f"{rel}:{lineno}: imports `{mod}` ({dist}), which no "
                f"requirements file declares — add it with bounds, or map "
                f"it in IMPORT_TO_DIST/SYSTEM_MODULES")
    if lane == "optional" and not guarded:
        return (f"{rel}:{lineno}: `{mod}` is declared optional but imported "
                f"at module scope — collection fails without it. Use "
                f"`{mod} = pytest.importorskip(\"{mod}\")`, or promote it to "
                f"requirements.txt")
    if lane == "dev":
        return (f"{rel}:{lineno}: `{mod}` is dev tooling; the test tree must "
                f"not import it")
    return None


def _classify_import(mod, lineno, guarded, rel, lanes, local, stdlib, surface):
    """Finding string for one import (or None). Records module-scope surface."""
    if mod in stdlib or mod in local or mod in SYSTEM_MODULES:
        return None
    surface[mod] = surface.get(mod, False) or not guarded
    dist = _norm(IMPORT_TO_DIST.get(mod, mod))
    return _lane_finding(mod, lineno, rel, dist, lanes.get(dist), guarded)


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    lanes, findings = _declared(root)
    local = _local_module_names(root)
    stdlib = set(sys.stdlib_module_names)
    surface = {}
    for path in _sources(root):
        _audit_source(path, root, lanes, local, stdlib, surface, findings)
    return not findings, sorted(set(findings))


def _audit_source(path, root, lanes, local, stdlib, surface, findings):
    parsed = _parse_source(path, root, findings)
    if parsed is None:
        return
    text, tree = parsed
    for module, lineno, guarded in _imports(tree, "importorskip" in text):
        if module in stdlib or module in local or module in SYSTEM_MODULES:
            continue
        surface[module] = surface.get(module, False) or not guarded
        finding = _import_finding(path, root, module, lineno, guarded, lanes)
        if finding:
            findings.append(finding)


def _parse_source(path, root, findings=None):
    try:
        text = path.read_text(errors="replace")
        return text, ast.parse(text)
    except SyntaxError as error:
        if findings is not None:
            findings.append(f"{path.relative_to(root)}: unparseable — {error}")
        return None


def _import_finding(path, root, module, lineno, guarded, lanes):
    dist = _norm(IMPORT_TO_DIST.get(module, module))
    lane = lanes.get(dist)
    relative = path.relative_to(root)
    if lane is None:
        return (f"{relative}:{lineno}: imports `{module}` ({dist}), which no "
                f"requirements file declares — add it with bounds, or map "
                f"it in IMPORT_TO_DIST/SYSTEM_MODULES")
    if lane == "optional" and not guarded:
        return (f"{relative}:{lineno}: `{module}` is declared optional but imported "
                f"at module scope — collection fails without it. Use "
                f"`{module} = pytest.importorskip(\"{module}\")`, or promote it "
                f"to requirements.txt")
    if lane == "dev":
        return (f"{relative}:{lineno}: `{module}` is dev tooling; the test tree "
                f"must not import it")
    return None


def _list(root: Path) -> None:
    lanes, _ = _declared(root)
    local = _local_module_names(root)
    stdlib = set(sys.stdlib_module_names)
    surface = {}
    for path in _sources(root):
        _collect_surface(path, root, local, stdlib, surface)
    for mod in sorted(surface):
        _print_surface_module(mod, surface[mod], lanes)


def _collect_surface(path, root, local, stdlib, surface):
    parsed = _parse_source(path, root)
    if parsed is None:
        return
    text, tree = parsed
    for module, _lineno, guarded in _imports(tree, "importorskip" in text):
        if module not in stdlib and module not in local:
            surface[module] = surface.get(module, False) or not guarded


def _print_surface_module(module, at_module_scope, lanes):
    dist = _norm(IMPORT_TO_DIST.get(module, module))
    lane = SYSTEM_MODULES.get(module) or lanes.get(dist, "UNDECLARED")
    scope = "module-scope" if at_module_scope else "guarded"
    print(f"{module:22s} {scope:13s} {lane}")


def main() -> int:
    if "--list" in sys.argv[1:]:
        _list(ROOT)
        return 0
    ok, findings = run(ROOT)
    if not ok:
        print("check_python_deps: FAIL", file=sys.stderr)
        for line in findings:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("check_python_deps: OK (imports declared, bounds two-sided)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

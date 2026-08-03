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
SCAN = ("tests", "tools", "utils", "k8s-tests")
SCAN_FILES = ("conftest.py",)

# Import name -> PyPI distribution name, where they differ.
IMPORT_TO_DIST = {
    "XRootD": "xrootd",
    "yaml": "PyYAML",
    "brotli": "Brotli",
    "requests_aws4auth": "requests-aws4auth",
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
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others",
             "--exclude-standard", "-z", "--", *SCAN, *SCAN_FILES],
            capture_output=True,
            check=True,
        )
        listed = [f for f in out.stdout.decode().split("\0") if f.endswith(".py")]
        return sorted({root / f for f in listed})
    except Exception:
        found = [p for tree in SCAN for p in (root / tree).rglob("*.py")
                 if (root / tree).exists()]
        found += [root / n for n in SCAN_FILES if (root / n).exists()]
        return sorted(set(found))


def _imports(tree: ast.AST):
    """Yield (module, lineno, guarded) for every import in a parsed file.

    `guarded` means the statement cannot break collection: it sits inside a
    try/except or a function body. A module-scope `pytest.importorskip("x")`
    is reported as a guarded use of x — that is the sanctioned idiom here."""

    def walk(node, guarded: bool):
        for child in ast.iter_child_nodes(node):
            inner = guarded or isinstance(
                node, (ast.Try, ast.FunctionDef, ast.AsyncFunctionDef)
            )
            if isinstance(child, ast.Import):
                for alias in child.names:
                    yield alias.name.split(".")[0], child.lineno, inner
            elif isinstance(child, ast.ImportFrom) and child.level == 0 and child.module:
                yield child.module.split(".")[0], child.lineno, inner
            elif (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "importorskip"
                and child.args
                and isinstance(child.args[0], ast.Constant)
                and isinstance(child.args[0].value, str)
            ):
                yield child.args[0].value.split(".")[0], child.lineno, True
            yield from walk(child, inner)

    yield from walk(tree, False)


def _declared(root: Path) -> tuple[dict[str, str], list[str]]:
    """(normalized dist name -> lane, R2 findings)."""
    lanes: dict[str, str] = {}
    findings: list[str] = []
    for rel, lane in REQ_FILES.items():
        path = root / rel
        if not path.exists():
            findings.append(f"{rel}: missing — declared in REQ_FILES but not on disk")
            continue
        for name, spec, lineno in _parse_requirements(path):
            lanes[_norm(name)] = lane
            has_lower = ">=" in spec or "==" in spec or "~=" in spec
            has_upper = "<" in spec or "==" in spec or "~=" in spec
            if not (has_lower and has_upper):
                missing = "upper" if has_lower else "lower" if has_upper else "both"
                findings.append(
                    f"{rel}:{lineno}: {name}{' ' + spec if spec else ''} — "
                    f"{missing} bound missing; use `name>=X,<Y` so a new major "
                    f"cannot enter CI unreviewed"
                )
    return lanes, findings


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    lanes, findings = _declared(root)
    local = _local_module_names(root)
    stdlib = set(sys.stdlib_module_names)
    surface: dict[str, bool] = {}  # import name -> seen at module scope

    for path in _sources(root):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except SyntaxError as exc:
            findings.append(f"{path.relative_to(root)}: unparseable — {exc}")
            continue
        for mod, lineno, guarded in _imports(tree):
            if mod in stdlib or mod in local or mod in SYSTEM_MODULES:
                continue
            surface[mod] = surface.get(mod, False) or not guarded
            dist = _norm(IMPORT_TO_DIST.get(mod, mod))
            lane = lanes.get(dist)
            rel = path.relative_to(root)
            if lane is None:
                findings.append(
                    f"{rel}:{lineno}: imports `{mod}` ({dist}), which no "
                    f"requirements file declares — add it with bounds, or map "
                    f"it in IMPORT_TO_DIST/SYSTEM_MODULES"
                )
            elif lane == "optional" and not guarded:
                findings.append(
                    f"{rel}:{lineno}: `{mod}` is declared optional but imported "
                    f"at module scope — collection fails without it. Use "
                    f"`{mod} = pytest.importorskip(\"{mod}\")`, or promote it to "
                    f"requirements.txt"
                )
            elif lane == "dev":
                findings.append(
                    f"{rel}:{lineno}: `{mod}` is dev tooling; the test tree must "
                    f"not import it"
                )
    return not findings, sorted(set(findings))


def _list(root: Path) -> None:
    lanes, _ = _declared(root)
    local = _local_module_names(root)
    stdlib = set(sys.stdlib_module_names)
    surface: dict[str, bool] = {}
    for path in _sources(root):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except SyntaxError:
            continue
        for mod, _lineno, guarded in _imports(tree):
            if mod in stdlib or mod in local:
                continue
            surface[mod] = surface.get(mod, False) or not guarded
    for mod in sorted(surface):
        dist = _norm(IMPORT_TO_DIST.get(mod, mod))
        lane = SYSTEM_MODULES.get(mod) or lanes.get(dist, "UNDECLARED")
        scope = "module-scope" if surface[mod] else "guarded"
        print(f"{mod:22s} {scope:13s} {lane}")


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

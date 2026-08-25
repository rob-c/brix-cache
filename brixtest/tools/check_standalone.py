#!/usr/bin/env python3
"""Refuse imports that make the brixtest package depend on its host repository."""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_TREES = ("src", "tests", "examples", "compat_tests", "tools")
# Every non-stdlib import must belong to BriXTest itself or to one of its
# bounded base/optional dependencies in pyproject.toml.  Repository-local
# packages deliberately never appear here.
ALLOWED_EXTERNAL = {
    "botocore", "cryptography", "duckdb", "packaging", "pluggy", "pyarrow", "pytest",
    "quality_paths", "xdist",
}
FORBIDDEN_ADAPTER = "brix_" + "suite"


def _imports(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [item.name.split(".")[0] for item in node.names]
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        return [node.module.split(".")[0]]
    return []


def _path_findings(path: Path) -> list[str]:
    text = path.read_text()
    tree = ast.parse(text, filename=str(path))
    findings = []
    for node in ast.walk(tree):
        for name in _imports(node):
            if name == "brixtest" or name in sys.stdlib_module_names \
                    or name in ALLOWED_EXTERNAL:
                continue
            findings.append("%s:%d imports %s" % (path.relative_to(ROOT), node.lineno, name))
    if FORBIDDEN_ADAPTER in text:
        findings.append(
            "%s references repository adapter %s" % (
                path.relative_to(ROOT), FORBIDDEN_ADAPTER,
            )
        )
    return findings


def main() -> int:
    findings = _all_findings()
    _report(findings)
    return int(bool(findings))


def _all_findings() -> list[str]:
    imports = [
        finding
        for tree in PYTHON_TREES
        for path in sorted((ROOT / tree).rglob("*.py"))
        for finding in _path_findings(path)
    ]
    return [*imports, *_external_links()]


def _external_links() -> list[str]:
    findings = []
    for path in ROOT.rglob("*"):
        if not path.is_symlink():
            continue
        try:
            path.resolve().relative_to(ROOT)
        except ValueError:
            findings.append("%s links outside BriXTest" % path.relative_to(ROOT))
    return findings


def _report(findings: list[str]) -> None:
    for finding in findings:
        print("FAIL " + finding)
    if not findings:
        print("check_standalone: OK")


if __name__ == "__main__":
    raise SystemExit(main())

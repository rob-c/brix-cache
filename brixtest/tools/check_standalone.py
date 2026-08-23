#!/usr/bin/env python3
"""Refuse imports that make the brixtest package depend on its host repository."""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "brixtest"
# Every non-stdlib import must belong to BriXTest itself or to one of its
# bounded base/optional dependencies in pyproject.toml.  Repository-local
# packages deliberately never appear here.
ALLOWED_EXTERNAL = {
    "botocore", "cryptography", "duckdb", "pluggy", "pyarrow", "pytest", "xdist",
}


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
    if "brix_suite" in text:
        findings.append("%s references repository adapter brix_suite" % path.relative_to(ROOT))
    return findings


def main() -> int:
    findings = _all_findings()
    _report(findings)
    return int(bool(findings))


def _all_findings() -> list[str]:
    return [
        finding
        for path in sorted(PACKAGE.rglob("*.py"))
        for finding in _path_findings(path)
    ]


def _report(findings: list[str]) -> None:
    for finding in findings:
        print("FAIL " + finding)
    if not findings:
        print("check_standalone: OK")


if __name__ == "__main__":
    raise SystemExit(main())

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


def main() -> int:
    findings = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [item.name.split(".")[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name == "brixtest" or name in sys.stdlib_module_names:
                    continue
                if name not in ALLOWED_EXTERNAL:
                    findings.append("%s:%d imports %s" % (
                        path.relative_to(ROOT), node.lineno, name
                    ))
        if "brix_suite" in path.read_text():
            findings.append("%s references repository adapter brix_suite" % path.relative_to(ROOT))
    for finding in findings:
        print("FAIL " + finding)
    if not findings:
        print("check_standalone: OK")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

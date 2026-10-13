#!/usr/bin/env python3
"""Keep server and complete standalone diagnostics on the logging adapters."""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.refactor.normalize_server_logging import ADAPTER, normalize
from tools.refactor.normalize_client_logging import migrate
from tools.logging_support import diagnostic


def _server_violations(root):
    failures = []
    for path in (root / "src").rglob("*"):
        if path.suffix in (".c", ".h") and path != ADAPTER:
            if normalize(path.read_text())[1]:
                failures.append(f"{path.relative_to(root)}: raw nginx logging")
    return failures


def _native_violations(root):
    failures = []
    for directory in ("client", "tools", "shared"):
        for path in (root / directory).rglob("*.c"):
            if "tests" in path.parts or "unittest" in path.name:
                continue
            if migrate(path, path.read_text())[1]:
                failures.append(f"{path.relative_to(root)}: raw complete stderr diagnostic")
    return failures


def _is_raw_stderr_print(node):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id != "print":
        return False
    return any(
        keyword.arg == "file"
        and isinstance(keyword.value, ast.Attribute)
        and isinstance(keyword.value.value, ast.Name)
        and keyword.value.value.id == "sys"
        and keyword.value.attr == "stderr"
        for keyword in node.keywords
    )


def _python_violations(root):
    failures = []
    for directory in ("tools", "utils"):
        for path in (root / directory).rglob("*.py"):
            if "refactor" in path.parts or path.name == "logging_support.py":
                continue
            failures.extend(_python_file_violations(path, root))
    return failures


def _python_file_violations(path, root):
    failures = []
    for node in ast.walk(ast.parse(path.read_text())):
        if _is_raw_stderr_print(node):
            failures.append(
                f"{path.relative_to(root)}:{node.lineno}: raw stderr diagnostic")
    return failures


def violations(root=ROOT):
    """Find bypasses without rewriting source or treating UI as diagnostics."""
    return [
        *_server_violations(root),
        *_native_violations(root),
        *_python_violations(root),
    ]


def main():
    failures = violations()
    for failure in failures:
        diagnostic("ERROR", "tools/ci/check_logging_template.py", "main", failure)
    if not failures:
        print("logging template: OK (server, native clients/tools, Python tools)")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())

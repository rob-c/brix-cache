"""Keep the public examples complete, self-contained, and safely configured."""

import ast
import sys
import sysconfig
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _modules():
    return sorted(EXAMPLES.glob("test_*.py"))


def _stdlib_names():
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return set(names)
    root = Path(sysconfig.get_paths()["stdlib"])
    return set(sys.builtin_module_names) | {
        path.stem if path.is_file() else path.name
        for path in root.iterdir()
        if path.suffix == ".py" or path.is_dir()
    }


def test_example_catalogue_contains_exactly_twenty_compilable_tests():
    names = [name for path in _modules() for name in _test_names(path)]
    numbers = [int(name.split("_", 2)[1]) for name in names]
    assert (len(names), numbers) == (20, list(range(1, 21)))


def test_examples_import_only_stdlib_pytest_and_brixtest():
    allowed = {"brixtest", "pytest"} | _stdlib_names()
    for path in _modules():
        _assert_safe_example(path, allowed)


def _test_names(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    return [
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]


def _assert_safe_example(path, allowed):
    tree = ast.parse(path.read_text(), filename=str(path))
    imports = [name for node in ast.walk(tree) for name in _import_roots(node)]
    assert (set(imports) <= allowed, "../" not in path.read_text()) == (True, True), (
        path, imports,
    )


def _import_roots(node):
    if isinstance(node, ast.Import):
        return [item.name.split(".")[0] for item in node.names]
    if isinstance(node, ast.ImportFrom) and node.module:
        return [node.module.split(".")[0]]
    return []


def test_nginx_example_is_loopback_dynamic_and_unprivileged():
    template = (EXAMPLES / "configs" / "nginx.conf.in").read_text()
    assert "listen {host}:{port};" in template
    assert "root {artifact_nginx_page_dir};" in template
    assert "daemon off;" in template
    assert "listen 80" not in template
    assert "user root" not in template

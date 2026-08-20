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
    names = []
    for path in _modules():
        tree = ast.parse(path.read_text(), filename=str(path))
        names.extend(
            node.name for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        )
    assert len(names) == 20
    assert [int(name.split("_", 2)[1]) for name in names] == list(range(1, 21))


def test_examples_import_only_stdlib_pytest_and_brixtest():
    allowed = {"brixtest", "pytest"} | _stdlib_names()
    for path in _modules():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports = [item.name.split(".")[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports = [node.module.split(".")[0]]
            else:
                continue
            assert all(name in allowed for name in imports), (path, imports)
        assert "../" not in path.read_text()


def test_nginx_example_is_loopback_dynamic_and_unprivileged():
    template = (EXAMPLES / "configs" / "nginx.conf.in").read_text()
    assert "listen {host}:{port};" in template
    assert "root {artifact_nginx_page_dir};" in template
    assert "daemon off;" in template
    assert "listen 80" not in template
    assert "user root" not in template

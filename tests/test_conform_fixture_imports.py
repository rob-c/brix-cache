"""HTTP semantic fixtures import independently of pytest's module naming."""

from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("first", [
    "test_xrd_conform_http_semantics",
    "xrd_conform_http_semantics_runtime",
    "alternate_pytest_module_name",
])
def test_semantic_fixture_import_order_is_acyclic(first):
    """A collected alias or runtime-first import cannot re-enter the facade."""
    script = """
import importlib
import importlib.util
import sys
from pathlib import Path
name = sys.argv[1]
if name == 'alternate_pytest_module_name':
    path = Path('tests/test_xrd_conform_http_semantics.py').resolve()
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
else:
    module = importlib.import_module(name)
runtime = importlib.import_module('xrd_conform_http_semantics_runtime')
facade = importlib.import_module('test_xrd_conform_http_semantics')
assert module.SemanticOrigin is runtime.SemanticOrigin is facade.SemanticOrigin
assert module.NamespaceRoot is runtime.NamespaceRoot is facade.NamespaceRoot
assert callable(facade._run) and callable(facade._run_cross_plane)
"""
    result = subprocess.run([sys.executable, "-c", script, first],
                            cwd=Path(__file__).resolve().parents[1],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr

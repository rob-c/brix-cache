"""TS-2 harness extraction: one arbiter, one tracer, an undimmed gate.

Triad for the conftest-constellation absorption (testsuite-modernization-plan
§11 TS-2): the sentinel/fixture names every consumer sees are the SAME module
objects from brix_suite.harness (single-instance — a by-path re-execution of
conftest.py shares them instead of duplicating them); re-executing the conftest
source can no longer stack a second os.kill/Popen wrapper (the pre-TS-2
double-wrap hazard); and the server-declaration gate still refuses a test that
uses a fleet server it does not declare — the move cannot have silently
disconnected the security check.

Plus the §10.2 shim proof: ``conftest_mu`` and ``brix_suite.harness_ext`` are
one module in sys.modules regardless of import order.
"""

import importlib.util
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

_TESTS = Path(__file__).resolve().parent
_REPO = _TESTS.parent


def _load_conftest_by_path(name):
    """Execute tests/conftest.py as a fresh module, the pinning suite's way."""
    spec = importlib.util.spec_from_file_location(name, _TESTS / "conftest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- success: single-instance identity across every import path --------------


def test_conftest_reexports_are_the_harness_module_objects():
    """A by-path duplicate of conftest.py binds the very same sentinel, tracer
    and fixture objects as the packaged modules — one arbiter, one state dict,
    one fixture surface, however the code is reached."""
    from brix_suite.harness import fixtures, kill_tracer, sentinel

    dup = _load_conftest_by_path("ts2_conftest_identity_probe")

    for name in ("_capture_fleet_baseline", "_verify_fleet_conservation",
                 "_require_fleet_startup_stability", "_start_sentinel_watchdog",
                 "_stop_sentinel_watchdog", "_check_server_reachable",
                 "pytest_runtest_setup", "pytest_runtest_teardown"):
        assert getattr(dup, name) is getattr(sentinel, name), name
    # mutable sentinel state is shared by identity, not copied
    assert dup._sentinel is sentinel._sentinel
    assert dup._sentinel_watchdog is sentinel._sentinel_watchdog
    assert dup._CURRENT_NODEID is kill_tracer._CURRENT_NODEID
    for name in ("registry", "registry_server", "lifecycle", "command_runner",
                 "matrix_node", "test_env", "ref_xrootd", "ref_brix_gsi",
                 "ref_brix_gsi_shared", "pytest_generate_tests"):
        assert getattr(dup, name) is getattr(fixtures, name), name
    # the fixture objects still carry their pytest registration, so collection
    # from the conftest namespace keeps finding them (pytest < 8.4 tags the
    # function; 8.4+ replaces it with a _pytest.fixtures wrapper object)
    assert (hasattr(fixtures.test_env, "_pytestfixturefunction")
            or type(fixtures.test_env).__module__.startswith("_pytest"))


@pytest.mark.parametrize("first", ["conftest_mu", "brix_suite.harness_ext"])
def test_conftest_mu_shim_is_one_module_either_import_order(first):
    """§10.2 alias shim: both names resolve to one module object, whichever is
    imported first (subprocess so each order starts from a clean sys.modules)."""
    second = ("brix_suite.harness_ext"
              if first == "conftest_mu" else "conftest_mu")
    code = (
        f"import {first}\n"
        f"import {second}\n"
        "import sys\n"
        "a = sys.modules['conftest_mu']\n"
        "b = sys.modules['brix_suite.harness_ext']\n"
        "assert a is b, 'two module objects for one canonical module'\n"
        "assert hasattr(a, 'mu_fleet') and hasattr(a, 'cast')\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_TESTS), str(_REPO / "brixtest" / "src")])
    proc = subprocess.run([sys.executable, "-c", code], env=env,
                          capture_output=True, text=True, cwd=str(_REPO))
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --- error: re-executing the conftest source must not stack wrappers ---------


def test_double_conftest_execution_does_not_stack_kill_wrappers():
    """Before TS-2 every by-path execution of conftest.py re-ran the inline
    tracer install, wrapping os.kill/Popen once more each time.  The tracer now
    installs at first import of brix_suite.harness.kill_tracer, so a second
    execution of the conftest source leaves the wrappers untouched."""
    code = (
        "import importlib.util, os, subprocess, sys\n"
        "def load(name):\n"
        "    spec = importlib.util.spec_from_file_location(\n"
        "        name, 'tests/conftest.py')\n"
        "    m = importlib.util.module_from_spec(spec)\n"
        "    spec.loader.exec_module(m)\n"
        "    return m\n"
        "load('ts2_exec_one')\n"
        "kill_1, popen_1 = os.kill, subprocess.Popen\n"
        "assert kill_1.__name__ == '_kill', 'tracer not installed on first exec'\n"
        "assert popen_1.__name__ == '_TracingPopen'\n"
        "load('ts2_exec_two')\n"
        "assert os.kill is kill_1, 'second conftest exec stacked another os.kill wrapper'\n"
        "assert subprocess.Popen is popen_1, 'second conftest exec stacked another Popen wrapper'\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_TESTS)
    env["BRIX_FLEET_SENTINEL"] = "1"
    env.pop("TEST_SERVER_HOST", None)
    proc = subprocess.run([sys.executable, "-c", code], env=env,
                          capture_output=True, text=True, cwd=str(_REPO))
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --- security-negative: the declaration gate survived the extraction ---------


class _GateItem:
    """The minimal item surface _declaration_violations consumes."""

    cls = None

    def __init__(self, fspath, name, markers=()):
        self.fspath = fspath
        self.name = name
        self.originalname = name
        self.nodeid = f"{os.path.basename(str(fspath))}::{name}"
        self._markers = list(markers)

    def iter_markers(self, marker_name):
        return [m for m in self._markers if m.name == marker_name]


def test_declaration_gate_still_refuses_undeclared_server_use(tmp_path):
    """A test that references a dedicated fleet server's port constant without
    @pytest.mark.registry_server(...) still aborts collection after TS-2 — and
    the same test WITH the marker passes, so the gate's verdict (not merely its
    ability to fail) survived the move."""
    import fleet_declares
    import fleet_ports

    dup = _load_conftest_by_path("ts2_conftest_gate_probe")

    ded_spec = next(
        s for s in sorted(fleet_ports.CONST_TO_SPEC.values())
        if s not in fleet_declares.backbone_specs()
    )
    ded_const = next(
        c for c, s in sorted(fleet_ports.CONST_TO_SPEC.items()) if s == ded_spec
    )
    mod = tmp_path / "test_ts2_gate_probe.py"
    mod.write_text(
        f"from settings import {ded_const}\n"
        "def test_uses_server():\n"
        f"    connect({ded_const})\n"
    )

    undeclared = _GateItem(str(mod), "test_uses_server")
    with pytest.raises(pytest.UsageError, match=ded_spec):
        dup._enforce_server_declarations(None, [undeclared])

    declared = _GateItem(
        str(mod), "test_uses_server",
        markers=[types.SimpleNamespace(name="registry_server",
                                       args=(ded_spec,))])
    dup._enforce_server_declarations(None, [declared])  # must not raise

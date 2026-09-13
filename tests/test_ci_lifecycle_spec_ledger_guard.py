"""Guard #14 (`check_lifecycle_spec_ledger.py`) — does it actually fire?

Race-hunt run 34 halted 9,133 tests in on ``RuntimeError: lifecycle spec
'lc-p115-cms-space-mgr' has no fixed port``: a new suite started its manager
through a helpers-module wrapper whose ``name=`` was the caller's second
argument, and the name had no row on the lifecycle ledger.  ``register`` only
looks the name up at the first start, so ``--collect-only`` was green and the
fleet found out 22 minutes in.  ``test_fleet_ports.py`` proves the ledger
consistent with itself; nothing proved its consumers consistent with it.

  success       — an inline spec with a row passes; ``port=`` is the harness's
                  own exemption; a spec constructed but never started is not
                  the guard's business; the real tree is green;
  error         — the run-34 shape: a literal through a helpers-module wrapper
                  -> exit 1 naming the caller line, the name and the wrapper;
                  the same inline, bound-then-registered, by keyword, and two
                  wrappers deep;
  security-neg  — a wrapper whose second parameter is a *reason* with the name
                  fixed inside (audit15f's shape) does not turn its callers'
                  strings into names; a dynamic name is left alone rather than
                  guessed; a start inside ``pytest.raises`` is a negative, not
                  a finding; the guard never writes to the tree it scans.

Every case builds its own scratch tree and points the guard at it with
``--root``; the ledger is always the real tree's, so the one on-ledger name
these fixtures use is read from it rather than hard-coded.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
GUARD = TESTS.parent / "tools" / "ci" / "check_lifecycle_spec_ledger.py"

sys.path.insert(0, str(TESTS))
import fleet_lifecycle_ports as _ledger  # noqa: E402

#: A name the real ledger resolves -- whichever row comes first.
ON_LEDGER = next(n for n in _ledger.LIFECYCLE_SHARED_PORTS
                 if _ledger.lifecycle_ports_for(n)[0] is not None)
OFF_LEDGER = "lc-scratch-nobody-added-this-mgr"

_HELPERS = '''"""Starts a suite's manager; the name is the caller's (run-34 shape)."""
from server_registry import NginxInstanceSpec


def _mgr(lifecycle, name, extra="", reason=""):
    ep = lifecycle.start(NginxInstanceSpec(
        name=name, template="mgr.conf", protocol="root", readiness="tcp",
        template_values={"EXTRA": extra}, reason=reason))
    return ep.port
'''

_CALLER = f'''from _thing_helpers import _mgr

MGR = "{OFF_LEDGER}"


def test_x(lifecycle):
    assert _mgr(lifecycle, MGR, "brix_thing on;", "why")
'''


def _run(root):
    return subprocess.run([sys.executable, str(GUARD), "--root", str(root)],
                          capture_output=True, text=True, timeout=120)


def _tree(root, caller, helpers=_HELPERS):
    (root / "_thing_helpers.py").write_text(helpers)
    (root / "test_new.py").write_text(caller)
    return root


def _inline(name, extra=""):
    return ('from server_registry import NginxInstanceSpec\n\n\n'
            'def test_x(lifecycle):\n'
            f'    lifecycle.start(NginxInstanceSpec(name={name}, template="t.conf"{extra}))\n')


def _snapshot(root):
    return {p: p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# ---------------------------------------------------------------------------
# success


def test_an_inline_spec_with_a_ledger_row_passes(tmp_path):
    proc = _run(_tree(tmp_path, _inline(f'"{ON_LEDGER}"')))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 spec name(s) judged" in proc.stdout


def test_an_explicit_port_is_the_harness_own_exemption(tmp_path):
    """A parse-only spec passes SHARED_PARSE_PLACEHOLDER_PORT and needs no row."""
    proc = _run(_tree(tmp_path, _inline(f'"{OFF_LEDGER}"', ", port=PLACEHOLDER")))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0 spec name(s) judged" in proc.stdout


def test_a_spec_constructed_but_never_started_is_not_judged(tmp_path):
    """Registry unit tests build specs to compare and to probe endpoint_for."""
    caller = ('from server_registry import NginxInstanceSpec, endpoint_for\n\n\n'
              'def test_x():\n'
              f'    spec = NginxInstanceSpec(name="{OFF_LEDGER}", template="t.conf")\n'
              '    assert endpoint_for(spec)\n')
    proc = _run(_tree(tmp_path, caller))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0 spec name(s) judged" in proc.stdout


@pytest.mark.timeout(180)
def test_the_real_tree_is_green():
    """The guard's own subject, so a regression here is not mistaken for setup."""
    proc = _run(TESTS)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# error — the guard has to fail, or it is decoration


def test_a_literal_through_a_helpers_wrapper_fails(tmp_path):
    """Exactly the run-34 halt: MGR reaches name= through _mgr's second slot."""
    proc = _run(_tree(tmp_path, _CALLER))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"test_new.py:7 spec '{OFF_LEDGER}' via _mgr() in _thing_helpers.py" in proc.stdout
    assert "fleet_ports_shared_phase5" in proc.stdout


def test_an_inline_spec_without_a_row_fails(tmp_path):
    proc = _run(_tree(tmp_path, _inline(f'"{OFF_LEDGER}"')))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"test_new.py:5 spec '{OFF_LEDGER}'" in proc.stdout


def test_a_spec_bound_then_registered_fails(tmp_path):
    """harness = LifecycleHarness(); spec = NginxInstanceSpec(...); harness.register(spec)."""
    caller = ('from server_registry import NginxInstanceSpec\n'
              'from server_launcher import LifecycleHarness\n\n\n'
              'def test_x():\n'
              '    harness = LifecycleHarness()\n'
              f'    spec = NginxInstanceSpec(name="{OFF_LEDGER}", template="t.conf")\n'
              '    unique = harness.register(spec)\n')
    proc = _run(_tree(tmp_path, caller))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"spec '{OFF_LEDGER}'" in proc.stdout


def test_a_keyword_argument_through_the_wrapper_fails(tmp_path):
    caller = _CALLER.replace('_mgr(lifecycle, MGR, "brix_thing on;", "why")',
                             '_mgr(lifecycle, name=MGR, extra="brix_thing on;")')
    assert "name=MGR" in caller
    proc = _run(_tree(tmp_path, caller))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"spec '{OFF_LEDGER}' via _mgr()" in proc.stdout


def test_a_wrapper_of_a_wrapper_is_followed(tmp_path):
    """A suite-local helper that forwards its own `name` into _mgr's slot."""
    caller = ('from _thing_helpers import _mgr\n\n\n'
              'def _node(lifecycle, name, on):\n'
              '    return _mgr(lifecycle, name, "on;" if on else "")\n\n\n'
              'def test_x(lifecycle):\n'
              f'    assert _node(lifecycle, "{OFF_LEDGER}", True)\n')
    proc = _run(_tree(tmp_path, caller))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"test_new.py:9 spec '{OFF_LEDGER}' via _node() in test_new.py" in proc.stdout


# ---------------------------------------------------------------------------
# security-neg — never guess, never touch the tree


def test_a_fixed_name_wrapper_does_not_make_reasons_into_names(tmp_path):
    """audit15f's `_mgr(lifecycle, reason, ...)`: the name is fixed inside, so
    the caller's second argument is prose, judged nowhere."""
    helpers = ('from server_registry import NginxInstanceSpec\n\n\n'
               'def _mgr(lifecycle, reason, extra=""):\n'
               '    return lifecycle.start(NginxInstanceSpec(\n'
               f'        name="{ON_LEDGER}", template="t.conf", reason=reason))\n')
    caller = ('from _thing_helpers import _mgr\n\n\n'
              'def test_x(lifecycle):\n'
              '    _mgr(lifecycle, "audit-15f brix_cms_load_weight 100 selection blend")\n')
    proc = _run(_tree(tmp_path, caller, helpers))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 spec name(s) judged, 0 wrapper(s)" in proc.stdout


def test_a_dynamic_name_is_left_alone_not_guessed(tmp_path):
    proc = _run(_tree(tmp_path, _inline('f"lc-{os.getpid()}-mgr"')))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0 spec name(s) judged" in proc.stdout


def test_a_start_inside_pytest_raises_is_a_negative_not_a_finding(tmp_path):
    caller = ('import pytest\n'
              'from server_registry import NginxInstanceSpec\n\n\n'
              'def test_x(lifecycle):\n'
              '    with pytest.raises(RuntimeError, match="has no fixed port"):\n'
              f'        lifecycle.start(NginxInstanceSpec(name="{OFF_LEDGER}", template="t.conf"))\n')
    proc = _run(_tree(tmp_path, caller))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_guard_never_writes_to_the_tree_it_scans(tmp_path):
    root = _tree(tmp_path, _CALLER)
    before = _snapshot(root)
    _run(root)
    assert _snapshot(root) == before

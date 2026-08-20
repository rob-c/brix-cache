"""TS-4 pins: the registry move and its §10.2 shim.

testsuite-modernization-plan.md TS-4 item 1.  The grown body of
``tests/server_registry.py`` moved to ``brix_suite.registry``; the flat
module is now a self-replacement shim.  354 dependent modules and 879
``NginxInstanceSpec`` spellings were NOT touched, and the registry keeps
its whole state in module-level singletons — so the move is safe only if
the two import names resolve to one module object.

  success   — one module object, one ``_SPECS``, the alias is an alias,
              and every baseline name is still exported.
  error     — ``_caller_site`` still names the CALLER.  It used to
              identify this module by the basename ``server_registry.py``,
              which the move silently falsified: the walk would stop on
              the registry's own frame and every duplicate-registration
              error would blame itself instead of the test that clashed.
  security  — a duplicate registration is still refused when the two
              registrations arrive through the two different import
              names.  Two module objects would mean two fleets: a spec
              registered under one name is invisible to a launcher
              importing the other, so a port/data_root collision is
              accepted in silence instead of raising.

The import-identity cases run in a subprocess with a pristine
``sys.modules``, and in both import orders: a shim that only works when
the flat name is imported first is not a shim.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import brix_suite.registry as registry
import server_registry

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "brixtest" / "src"
TESTS = REPO / "tests"
BASELINE = REPO / "docs/refactor/testsuite-shim-baseline.json"


def _probe(code):
    """Run `code` with a pristine interpreter and the suite on the path."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(TESTS), str(SRC)])
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


# --- success ---------------------------------------------------------------


@pytest.mark.parametrize("first,second", [
    ("server_registry", "brix_suite.registry"),
    ("brix_suite.registry", "server_registry"),
])
def test_both_import_names_yield_one_module_in_either_order(first, second):
    code = (
        "import importlib\n"
        "a = importlib.import_module(%r)\n"
        "b = importlib.import_module(%r)\n"
        "print(a is b, a._SPECS is b._SPECS, a._REGISTRATION_SITES is b._REGISTRATION_SITES)\n"
        % (first, second)
    )
    assert _probe(code) == "True True True"


def test_nginx_instance_spec_is_an_alias_not_a_second_dataclass():
    """A subclass would give the two names two ``__eq__`` and two fields."""
    assert server_registry.NginxInstanceSpec is registry.InstanceSpec
    a = registry.InstanceSpec(name="alias-probe", template="t.conf")
    b = server_registry.NginxInstanceSpec(name="alias-probe", template="t.conf")
    assert type(a) is type(b)
    assert a == b
    assert registry.InstanceSpec.__mro__ == (registry.InstanceSpec, object)


def test_every_baselined_registry_name_survives_the_move():
    baseline = json.loads(BASELINE.read_text())
    missing = [name for name in baseline["server_registry"]
               if not hasattr(server_registry, name)]
    assert not missing, "shim dropped %d name(s): %s" % (len(missing), missing)


# --- error -----------------------------------------------------------------


def test_caller_site_names_the_caller_not_the_registry_module():
    """The failure mode the basename check introduced: self-blame."""
    registry.clear_registry()
    try:
        registry.register_nginx(
            registry.InstanceSpec(name="site-probe", template="t.conf"))
        site = registry._REGISTRATION_SITES["site-probe"]
    finally:
        registry.clear_registry()

    assert site.startswith(str(Path(__file__).resolve())), site
    assert "registry.py" not in Path(site.rsplit(":", 1)[0]).name, site


def test_unknown_server_error_still_names_the_missing_spec():
    registry.clear_registry()
    with pytest.raises(KeyError) as excinfo:
        registry.get_server("no-such-server")
    assert "no-such-server" in str(excinfo.value)


# --- security-negative -----------------------------------------------------


def test_duplicate_across_the_two_import_names_is_still_refused():
    """Two module objects would accept this silently — and one spec's
    port and data_root would quietly replace another's."""
    registry.clear_registry()
    try:
        server_registry.register_nginx(
            server_registry.NginxInstanceSpec(
                name="dup-probe", template="t.conf", port=19001))
        with pytest.raises(ValueError) as excinfo:
            registry.register_nginx(
                registry.InstanceSpec(
                    name="dup-probe", template="t.conf", port=19002))
        assert "dup-probe" in str(excinfo.value)
        assert registry.registered_specs()[0].port == 19001
    finally:
        registry.clear_registry()


def test_registering_through_one_name_is_visible_through_the_other():
    registry.clear_registry()
    try:
        server_registry.register_nginx(
            server_registry.NginxInstanceSpec(name="vis-probe", template="t.conf"))
        assert [s.name for s in registry.registered_specs()] == ["vis-probe"]
        registry.clear_registry()
        assert server_registry.registered_specs() == []
    finally:
        registry.clear_registry()

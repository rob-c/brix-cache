"""TS-5 security cluster — the Kerberos realm provisioner move, pinned.

``tests/kdc_helpers.py`` became :mod:`brix_suite.security.kdc`.  Three things
make this move riskier than its 367 lines suggest:

* it is started as a **script by absolute path** from the spec catalogue
  (``[python, tests/kdc_helpers.py, "up"]``), so ``sys.path[0]`` is the script's
  own directory and nothing else is on the path.  The module self-locates to fix
  that, and the self-locate is a ``__file__`` walk — the move-hazard class;
* it holds a cross-process realm lock in module state (``_realm_lock_fd``).  Two
  module objects would mean two locks and two ideas of whether the realm is up,
  which is exactly what the §10.2 shim prevents;
* its whole purpose is *isolation from the host*.  Every krb5 tool is invoked
  with ``KRB5_CONFIG``/``KRB5_KDC_PROFILE`` pointed into ``TEST_ROOT``.  A move
  that lost that would not fail — the tools would fall back to
  ``/etc/krb5.conf`` and the suite would quietly authenticate against whatever
  realm the *host* is joined to.  Nothing in the krb5 tier asserts otherwise, so
  it is asserted here.

``up`` also has an exit-code contract the shell reads: 0 = realm up, 3 = cleanly
skipped (no MIT tooling), anything else = a real error.  A lost entry point
would have exited 0 and the krb5 instance would have been started against a
realm that was never provisioned.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
FLAT = TESTS / "kdc_helpers.py"
ARCHIVE = TESTS / "brix_suite" / "_legacy" / "kdc_helpers_flat.py"
MOVED = TESTS / "brix_suite" / "security" / "kdc.py"


def _probe(code: str, env: dict | None = None):
    e = dict(os.environ, PYTHONPATH=str(TESTS))
    e.update(env or {})
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, env=e, cwd=str(ROOT))
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout.strip()


def _cli(*args, env: dict | None = None):
    """Invoke the flat spelling exactly as the catalogue does: absolute path."""
    e = dict(os.environ)
    e.update(env or {})
    e.pop("PYTHONPATH", None)
    return subprocess.run([sys.executable, str(FLAT), *args],
                          capture_output=True, text=True, env=e, cwd="/")


# ---------------------------------------------------------------------------
# success


def test_flat_spelling_is_the_package_object():
    out = _probe("import kdc_helpers, brix_suite.security.kdc as c; "
                 "print(kdc_helpers is c)")
    assert out == "True"


def test_every_definition_moved_verbatim():
    def bodies(path: Path) -> dict[str, str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        return {
            node.name: hashlib.sha256("".join(
                ast.dump(b, include_attributes=False) for b in node.body).encode()
            ).hexdigest()
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }

    old, new = bodies(ARCHIVE), bodies(MOVED)
    assert old, "archive parsed to nothing — wrong path?"
    assert set(old) == set(new), f"missing={set(old)-set(new)} extra={set(new)-set(old)}"
    assert [n for n in old if old[n] != new[n]] == []
    assert len(old) == 17


def test_the_settings_values_did_not_fork():
    out = _probe("import brix_suite.security.kdc as k, settings; "
                 "print(k.KRB5_REALM == settings.KRB5_REALM, "
                 "k.KRB5_DIR == settings.KRB5_DIR, "
                 "k.KRB5_KEYTAB == settings.KRB5_KEYTAB)")
    assert out == "True True True"


# ---------------------------------------------------------------------------
# error


def test_the_script_entry_point_survived_the_move():
    """The catalogue's invocation, run for real: absolute path, no PYTHONPATH.

    This is the shape that a stranded ``__main__`` guard breaks — and it breaks
    it *silently*, because the process still exits.
    """
    proc = _cli()
    assert proc.returncode == 2, f"expected the usage refusal, got {proc.returncode}"
    assert "usage: kdc_helpers.py" in proc.stderr

    proc = _cli("nonsense")
    assert proc.returncode == 2, "an unknown subcommand must not report success"


def test_the_self_locate_still_lands_on_the_tests_tree():
    """`parents[2]`, asserted at the effect rather than the literal.

    Left at `.parent` the module would put `brix_suite/security` on the path,
    the settings import would fail, and the failure would land at KDC start —
    after the shell had already gated the tier as available.
    """
    out = _probe("import brix_suite.security.kdc as k, sys, json; "
                 "print(json.dumps([p for p in sys.path if p.endswith('tests')]))")
    assert str(TESTS) in json.loads(out)


def test_no_module_reaches_a_name_it_never_binds():
    tree = ast.parse(MOVED.read_text(encoding="utf-8"))
    bound = set(dir(builtins)) | {"__file__", "__name__", "__doc__",
                                  "__package__", "__spec__", "__loader__"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
        elif isinstance(node, ast.alias):
            bound.add((node.asname or node.name).split(".")[0])
    dangling = sorted({n.id for n in ast.walk(tree)
                       if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                       and n.id not in bound})
    assert dangling == [], f"reaches names it never binds: {dangling}"


# ---------------------------------------------------------------------------
# security-negative


def test_every_krb5_tool_is_pinned_to_the_test_realm_not_the_host():
    """The isolation contract, asserted where it is actually enforced.

    `_env()` is the single place the child environment is built.  If it stopped
    overriding `KRB5_CONFIG`, every kinit and kadmin in the tier would read
    `/etc/krb5.conf` — succeeding, against the host's realm, while the tests
    believe they are talking to a throwaway one.
    """
    out = _probe(
        "import brix_suite.security.kdc as k, json; "
        "e = k._env(); "
        "print(json.dumps([e['KRB5_CONFIG'], e['KRB5_KDC_PROFILE'], k.KRB5_DIR]))",
        env={"KRB5_CONFIG": "/etc/krb5.conf", "KRB5_KDC_PROFILE": "/etc/krb5kdc/kdc.conf"},
    )
    conf, profile, krb5_dir = json.loads(out)
    assert conf.startswith(krb5_dir), f"KRB5_CONFIG escaped the test realm: {conf}"
    assert profile.startswith(krb5_dir), f"KRB5_KDC_PROFILE escaped: {profile}"
    assert conf != "/etc/krb5.conf" and profile != "/etc/krb5kdc/kdc.conf"


@pytest.mark.timeout(600)
def test_a_real_provision_writes_a_realm_that_names_only_itself(tmp_path):
    """Provision for real, in an isolated TEST_ROOT — never the session's.

    `provision()` rmtree's `TEST_ROOT/krb5`, so this runs against a private
    tree: reaching the shared realm would wipe a live fleet's KDC.  The daemon
    is deliberately not started — that would bind the ladder's KDC port out from
    under whatever is using it.

    What is checked is what a broken move would break: the generated profile
    must name the test realm and the test KDC, and the exported keytab must
    carry the service principal in that realm and nothing from the host.
    """
    import brix_suite.security.kdc as kdc

    if not kdc.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed")

    out = _probe(
        "import brix_suite.security.kdc as k, json; "
        "k.provision(); "
        "print(json.dumps([k.KRB5_CONF, k.KRB5_KEYTAB, k.KRB5_REALM, "
        "k.KRB5_SERVICE_PRINCIPAL]))",
        env={"TEST_ROOT": str(tmp_path / "lane")},
    )
    conf, keytab, realm, service = json.loads(out.splitlines()[-1])
    assert Path(conf).is_relative_to(tmp_path), "the provision escaped its lane"

    text = Path(conf).read_text(encoding="utf-8")
    assert f"default_realm = {realm}" in text
    assert "dns_lookup_kdc = false" in text, "DNS realm discovery would reach the site KDC"

    klist = subprocess.run([kdc._find_tool("klist") or "klist", "-k", keytab],
                           capture_output=True, text=True)
    assert klist.returncode == 0, klist.stderr
    principals = {ln.split()[-1] for ln in klist.stdout.splitlines()
                  if "@" in ln and not ln.startswith("Keytab")}
    assert service in principals, f"service principal missing: {principals}"
    assert all(p.endswith(f"@{realm}") for p in principals), \
        f"a principal from another realm reached the keytab: {principals}"

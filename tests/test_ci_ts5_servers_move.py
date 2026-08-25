"""TS-5, the servers cluster: the other side of the wire.

Eight modules moved one-to-one out of ``tests/lib/`` into
:mod:`brix_suite.servers`.  Seven are processes — four started by the spec
catalogue, `ocsp_responder` spawned by path from two OCSP audit suites, and
`fwd_mint_proxy`/`fwd_oidc_server` by path from one ``cmdscripts`` driver —
and ``tokenconf`` is the WLCG conformance library twenty-five suites import.

Three properties decided what is tested here.

1. **These are started, not imported.**  A stub that no longer *runs* is not
   an ImportError anywhere; it is a fleet instance whose readiness probe times
   out, three levels away from the change that caused it.  So the moved stubs
   are started for real — under ``-m`` (the new spelling) and by path (the old
   one) — and asked for their wire contract.
2. **Five of them self-located.**  Each opened with
   ``sys.path.insert(0, dirname(dirname(__file__)))`` purely to reach
   ``settings``; two parents from ``tests/lib/`` is ``tests/``, two parents
   from ``brix_suite/servers/`` is ``brix_suite``.  Left in place the line
   would have inserted a directory that exists, so nothing would have raised —
   the import would simply have failed later and differently.  The line is
   gone and ``brix_suite.settings`` is named instead; the scan below proves no
   module reaches a name it never binds.
3. **``-m`` changes what ``sys.path`` starts as.**  A path spawn puts the
   script's own directory first; ``-m`` puts the *current* directory first.
   The four catalogue specs therefore carry ``PYTHONPATH``, and the failure
   without it is asserted rather than assumed — it is loud, and this file is
   where that is written down.

The verbatim-move check is an AST body hash against ``brix_suite/_legacy/``,
so a body that changed cannot be argued to be the same body.

Ports: every live start leases one from the run's own band via
``ephemeral_port.free_port()`` — never a kernel-random one, since two stubs
landing on one port is exactly the collision isolation exists to prevent.  The
four bare numbers below (``40999``, ``41100``, ``41150``, ``41200``) are
arguments to refusals that exit before any bind, so they are not ports this
file consumes and must not be read as fleet constants.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from settings import HOST
from ts5_ast_checks import (
    binding_problem,
    body_hashes,
    missing_names,
    move_problem,
    server_bindings,
    settings_import_problem,
)

TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parent
SERVERS = TESTS / "brix_suite" / "servers"
LEGACY = TESTS / "brix_suite" / "_legacy"
LIB = TESTS / "lib"

pytestmark = pytest.mark.timeout(180)

#: Every module in the cluster: (name, is it a process?).
MODULES = [
    ("fwd_mint_proxy", True),
    ("fwd_oidc_server", True),
    ("guard_stub_server", True),
    ("introspect_idp_server", True),
    ("mirror_shadow_server", True),
    ("ocsp_responder", True),
    ("static_origin_server", True),
    ("tokenconf", False),
]

#: The four the spec catalogue starts, and the spec name each answers to.
SPEC_STUBS = [
    ("guard-stub", "guard_stub_server"),
    ("static-origin", "static_origin_server"),
    ("mirror-shadow", "mirror_shadow_server"),
    ("introspect-idp", "introspect_idp_server"),
]


_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _bodies(path: pathlib.Path) -> dict:
    """sha256 of every def/class body, by qualified name, position-independent.

    ``include_attributes=False`` is what makes it position-independent: the
    archives keep the self-locate line the moved modules dropped, so every
    line number below it differs by construction.

    Methods are hashed as well as their class, which is redundant — a changed
    method already changes its class's hash — but it is redundancy that names
    the culprit.  ``_Handler`` differing tells you nothing; ``_Handler._reply``
    differing tells you where to look.
    """

    return body_hashes(path)


def _server_move_maps():
    before, after = {}, {}
    for name, _is_process in MODULES:
        old = _bodies(LEGACY / f"{name}_flat.py")
        new = _bodies(SERVERS / f"{name}.py")
        before.update({(name, key): digest for key, digest in old.items()})
        after.update({(name, key): digest for key, digest in new.items()})
    return before, after


def _suite_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(TESTS), str(REPO / "brixtest" / "src"),
         env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env.update(extra or {})
    return env


def _child(code, env_extra=None, timeout=90):
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=timeout, env=_suite_env(env_extra))


def _leased_port():
    """A port from the run's own mock band — never a kernel ephemeral one.

    Two stubs started on the same port is the collision this suite exists to
    keep out of other people's runs (operator ask viii).
    """
    sys.path.insert(0, str(TESTS))
    import ephemeral_port

    return ephemeral_port.free_port()


class _Started:
    """A stub started for real, torn down whatever the test does."""

    def __init__(self, argv, env=None, cwd=None):
        self.proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env or _suite_env(), cwd=cwd)

    def wait_ready(self, port, deadline=15.0):
        end = time.time() + deadline
        while time.time() < end:
            if self.proc.poll() is not None:
                return False
            with socket.socket() as s:
                s.settimeout(0.3)
                if s.connect_ex((HOST, port)) == 0:
                    return True
            time.sleep(0.1)
        return False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)


def _get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.status, resp.read()


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,_proc", MODULES, ids=[m for m, _ in MODULES])
def test_every_flat_spelling_is_the_package_object(name, _proc):
    """``lib.X`` and ``brix_suite.servers.X`` must be ONE module object.

    ``tokenconf`` is the reason this is a rule and not a nicety: its
    ``ensure_conformance_data()`` memoises the provisioned tree in module
    state, and twenty-five suites reach it by the ``lib.`` spelling while the
    package spelling is what the migration writes.  Two objects would mean two
    memos and a second provision nobody asked for.
    """
    out = _child(
        "import importlib\n"
        "a = importlib.import_module('lib.%s')\n"
        "b = importlib.import_module('brix_suite.servers.%s')\n"
        "print(a is b)\n" % (name, name))
    assert out.returncode == 0, out.stdout + out.stderr
    assert out.stdout.strip() == "True"


def test_every_definition_moved_verbatim():
    """45 top-level definitions — 69 counting methods — by body hash.

    The two counts are both pinned because they answer different
    questions: the first is "did a function go missing", the second is
    "did a handler method go missing", and a class whose body was
    replaced wholesale would change neither count on its own — which is
    what the hashes are for.
    """
    before, after = _server_move_maps()
    problem = move_problem(before, after, expected_shape=(69, 45))
    assert problem is None, problem


def test_a_moved_stub_serves_its_contract_under_the_module_spelling():
    """``python -m brix_suite.servers.guard_stub_server`` really serves.

    This is the spelling the catalogue now uses, so it is the one that has to
    be shown working — not inferred from the module importing cleanly.
    """
    port = _leased_port()
    argv = [sys.executable, "-m", "brix_suite.servers.guard_stub_server", str(port)]
    with _Started(argv) as stub:
        assert stub.wait_ready(port), stub.proc.stdout.read()
        status, body = _get("http://%s:%d/anything" % (HOST, port))
        assert (status, body) == (200, b"stub-ok\n")
        _, raw = _get("http://%s:%d/__introspect" % (HOST, port))
        assert json.loads(raw)["hits"] == 1


def test_the_old_path_spelling_still_runs_as_a_script():
    """``python3 tests/lib/static_origin_server.py`` is guard #11's property.

    Two ``cmdscripts`` drivers and every operator runbook still name these
    paths.  The shim's ``__main__`` block is what keeps them true, and it has
    to run *before* the ``sys.modules`` self-replacement.
    """
    port = _leased_port()
    argv = [sys.executable, str(LIB / "static_origin_server.py"), str(port)]
    with _Started(argv) as stub:
        assert stub.wait_ready(port), stub.proc.stdout.read()
        status, body = _get("http://%s:%d/" % (HOST, port))
        assert status == 200 and b"ORIGIN-OK" in body


def test_the_catalogue_starts_the_four_stubs_as_modules():
    """The specs name ``-m brix_suite.servers.X`` and carry the path it needs."""
    out = _child(
        "import json\n"
        "from brix_suite.catalogue.support import support_specs\n"
        "specs = {s.name: s for s in support_specs()}\n"
        "print(json.dumps({n: [specs[n].template_values['argv'][1:],\n"
        "                      specs[n].env.get('PYTHONPATH', '')]\n"
        "                  for n, _ in %r}))\n" % (SPEC_STUBS,))
    assert out.returncode == 0, out.stdout + out.stderr
    seen = json.loads(out.stdout)
    for spec_name, module in SPEC_STUBS:
        argv_tail, pypath = seen[spec_name]
        assert argv_tail == ["-m", "brix_suite.servers.%s" % module], spec_name
        assert str(TESTS) in pypath.split(os.pathsep), spec_name


def test_no_module_reaches_a_name_it_never_binds():
    """The static scan that caught the cross-shard NameErrors in TS-5.

    Five modules lost a ``sys.path`` line and, with it, the last use of an
    ``import os`` (or ``import sys``).  Dropping the wrong one is a NameError
    the moment the stub is started, which is exactly when nobody is watching.
    """
    problems = missing_names(sorted(SERVERS.glob("*.py")))
    assert not problems, problems


def test_the_moved_modules_name_the_package_settings():
    """The self-locate is gone, so the import has to be the dotted one."""
    problem = settings_import_problem(
        sorted(SERVERS.glob("*.py")), "brix_suite.settings"
    )
    assert problem is None, problem


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_a_module_spawn_without_the_path_fails_loudly():
    """Why ``_module_env`` exists, demonstrated instead of asserted.

    ``-m`` resolves against the current directory, so a spec that forgot
    ``PYTHONPATH`` gets a child that dies before it binds.  That is the good
    case — it is loud.  The bad case would be a spelling that starts and
    serves the wrong thing, which is why the spec is pinned above.
    """
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-m", "brix_suite.servers.guard_stub_server"],
        capture_output=True, text=True, timeout=60, cwd="/", env=env)
    assert proc.returncode != 0
    assert "No module named" in proc.stderr


def test_a_stub_asked_for_a_taken_port_exits_nonzero():
    """A bind clash is a start failure with a reason, not a silent no-op."""
    port = _leased_port()
    holder = socket.socket()
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind((HOST, port))
    holder.listen(1)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "brix_suite.servers.static_origin_server",
             str(port)],
            capture_output=True, text=True, timeout=60, env=_suite_env())
        assert proc.returncode != 0
        assert "Address already in use" in (proc.stderr + proc.stdout)
    finally:
        holder.close()


def test_guard_eleven_finds_a_stack_head_inside_a_package_directory():
    """These eight shims are the first that do not live at the top of tests/.

    The head resolver looked only at ``tests/<name>.py``, so every archive in
    this cluster read as a CLI with nowhere to live — a red on eight files
    that were correct.  It asks the tree now, and this pins the answer for the
    real archives rather than a scratch tree.
    """
    sys.path.insert(0, str(REPO / "tools" / "ci"))
    import check_shim_entrypoints as guard

    for name, is_proc in MODULES:
        if not is_proc:
            continue
        head = guard._stack_head(name, TESTS)
        assert head == LIB / ("%s.py" % name), (name, head)
        assert head.is_file()


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

def test_no_moved_stub_binds_a_wildcard_address():
    """A stub is a lane's private counterpart, never a host-wide listener.

    ``0.0.0.0`` or ``""`` here would put every concurrent lane's traffic —
    and anything else on the network — into one stub's hit counter, which is
    the state several of these suites assert on.
    """
    bindings = server_bindings(sorted(SERVERS.glob("*.py")))
    allowed = {"127.0.0.1", "BIND_HOST", "bind", "args"}  # net-literal-allow: the allowed-bindings model this test asserts, not a dial target
    problem = binding_problem(bindings, allowed)
    assert problem is None, problem


def test_the_designed_base_refuses_to_bind_outside_its_lane():
    """The promoted security-negative for this cluster (F12).

    The seven grown stubs keep their behaviour verbatim — suites read their
    exact wire responses — so the refusal lives in
    :class:`brixtest.stubs.StubServer`, which is what the next stub is written
    on.  Refusal is exit 2 with one line, so F3's StartError carries the
    reason as its log tail.
    """
    out = _child(
        "from brixtest.stubs.origin import OriginStub\n"
        "raise SystemExit(OriginStub.main())\n",
        env_extra={"BRIXTEST_PORT": "40999", "BRIXTEST_PORT_BASE": "41100",
                   "BRIXTEST_PORT_SPAN": "100"})
    assert out.returncode == 2, out.stdout + out.stderr
    assert "outside the lane's range" in out.stdout


def test_the_designed_base_refuses_a_non_loopback_bind():
    """No stub becomes a bare listener another lane — or another host — trips over."""
    out = _child(
        "from brixtest.stubs.origin import OriginStub\n"
        "raise SystemExit(OriginStub.main())\n",
        env_extra={"BRIXTEST_PORT": "41150",
                   "BRIXTEST_BIND": "0.0.0.0"})  # net-literal-allow: the non-loopback bind under refusal
    assert out.returncode == 2, out.stdout + out.stderr
    assert "not loopback" in out.stdout


def test_the_ocsp_responder_still_refuses_to_start_without_a_signer():
    """Its whole purpose is signing verdicts; no signer is a refusal, not a default.

    A responder that started unsigned would answer revocation queries the
    suites treat as authoritative, and every revocation test would pass on a
    reply nothing vouched for.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "brix_suite.servers.ocsp_responder",
         "--port", "41200"],
        capture_output=True, text=True, timeout=60, env=_suite_env())
    assert proc.returncode != 0
    assert "signer-cert" in (proc.stderr + proc.stdout)

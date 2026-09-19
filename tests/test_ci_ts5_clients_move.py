"""TS-5, the clients cluster: the drivers the suite points at a fleet.

Six flat modules moved.  Five are ordinary relocations; the sixth is the
out-of-process XrdCl isolation layer, which is the most dangerous thing in this
phase to move and the reason the file is this long.

* ``_xrdcl_proxy.py`` + ``_xrdcl_proxy_part2.py`` → :mod:`brix_suite.clients.xrdcl`
  (``worker_link`` / ``results`` / ``proxies``)
* ``_xrdcl_worker.py`` → :mod:`brix_suite.clients.xrdcl.worker`
* ``guard_http_lib.py`` → :mod:`brix_suite.clients.http`
* ``gridftp_client_env.py`` → :mod:`brix_suite.clients.gridftp`
* ``cli_pty.py`` → **core**, :mod:`brixtest.clients.pty` (§7.2 promotion)

Three properties decided the shape of these tests.

1. **The worker is a script the package must be able to find.**  The proxy
   starts it by absolute path, derived in the grown module from ``__file__``.
   Move the body and get that path wrong and nothing raises: the interpreter
   probe finds no candidate, ``real_bindings_available()`` returns False, and
   nine XrdCl suites SKIP.  Green, forever.  So the path is asserted, and the
   failure mode is *demonstrated* rather than assumed.
2. **The layer is a singleton.**  One worker subprocess, one lock, one atexit
   hook, all module state.  Two module objects would mean two of the first two
   and one of the third — an orphaned pyxrootd child per session.
3. **Splitting a stateful module cannot re-export its state truthfully.**
   ``_worker_singleton`` is rebound by ``_worker()``; a ``from … import`` in
   the facade would have frozen ``None`` there forever while the worker it
   describes came and went.  Guard #3 checks that a name exists, not that it
   still means anything — so the facade serves it through ``__getattr__`` and
   the guard's probe moved from ``vars()`` to ``dir()``.  Both halves are
   pinned below; this is the rule the stateful ``server_registry`` alias will
   need too.

The verbatim-move check is an AST body hash against ``brix_suite/_legacy/``,
so a body that changed cannot be argued to be the same body.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import os
import pathlib
import subprocess
import sys

import pytest

def _check_test_every_definition_moved_verbatim_1(label, new, old):
    extra = sorted(set(new) - set(old) - _ADDED_SINCE_MOVE.get(label, set()))
    assert extra == [], f"{label}: unexplained additions: {extra}"

def _check_test_every_definition_moved_verbatim_2(differing, label):
    assert differing == [], f"{label}: bodies changed during the move: {differing}"

def _undeclared_drift(label, old, new):
    """Archived names whose body changed and that no ledger line explains."""
    declared = _CHANGED_SINCE_MOVE.get(label, set())
    return sorted(k for k in old if old[k] != new[k] and k not in declared)

def _check_test_every_definition_moved_verbatim_3(label, old, new):
    """A ledger line that no longer describes anything is a lie by omission:
    it exempts a name the archive still matches, so a LATER edit to that name
    would land silently under an explanation written for a different change."""
    stale = sorted(k for k in _CHANGED_SINCE_MOVE.get(label, set())
                   if old.get(k) == new.get(k))
    assert stale == [], f"{label}: declared changed but still verbatim: {stale}"


TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parent
CLIENTS = TESTS / "brix_suite" / "clients"
XRDCL = CLIENTS / "xrdcl"
LEGACY = TESTS / "brix_suite" / "_legacy"
CORE_PTY = REPO / "brixtest" / "src" / "brixtest" / "clients" / "pty.py"

pytestmark = pytest.mark.timeout(180)

#: Grown since the move, by group and with the reason.  The archive pins what
#: the MOVE did — nothing lost, nothing quietly rewritten on the way across —
#: not the module's future; an undeclared addition still fails.
_ADDED_SINCE_MOVE = {
    # `_worker_python` used to inline its import probe, including a bare
    # `dict(os.environ)`.  The XRootD/GSI C bindings call putenv() from
    # several threads and can leave a malformed NAME in os.environ for an
    # instant; subprocess then rejects the WHOLE environment with ValueError,
    # the inlined `except` swallowed it as "this interpreter has no
    # bindings", and one unlucky moment disqualified every candidate for the
    # rest of the session — reported as "no Python interpreter with real
    # XRootD bindings found", which names the opposite of the cause.  The
    # probe became its own function so it can sanitize the env the way the
    # fleet launcher does and record WHY each candidate was rejected.
    "xrdcl": {"_probe_bindings"},
}

#: Archived definitions since EDITED, with what changed.  Stricter than an
#: addition: an edit is where a move can be undone quietly.
_CHANGED_SINCE_MOVE = {
    "xrdcl": {
        # Both ends of the same repair as `_probe_bindings` above:
        # `_worker_python` calls the extracted probe instead of inlining it,
        # and `_Worker.__init__` builds the worker's env through
        # `sanitized_env()` and puts the collected probe failures into the
        # error it raises, so the message names the interpreters it tried.
        "_Worker", "_worker_python",
    },
}

#: (flat spelling, canonical dotted name) — the worker is deliberately absent:
#: importing it pulls the real pyxrootd bindings into whichever interpreter
#: does it, which is the one thing this whole layer exists to prevent.  It is
#: checked in a child process instead.
SPELLINGS = [
    ("_xrdcl_proxy", "brix_suite.clients.xrdcl"),
    ("_xrdcl_proxy_part2", "brix_suite.clients.xrdcl"),
    ("guard_http_lib", "brix_suite.clients.http"),
    ("gridftp_client_env", "brix_suite.clients.gridftp"),
    ("cli_pty", "brixtest.clients.pty"),
]

#: (label, archives, live modules, canonical definition count)
GROUPS = [
    ("xrdcl", ["_xrdcl_proxy_flat.py", "_xrdcl_proxy_part2_flat.py"],
     [XRDCL / "worker_link.py", XRDCL / "results.py", XRDCL / "proxies.py"], 33),
    ("worker", ["_xrdcl_worker_flat.py"], [XRDCL / "worker.py"], 37),
    ("http", ["guard_http_lib_flat.py"], [CLIENTS / "http.py"], 3),
    ("gridftp", ["gridftp_client_env_flat.py"], [CLIENTS / "gridftp.py"], 1),
    ("pty", ["cli_pty_flat.py"], [CORE_PTY], 13),
]


def _import(dotted):
    __import__(dotted)
    return sys.modules[dotted]


def _bodies(path: pathlib.Path) -> dict:
    """sha256 of each top-level def/class body, position-independent.

    ``include_attributes=False`` is what makes it position-independent: the
    archives carry a prepended header and the split modules carry new
    preludes, so line numbers differ by construction and an unchanged body
    must not read as changed.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            blob = "".join(ast.dump(b, include_attributes=False) for b in node.body)
            out[node.name] = hashlib.sha256(blob.encode()).hexdigest()
    return out


def _child(code, env_extra=None, timeout=90):
    """Run *code* in a fresh interpreter with the suite importable."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(TESTS), str(REPO / "brixtest" / "src"),
         env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=timeout, env=env, cwd=str(TESTS))


# --------------------------------------------------------------------------
# success — the move landed
# --------------------------------------------------------------------------

@pytest.mark.parametrize("flat,dotted", SPELLINGS)
def test_flat_spelling_is_the_package_object(flat, dotted):
    """One module object, not two copies.

    For the proxy this is the difference between one worker subprocess per
    pytest process and two: the singleton, its lock and the atexit hook are all
    module state.
    """
    assert _import(flat) is _import(dotted), f"{flat} and {dotted} are two objects"


#: Files allowed to name the worker: its shim, the package hosting it, and
#: the pre-move archives.  Everything else reaches it through a child process.
_WORKER_NAMES = {"_xrdcl_worker", "brix_suite.clients.xrdcl.worker"}
_WORKER_HOSTS = ("_xrdcl_worker.py", "brix_suite/clients/xrdcl/", "brix_suite/_legacy/")


def _imported_names(node) -> set:
    """Dotted names an import statement binds; empty for any other node."""
    if isinstance(node, ast.Import):
        return {a.name for a in node.names}
    if isinstance(node, ast.ImportFrom) and node.module:
        return {node.module, *(f"{node.module}.{a.name}" for a in node.names)}
    return set()


def _worker_import_lines(path: pathlib.Path) -> list:
    """Line numbers of every import statement in *path* naming the worker."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.lineno for node in ast.walk(tree)
            if _imported_names(node) & _WORKER_NAMES]


def _in_process_worker_imports(root: pathlib.Path) -> list:
    """``(file, line)`` of every import statement naming the worker, any depth."""
    hits = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel.startswith(_WORKER_HOSTS):
            continue
        hits.extend((rel, line) for line in _worker_import_lines(path))
    return hits


def test_no_suite_module_imports_the_worker_in_process():
    """Importing the worker inside pytest breaks the importing process.

    Its prologue strips every ``sys.path`` entry carrying the shadow
    ``XRootD`` package -- ``tests/`` itself -- so every later FIRST import of
    a ``tests/`` module in that xdist worker raises ``ModuleNotFoundError``,
    and then it imports the real bindings into pytest.  Run rhB49 found the
    one such import (``test_maintainability_tools.py``) 170 modules before
    ``_xrdcl_proxy_part2`` was first needed on the same worker.
    """
    assert _in_process_worker_imports(TESTS) == []


def test_the_census_sees_an_import_inside_a_function(tmp_path):
    (tmp_path / "test_x.py").write_text(
        "def test_x():\n    import _xrdcl_worker as w\n    assert w\n")
    (tmp_path / "test_y.py").write_text(
        "from brix_suite.clients.xrdcl.worker import _encode_response\n")
    (tmp_path / "test_z.py").write_text("import brix_suite.clients.xrdcl as x\n")
    legacy = tmp_path / "brix_suite" / "_legacy"
    legacy.mkdir(parents=True)
    (legacy / "old_flat.py").write_text("import _xrdcl_worker\n")
    assert _in_process_worker_imports(tmp_path) == [("test_x.py", 2), ("test_y.py", 1)]


_POLLUTION_PROBE = """
import sys, _xrdcl_worker
print(%r in sys.path)
try:
    import _xrdcl_proxy_part2
except ModuleNotFoundError as exc:
    print(exc.name)
else:
    print("imported")
"""


def test_importing_the_worker_removes_tests_from_sys_path():
    """The reason for the census, demonstrated where it is harmless.

    This is rhB49's failing direction verbatim, in a child: import the worker
    first, then make a fresh top-level import from tests/ in the same
    interpreter.  The second import must fail -- if it ever succeeds the
    strip is gone and the census above has lost its reason.
    """
    proc = _child(_POLLUTION_PROBE % str(TESTS))
    if proc.returncode != 0:
        pytest.skip("no real XRootD bindings on this host: %s"
                    % proc.stderr.strip().splitlines()[-1:])
    assert proc.stdout.split() == ["False", "_xrdcl_proxy_part2"], proc.stdout


def test_the_worker_spelling_resolves_without_importing_it_here():
    """The worker's shim maps to the package — checked out of process.

    ``import _xrdcl_worker`` executes ``from XRootD import client``, i.e. the
    real bindings and their C++ poller threads.  Asserting the shim's identity
    in *this* interpreter would import into pytest exactly what the layer
    exists to keep out.
    """
    proc = _child(
        "import _xrdcl_worker as w, brix_suite.clients.xrdcl.worker as c;"
        "print(w is c)")
    if proc.returncode != 0:
        pytest.skip("no real XRootD bindings on this host: %s"
                    % proc.stderr.strip().splitlines()[-1:])
    assert proc.stdout.strip() == "True", proc.stdout


@pytest.mark.parametrize("label,archives,live,count", GROUPS)
def test_every_definition_moved_verbatim(label, archives, live, count):
    old = {}
    for name in archives:
        old.update(_bodies(LEGACY / name))
    new = {}
    for path in live:
        new.update(_bodies(path))
    def _assert_test_every_definition_moved_verbatim_1():
        assert len(old) == count, f"{label}: archive shape changed: {sorted(old)}"
        assert sorted(set(old) - set(new)) == [], f"{label}: lost definitions"

    _assert_test_every_definition_moved_verbatim_1()
    _check_test_every_definition_moved_verbatim_1(label, new, old)
    _check_test_every_definition_moved_verbatim_2(_undeclared_drift(label, old, new), label)
    _check_test_every_definition_moved_verbatim_3(label, old, new)


def test_the_package_carries_the_worker_script_it_starts():
    """The one piece of data the move could have got wrong in silence."""
    link = _import("brix_suite.clients.xrdcl.worker_link")
    assert os.path.isfile(link.WORKER_SCRIPT), link.WORKER_SCRIPT
    assert link._WORKER == link.WORKER_SCRIPT, "the flat spelling drifted"
    assert pathlib.Path(link.WORKER_SCRIPT).parent == XRDCL


def test_the_duplicated_prelude_became_one_assignment():
    """Both shards carried the same 41-line prelude and re-ran it on load.

    ``_WORKER`` and ``_CALL_TIMEOUT`` were assigned twice per process to the
    same values — harmless only for as long as the two copies agreed.  The
    x509 forge had eighteen such assignments; this is the same defect, smaller.
    """
    def assignments(paths, name):
        return sum(
            isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
            and n.id == name
            for p in paths for n in ast.walk(ast.parse(p.read_text())))

    archives = [LEGACY / "_xrdcl_proxy_flat.py",
                LEGACY / "_xrdcl_proxy_part2_flat.py"]
    live = sorted(XRDCL.glob("*.py"))
    for name in ("_WORKER", "_CALL_TIMEOUT"):
        assert assignments(archives, name) == 2, f"{name}: archive shape changed"
        assert assignments(live, name) == 1, f"{name} is still assigned twice"


def test_the_shadow_package_re_exports_the_moved_proxy():
    """``from XRootD import client`` is how ~9 suites reach this layer.

    The shadow does ``importlib.import_module("_xrdcl_proxy")`` — a flat name,
    resolved at runtime, invisible to any import rewrite.
    """
    from XRootD import client

    canonical = _import("brix_suite.clients.xrdcl")
    for name in ("FileSystem", "File", "CopyProcess", "URL", "XrdClWorkerError"):
        assert getattr(client, name) is getattr(canonical, name), name


def test_the_layer_still_drives_the_real_bindings():
    """End to end, without a fleet: shim → package → worker → pyxrootd.

    A URL parse is answered by the real ``XrdCl::URL`` in the child, so this
    fails if any hop of the chain is broken — including the worker script path,
    the JSON framing and the response decoder.
    """
    proxy = _import("_xrdcl_proxy")
    if not proxy.real_bindings_available():
        pytest.skip("no interpreter with real XRootD bindings on this host")
    from XRootD import client

    url = client.URL("root://host.example:1094//a/b?x=1")
    assert url.is_valid() and url.hostname == "host.example"
    assert url.port == 1094 and url.path == "/a/b"


# --------------------------------------------------------------------------
# error — the failure modes this move could have introduced
# --------------------------------------------------------------------------

def test_a_worker_path_that_does_not_resolve_fails_green(monkeypatch):
    """Why the assertion above exists at all.

    Point the layer at a script that is not there and nothing raises: the probe
    finds no interpreter, ``real_bindings_available()`` goes False, and every
    XrdCl suite reports a skip.  A test that only asserted "the module imports"
    would have passed through this.
    """
    link = _import("brix_suite.clients.xrdcl.worker_link")
    if not link.real_bindings_available():
        pytest.skip("no real bindings here; the contrast has nothing to show")
    monkeypatch.setattr(link, "_WORKER", str(TESTS / "no_such_worker.py"))
    link._worker_python.cache_clear()
    try:
        assert link.real_bindings_available() is False
    finally:
        #: undo by hand: monkeypatch's own teardown runs after this body, and
        #: the memoised probe has to be cleared on the way back out too, or the
        #: next test in the process inherits a cached "no bindings here".
        monkeypatch.undo()
        link._worker_python.cache_clear()
    assert link.real_bindings_available() is True, "probe cache not restored"


def test_the_facade_serves_live_state_rather_than_a_copy():
    """``_worker_singleton`` must read through to the module that owns it."""
    facade = _import("brix_suite.clients.xrdcl")
    link = _import("brix_suite.clients.xrdcl.worker_link")
    assert "_worker_singleton" not in vars(facade), \
        "the facade froze a copy of live state"
    assert "_worker_singleton" in dir(facade)
    sentinel = object()
    saved = link._worker_singleton
    link._worker_singleton = sentinel
    try:
        assert facade._worker_singleton is sentinel
    finally:
        link._worker_singleton = saved


def test_guard_three_would_have_passed_the_frozen_copy():
    """The guard-probe half of the same finding.

    Every baseline name must be reachable, and ``vars()`` — what the guard
    probed before this cluster — cannot see the only spelling that is
    truthful.  So the guard would have rejected the correct facade and
    accepted one that lied.
    """
    import json

    baseline = json.loads(
        (REPO / "docs/refactor/testsuite-shim-baseline.json").read_text())
    facade = _import("brix_suite.clients.xrdcl")
    names = set(baseline["_xrdcl_proxy"])
    assert names - set(dir(facade)) == set()
    assert names - set(vars(facade)) == {"_worker_singleton"}


def test_the_settings_import_survived_the_package_boundary():
    """``guard_http_lib`` names ``brix_suite.settings`` inside the package.

    The flat ``from settings import …`` resolves only with ``tests/`` on
    ``sys.path``, which the package cannot assume.  The rewrite is safe only
    because the two spellings are one module object — assert that, not a pair
    of values: naming a port constant here would make the file a declared
    consumer of the fleet server that owns it.
    """
    http = _import("brix_suite.clients.http")
    assert _import("settings") is _import("brix_suite.settings")
    assert http.HOST == _import("settings").HOST
    reached = {n.module for n in ast.walk(ast.parse(
        (CLIENTS / "http.py").read_text())) if isinstance(n, ast.ImportFrom)}
    assert "brix_suite.settings" in reached and "settings" not in reached


# --------------------------------------------------------------------------
# security-negative
# --------------------------------------------------------------------------

def test_the_worker_never_imports_the_shadow_package(tmp_path):
    """The worker must reach the REAL bindings, whatever is on its path.

    ``tests/`` is on ``PYTHONPATH`` for every suite, and ``tests/XRootD`` is a
    shadow that forwards straight back into the proxy.  A worker that imported
    it would proxy to itself: no bindings, no error, and a layer that answers
    every call with a timeout.  The strip is what prevents that, so it is
    exercised with a decoy the strip must NOT remove.
    """
    real = tmp_path / "real"
    (real / "XRootD").mkdir(parents=True)
    (real / "XRootD" / "__init__.py").write_text(
        "import pathlib\n"
        "class client:\n    pass\n"
        f"pathlib.Path({str(tmp_path / 'picked')!r}).write_text('real')\n")
    proc = _child("import runpy, sys; sys.argv=['worker'];"
                  " runpy.run_path(%r, run_name='__main__')"
                  % str(XRDCL / "worker.py"),
                  {"PYTHONPATH": os.pathsep.join([str(real), str(TESTS)]),
                   "XRDCL_IMPORT_PROBE": "1"})
    assert (tmp_path / "picked").exists(), \
        "the worker did not import the non-shadow XRootD on its path: %s" % proc.stderr


def test_the_worker_refuses_a_path_that_advertises_a_shadow(tmp_path):
    """Same decoy, now carrying ``_SHADOW_MARKER`` — it must be skipped."""
    decoy = tmp_path / "decoy"
    (decoy / "XRootD").mkdir(parents=True)
    (decoy / "XRootD" / "_SHADOW_MARKER").write_text("")
    (decoy / "XRootD" / "__init__.py").write_text(
        "import pathlib\n"
        "class client:\n    pass\n"
        f"pathlib.Path({str(tmp_path / 'picked')!r}).write_text('shadow')\n")
    _child("import runpy, sys; sys.argv=['worker'];"
           " runpy.run_path(%r, run_name='__main__')" % str(XRDCL / "worker.py"),
           {"PYTHONPATH": os.pathsep.join([str(decoy), str(TESTS)]),
            "XRDCL_IMPORT_PROBE": "1"})
    assert not (tmp_path / "picked").exists(), \
        "the worker imported a path that declared itself a shadow"


@pytest.mark.parametrize("euid", [0, 1000])
def test_gsi_env_pins_the_credential_the_caller_chose(monkeypatch, tmp_path, euid):
    """The forged-proxy path is the security case, and it is uid-dependent.

    globus-url-copy honours ``X509_USER_PROXY`` only for a non-root caller; as
    uid 0 it falls back to the host credential.  A security-negative that
    hands this helper a deliberately bad proxy must therefore still be the
    credential that goes on the wire — otherwise the test proves the host cert
    was rejected and nothing about the forgery.
    """
    gridftp = _import("brix_suite.clients.gridftp")
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setenv("X509_USER_PROXY", "/etc/grid-security/hostcert.pem")
    monkeypatch.setenv("X509_USER_CERT", "/etc/grid-security/hostcert.pem")
    monkeypatch.setenv("X509_USER_KEY", "/etc/grid-security/hostkey.pem")
    forged = tmp_path / "forged.pem"
    forged.write_text("")
    env = gridftp.gsi_client_env(tmp_path / "certs", forged)
    assert env["X509_USER_PROXY"] == str(forged)
    assert env["X509_CERT_DIR"] == str(tmp_path / "certs")
    if euid == 0:
        #: uid 0 ignores the proxy variable, so the helper has to overwrite the
        #: host credential the environment came with — or the test would be
        #: measuring how the gateway treats /etc/grid-security/hostcert.pem.
        assert env["X509_USER_CERT"] == env["X509_USER_KEY"] == str(forged)
        assert "/etc/grid-security" not in env["X509_USER_CERT"]
    else:
        #: and it must NOT invent one below root: the proxy already wins, and
        #: rewriting CERT/KEY here would change which credential a non-root
        #: caller presents to every OTHER tool that reads the same env.
        assert env["X509_USER_CERT"] == "/etc/grid-security/hostcert.pem"
        assert env["X509_USER_KEY"] == "/etc/grid-security/hostkey.pem"


def test_core_pty_does_not_shadow_the_stdlib_module_it_uses():
    """``brixtest.clients.pty`` is a sibling of modules that ``import pty``.

    Under absolute imports that is the stdlib every time — but only while this
    directory stays off ``sys.path``, and this package does spawn scripts.
    """
    core = _import("brixtest.clients.pty")
    stdlib = _import("pty")
    assert core is not stdlib
    assert core._pty is stdlib and hasattr(stdlib, "openpty")


def test_core_pty_imports_nothing_from_the_adapter():
    """§7.2's one-way rule, at the file the promotion added."""
    tree = ast.parse(CORE_PTY.read_text(encoding="utf-8"))
    reached = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            reached.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            reached.add(node.module.split(".")[0])
    assert reached & {"brix_suite", "settings", "brixtest"} == set(), reached


def test_run_pipe_hands_the_child_no_terminal_and_no_stdin():
    """``run_pipe`` must close stdin: a CLI that prompts would hang the suite.

    ``run_pty`` is the deliberate opposite — one PTY on all three streams with
    a combined capture (its stderr slot is always empty), and stdin stays open
    until a declared ``input`` is written and closed with EOT.  That is the
    contract ``brixtest/tests/test_pty_transport.py`` pins from the package
    side; this end checks the two runners have not drifted toward each other.
    """
    core = _import("brixtest.clients.pty")
    probe = ("import sys;"
             " sys.stderr.write('%d%d' % (sys.stdout.isatty(), sys.stderr.isatty()));"
             " sys.stdout.write(sys.stdin.read() or 'EOF')")
    rc, out, err = core.run_pipe([sys.executable, "-c", probe], timeout=30)
    assert rc == 0 and out == b"EOF" and err == b"00"
    rc, out, err = core.run_pty([sys.executable, "-c", probe], timeout=30,
                                input="")
    assert rc == 0 and err == b""
    merged = out.replace(b"\r", b"")
    #: stdio buffering makes the interleave order of the two writes
    #: nondeterministic through one PTY; both must be present, nothing else.
    assert b"11" in merged and b"EOF" in merged and len(merged) == 5, out

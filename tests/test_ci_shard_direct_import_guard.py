"""Guard #13 (`check_shard_direct_imports.py`) — does it actually fire?

Race-hunt run 33 halted 9,289 tests in on a NameError raised at fixture setup:
a new suite imported ``pki`` from ``_test_gsi_handshake_helpers_b`` as a
module, but that file is a continuation shard -- ``split_continuation.reexport``
compiles it into ``_test_gsi_handshake_helpers``'s globals, and ``_have`` lives
only there.  Guard #10 censuses ``load``/``load_numbered`` and the inline exec
idiom; the ``reexport`` spelling (~300 modules) had no guard at all, and
nothing forbade importing any shard directly.  The import itself succeeds, so
a collection-only run never sees it.

  success       — pulling a self-sufficient name out of a continuation is fine
                  (three suites take helpers from ``conftest_part*``); a
                  complete module a parent re-exports may be imported whole;
                  the real tree is green;
  error         — the run-33 shape: the name taken reaches a parent-bound
                  name -> exit 1, naming the importer line, what it took, the
                  shard, its parent and the unbound name; the same through a
                  module alias; the ``load`` spelling is censused the same way;
  security-neg  — ask the tree, not the name: a file named like a shard that
                  no parent composes is not the guard's business; a shard that
                  star-imports cannot be proved and is left alone; a §10.2
                  self-replacement shim uses nothing; the guard never writes
                  to the tree it scans.

Every case builds its own scratch tree and points the guard at it with
``--root``.  Damaging the real tree to prove a guard fires would be a worse
bug than the one being guarded against.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

TESTS = pathlib.Path(__file__).resolve().parent
GUARD = TESTS.parent / "tools" / "ci" / "check_shard_direct_imports.py"

_PARENT = '''"""The composing parent: binds _have, then pulls the shard in."""
import shutil


def _have(*tools):
    return all(shutil.which(t) for t in tools)


from split_continuation import reexport as _reexport
_reexport(globals(), "_thing_helpers_b")
'''

_CONTINUATION = '''"""A continuation shard: _have is the parent's, port() is its own."""
BASE = 40000


def port(offset):
    return BASE + offset


def pki():
    assert _have("openssl"), "openssl is required"
    return {"ca": "ca.pem", "port": port(1)}
'''

_SELF_SUFFICIENT = '''"""A complete module a parent happens to re-export."""
import shutil


def pki():
    return {"ca": shutil.which("openssl")}
'''

_TAKES_PKI = 'from _thing_helpers_b import pki  # noqa: F401\n'
_TAKES_PORT = 'from _thing_helpers_b import port  # noqa: F401\n'
_SHIM = ('import sys as _sys\n'
         'import _thing_helpers_b as _canonical\n'
         '_sys.modules[__name__] = _canonical\n')


def _run(root):
    return subprocess.run([sys.executable, str(GUARD), "--root", str(root)],
                          capture_output=True, text=True, timeout=120)


def _write(root, parent, shard, importer):
    (root / "_thing_helpers.py").write_text(parent)
    (root / "_thing_helpers_b.py").write_text(shard)
    (root / "test_new.py").write_text(importer)
    return root


def _snapshot(root):
    return {p: p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# ---------------------------------------------------------------------------
# success


def test_taking_a_self_sufficient_name_from_a_continuation_passes(tmp_path):
    """`port` reaches only BASE, which the shard binds itself."""
    proc = _run(_write(tmp_path, _PARENT, _CONTINUATION, _TAKES_PORT))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 composed shard(s), 1 direct import(s) judged" in proc.stdout


def test_a_self_sufficient_module_may_be_imported_whole(tmp_path):
    """Re-exporting a complete module does not make it a continuation."""
    importer = 'import _thing_helpers_b as h\n\n\ndef test_x():\n    assert h.pki()\n'
    proc = _run(_write(tmp_path, _PARENT, _SELF_SUFFICIENT, importer))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_real_tree_is_green():
    """The guard's own subject, so a regression here is not mistaken for setup."""
    proc = _run(TESTS)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# error — the guard has to fail, or it is decoration


def test_taking_a_name_that_reaches_the_parent_fails(tmp_path):
    """Exactly the run-33 halt: pki's first call is a NameError on _have."""
    proc = _run(_write(tmp_path, _PARENT, _CONTINUATION, _TAKES_PKI))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "test_new.py:1 imports pki from" in proc.stdout
    assert "_thing_helpers_b.py" in proc.stdout
    assert "composed by" in proc.stdout and "_thing_helpers.py" in proc.stdout
    assert "reaches unbound: _have" in proc.stdout


def test_reading_that_name_through_a_module_alias_fails_too(tmp_path):
    """`import shard as h; h.pki()` is the same NameError spelled differently."""
    importer = 'import _thing_helpers_b as h\n\n\ndef test_x():\n    assert h.pki()\n'
    proc = _run(_write(tmp_path, _PARENT, _CONTINUATION, importer))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "imports pki from" in proc.stdout
    assert "reaches unbound: _have" in proc.stdout


def test_the_load_spelling_is_censused_too(tmp_path):
    """Guard #10's census is reused, so `load`-composed parts are covered."""
    (tmp_path / "thing.py").write_text(
        'LIMIT = 3\nfrom split_continuation import load as _load_continuations\n'
        '_load_continuations(globals(), __file__, "thing_part2.py")\n')
    (tmp_path / "thing_part2.py").write_text('def run():\n    return LIMIT\n')
    (tmp_path / "test_new.py").write_text('from thing_part2 import run\n')
    proc = _run(tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "thing_part2.py" in proc.stdout and "LIMIT" in proc.stdout


# ---------------------------------------------------------------------------
# security-neg — ask the tree, not the name; never touch the tree


def test_a_lookalike_no_parent_composes_is_not_flagged(tmp_path):
    """A shard-shaped name with no composing parent is a plain module; its
    free names are somebody else's bug, not a composition one."""
    (tmp_path / "_thing_helpers_b.py").write_text(_CONTINUATION)
    (tmp_path / "test_new.py").write_text(_TAKES_PKI)
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0 composed shard(s)" in proc.stdout


def test_a_star_importing_shard_is_left_alone(tmp_path):
    """`from x import *` may bind anything, so nothing can be proved unbound."""
    shard = 'from shutil import *\n' + _CONTINUATION
    proc = _run(_write(tmp_path, _PARENT, shard, _TAKES_PKI))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_self_replacement_shim_is_plumbing_not_use(tmp_path):
    """A §10.2 shim hands its name to the canonical module and calls nothing,
    which is how tests/load_test_part2.py stands in for its moved body."""
    proc = _run(_write(tmp_path, _PARENT, _CONTINUATION, _SHIM))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_guard_never_writes_to_the_tree_it_scans(tmp_path):
    """A guard that edits what it audits is worse than no guard."""
    root = _write(tmp_path, _PARENT, _CONTINUATION, _TAKES_PKI)
    before = _snapshot(root)
    _run(root)
    assert _snapshot(root) == before

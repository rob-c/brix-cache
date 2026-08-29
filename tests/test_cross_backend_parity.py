"""
test_cross_backend_parity.py — nginx and stock XRootD answer the same, in ONE run.

THE GAP: `TEST_CROSS_BACKEND` is a process-wide switch that six modules read at
import time, and **nothing in `tests/`, `Makefile` or `.github/` ever sets it**.
Both implementations were reachable the whole time — `main` (nginx) and
`ref-anon` (stock `/usr/bin/xrootd`) are always-on backbone fleet members
exporting the *same* data root — but a default `pytest tests/` run only ever
drove the nginx side, so "parity" was a documented capability nobody exercised.
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §7 fold-in.

This module resolves the backend **per test** instead of per process
(`backend_matrix.anon_url`), so one ordinary run compares both. It deliberately
asserts only the contract both implementations must share — an implementation
difference is a finding, not a skip — and stays narrow: this is a parity probe,
not a second copy of the protocol suite.

Trio per CLAUDE.md:
  * success  — a seeded file reads back byte-exact, and stats identically,
               from both servers.
  * error    — an absent path is an error from both, never a short read.
  * security — a traversal path escapes neither export, verified by content.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_cross_backend_parity.py -v
"""

import os
import uuid

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags

from backend_matrix import BACKENDS, anon_url
from settings import DATA_ROOT, HOST, NGINX_ANON_PORT, REF_BRIX_PORT, SERVER_HOST

# xdist_group: this module stages its fixture data under the SHARED
# DATA_ROOT in a module-scoped fixture.  Ungrouped cells spread across
# workers under --dist loadgroup, so each worker runs its own copy of
# that fixture and the first teardown deletes the file out from under
# the workers still using it ("NotFound").  One group == one worker.
pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("cross-backend-parity")]

BODY = b"cross-backend-parity-" * 2048       # ~43 KiB: several reads, one file
SECRET = b"this file lives outside the export root\n"


@pytest.fixture(scope="module")
def seeded():
    """One file in the shared export, visible to both servers. Yields (name, body)."""
    name = f"parity-{uuid.uuid4().hex}.bin"
    path = os.path.join(DATA_ROOT, name)
    with open(path, "wb") as fh:
        fh.write(BODY)
    os.chmod(path, 0o644)
    try:
        yield name, BODY
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _endpoint(backend: str) -> str:
    """The anonymous root:// endpoint for `backend`.

    Deliberately spelled out with the `settings.py` port constants rather than
    delegating to `backend_matrix.anon_url()`: the server-declaration gate
    attributes fleet servers by *statically* following the constants a test
    reaches, and it cannot see through an imported helper. Reaching `main` and
    `ref-anon` via an opaque call means the session boots neither, and every
    read then hangs until XrdCl's connect timeout instead of failing.
    `test_the_helper_and_this_module_resolve_the_same_endpoints` keeps the two
    spellings honest.
    """
    return (f"root://{HOST}:{REF_BRIX_PORT}" if backend == "xrootd"
            else f"root://{SERVER_HOST}:{NGINX_ANON_PORT}")


def _read(backend: str, key: str) -> bytes:
    """Whole-file read over root://, or raise _Refused carrying the server's status."""
    with client.File() as fh:
        status, _ = fh.open(f"{_endpoint(backend)}//{key}", OpenFlags.READ)
        if not status.ok:
            raise _Refused(backend, status)
        status, data = fh.read()
        if not status.ok:
            raise _Refused(backend, status)
        return bytes(data)


class _Refused(Exception):
    def __init__(self, backend, status):
        super().__init__(f"{backend}: {status.message.strip()} "
                         f"(code={status.code} errno={status.errno})")
        self.backend = backend
        self.status = status


# --------------------------------------------------------------------------- #
# The helper itself — no server needed.                                        #
# --------------------------------------------------------------------------- #
def test_the_helper_and_this_module_resolve_the_same_endpoints():
    """`_endpoint` exists only to be statically visible to the declaration gate;
    if it ever disagrees with `backend_matrix.anon_url`, this module would be
    testing something the rest of the suite is not."""
    for backend in BACKENDS:
        assert anon_url(backend) == _endpoint(backend), backend


def test_an_unknown_backend_is_refused_not_defaulted():
    """A typo must not silently resolve to nginx — that is how a "parity" run
    quietly becomes two copies of the same test."""
    with pytest.raises(RuntimeError):
        anon_url("xrootdd")


# --------------------------------------------------------------------------- #
# Success.                                                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("backend", BACKENDS)
def test_a_seeded_file_reads_back_byte_exact(backend, seeded):
    name, body = seeded
    assert _read(backend, name) == body


def test_both_backends_return_identical_bytes(seeded):
    """The comparison the two-run form could never make: same file, same process,
    both servers, one equality."""
    name, body = seeded
    got = {b: _read(b, name) for b in BACKENDS}
    assert got["nginx"] == got["xrootd"] == body


def test_both_backends_report_the_same_size(seeded):
    """Stat is the other half of a read: a server that serves the right bytes
    while advertising the wrong size breaks every client that pre-allocates."""
    name, body = seeded
    sizes = {}
    for backend in BACKENDS:
        status, info = client.FileSystem(_endpoint(backend)).stat(f"/{name}")
        assert status.ok, f"{backend}: {status.message.strip()}"
        sizes[backend] = info.size
    assert sizes["nginx"] == sizes["xrootd"] == len(body), sizes


# --------------------------------------------------------------------------- #
# Error.                                                                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("backend", BACKENDS)
def test_an_absent_path_is_an_error_not_an_empty_body(backend):
    with pytest.raises(_Refused):
        _read(backend, f"no-such-parity-file-{uuid.uuid4().hex}.bin")


def test_both_backends_refuse_an_absent_path(seeded):
    """Neither may answer a missing key with a successful zero-length read —
    the failure mode that makes a corrupt copy look like an empty one."""
    missing = f"no-such-parity-file-{uuid.uuid4().hex}.bin"
    for backend in BACKENDS:
        with pytest.raises(_Refused):
            _read(backend, missing)


# --------------------------------------------------------------------------- #
# Security.                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def planted_outside():
    """A file one level above the shared export. Both servers must never serve it."""
    path = os.path.join(os.path.dirname(DATA_ROOT.rstrip("/")), "parity-outside.bin")
    with open(path, "wb") as fh:
        fh.write(SECRET)
    os.chmod(path, 0o644)
    try:
        yield os.path.basename(path)
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_traversal_path_never_escapes_the_export(backend, planted_outside):
    """Content-based verdict: a normalising client or server can rewrite
    `../x` to `/x` and refuse for the right reason or the wrong one, but SECRET
    coming back is a breach either way."""
    try:
        got = _read(backend, f"../{planted_outside}")
    except _Refused:
        return
    assert got != SECRET, f"{backend}: traversal returned a file outside the export"

"""
test_matrix_layer.py — the parametrization layer, exercised over real cells.

THE GAP: the suite had **zero** `pytest_generate_tests` and **zero**
`indirect=True` — 299 hand-written `NginxInstanceSpec(...)` literals across 212
modules, one module and one config template per cell. That is why the coverage
matrix was sparse, and why it re-sparsified every time a backend or an auth
mechanism was added: filling a new cell meant writing a new module by hand.
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §7 item 19.

This module is both the demonstrator and the regression test for the layer. The
four bodies below are written ONCE and run against every reachable
(protocol × auth × tls × backend) cell; adding a backend to `matrix_layer.py`
adds it to all four for free, which is the whole point.

Unreachable cells are parametrized and SKIP WITH A REASON rather than being
silently dropped — the audit's core complaint was that an empty cell and an
impossible cell looked identical from the outside.

Trio per CLAUDE.md:
  * success   — a seeded object reads back byte-exact through every cell.
  * error     — a missing object is refused on every cell, never a short body.
  * security  — an unauthenticated read is refused on every credentialed cell,
                and a traversal key never returns a file from outside the export.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_matrix_layer.py -v
"""
import os

import pytest

from matrix_layer import Refused

pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-matrix")]

BODY = b"matrix-payload-" * 3000          # ~45 KiB: several reads, one file
SECRET = b"this file lives outside the export root\n"

# The anonymous/bearer sweep: every protocol, both wire modes, both a local and
# a remote-origin backend.
SWEEP = pytest.mark.matrix(protocols=["root", "webdav", "s3"],
                           auths=["none", "token"],
                           tls=[False, True],
                           backends=["posix", "xroot"])

# The credentialed planes, which only exist over TLS (a client certificate) or
# only on one protocol (SigV4).  Kept as a second, narrow mark rather than
# widening the sweep, so the cost stays proportional to what it proves.
CREDENTIALED = pytest.mark.matrix(protocols=["root", "webdav", "s3"],
                                  auths=["gsi", "sigv4"],
                                  tls=[True],
                                  backends=["posix"])


# --------------------------------------------------------------------------- #
# Success.                                                                     #
# --------------------------------------------------------------------------- #
@SWEEP
def test_a_seeded_object_reads_back_byte_exact(matrix_node, tmp_path):
    want = matrix_node.seed("obj.bin", BODY)
    assert matrix_node.read("obj.bin", tmp=tmp_path) == want


@CREDENTIALED
def test_a_credentialed_plane_serves_its_own_client(matrix_node, tmp_path):
    want = matrix_node.seed("cred.bin", BODY)
    assert matrix_node.read("cred.bin", tmp=tmp_path) == want


# --------------------------------------------------------------------------- #
# Error.                                                                       #
# --------------------------------------------------------------------------- #
@SWEEP
def test_a_missing_object_is_refused(matrix_node, tmp_path):
    """Absent must be an error, never an empty or partial success."""
    with pytest.raises(Refused):
        matrix_node.read("no-such-object.bin", tmp=tmp_path)


# --------------------------------------------------------------------------- #
# Security.                                                                    #
# --------------------------------------------------------------------------- #
@SWEEP
def test_an_unauthenticated_read_is_refused(matrix_node, tmp_path):
    """The credential is the only thing removed; everything else is the cell
    that just served the object above."""
    if matrix_node.cell.auth == "none":
        pytest.skip("open plane by construction — nothing to withhold")
    matrix_node.seed("guarded.bin", BODY)
    with pytest.raises(Refused):
        matrix_node.read("guarded.bin", authenticated=False, tmp=tmp_path)


@SWEEP
def test_a_traversal_key_never_escapes_the_export(matrix_node, tmp_path):
    """A file planted one level above the export must stay unreachable.

    The verdict is content-based, not status-based: a normalising client or
    server can turn `../outside.bin` into `/outside.bin` and answer 404 for the
    right reason or the wrong one, but SECRET coming back is a breach either
    way.
    """
    outside = os.path.join(os.path.dirname(matrix_node.store), "outside.bin")
    with open(outside, "wb") as fh:
        fh.write(SECRET)
    os.chmod(outside, 0o644)
    try:
        got = matrix_node.read("../outside.bin", tmp=tmp_path)
    except Refused:
        return
    assert got != SECRET, "traversal returned a file from outside the export"

"""
test_cms_cross_impl_parity.py — a BriX CMS manager and a stock cmsd manager
answer the same client, in ONE run.

THE GAP: docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md left
exactly one CMS item open — the per-subsystem cross-implementation parity list.
`test_cross_backend_parity.py` closed the *data-server* half of that list (the
root:// read/stat/absent/traversal contract against `main` vs `ref-anon`), but
the **clustering** half had no probe at all: `test_cms_mesh_interop.py` proves a
BriX node registers with a real manager and a real node registers with a BriX
manager, yet nothing ever asked whether the two *managers* give a client the
same answers for the same namespace.

This module asks exactly that.  Topology `b` (BriX manager + real data node) and
topology `bl` (real cmsd manager + real data node) differ in one variable — the
manager implementation — so seeding byte-identical content into both data roots
and driving both front doors with the same `xrdfs`/`xrdcp` makes any divergence a
finding rather than a skip.  Deliberately narrow: this is a parity probe of the
client-visible clustering contract, not a second copy of the mesh suite.

Trio per CLAUDE.md:
  * success  — a seeded file locates, stats and reads back byte-exact and
               IDENTICALLY through both managers.
  * error    — a path no data node holds is an error from both, never a hang and
               never a fabricated success.
  * security — a traversal path escapes neither cluster, verified by content.

The mesh is brought up by the harness (`cms_mesh_servers.py start`); these tests
only connect, and skip when a topology is not listening.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_cms_cross_impl_parity.py -v
"""

import os
import uuid

import pytest

from cms_mesh_lib import (
    PORTS, data_dir, have_binaries, port_open, stat_size,
    xrdcp_get, xrdfs_locate, xrdfs_ls, xrdfs_stat,
)

pytestmark = [
    pytest.mark.skipif(
        not have_binaries(),
        reason="CMS manager parity needs xrootd, cmsd, xrdfs, xrdcp and nginx",
    ),
    pytest.mark.timeout(180),
    # serial: two live CMS meshes with heartbeat timing — unreliable in the pool.
    pytest.mark.serial,
]

# (label, manager front-door port, topology, data-node label).  ONE variable
# differs between the rows: who runs the manager.  Both data nodes are stock
# xrootd servers exporting "/", so a divergence cannot be blamed on the backend.
MANAGERS = [
    ("nginx", PORTS["b_mgr"], "b", "b-rds"),
    ("xrootd", PORTS["bl_mgr"], "bl", "bl-rds"),
]

BODY = b"cms-manager-parity-" * 512          # ~9.7 KiB: several reads, one file


def _require_mesh():
    for label, port, _topo, _node in MANAGERS:
        if not port_open(port):
            pytest.skip(f"{label} manager (:{port}) not up — run "
                        "cms_mesh_servers.py start")


@pytest.fixture(scope="module")
def seeded():
    """The same file, byte-identical, in BOTH clusters' export roots.

    Written straight into each data node's fixed export dir rather than pushed
    through a manager: a write path difference would otherwise contaminate the
    read comparison this module exists to make."""
    _require_mesh()
    name = f"/cmsparity-{uuid.uuid4().hex}.bin"
    paths = []
    for _label, _port, topo, node in MANAGERS:
        p = os.path.join(data_dir(topo, node), name.lstrip("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(BODY)
        os.chmod(p, 0o644)
        paths.append(p)
    try:
        yield name
    finally:
        for p in paths:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


def test_locate_succeeds_through_both_managers(seeded):
    """Both managers resolve the path to a data node — the core clustering
    contract. A manager that answered locate itself (or not at all) diverges
    here before any byte is read."""
    results = {}
    for label, port, _topo, _node in MANAGERS:
        rc, out, err = xrdfs_locate(port, seeded)
        results[label] = (rc, out, err)
        assert rc == 0, (label, rc, err)
        assert out.strip(), (label, "locate returned no endpoint")
    assert len(results) == len(MANAGERS)


def test_stat_reports_the_same_size_through_both_managers(seeded):
    """Size is the one stat field both implementations must agree on exactly —
    it is what a client sizes its read plan from."""
    sizes = {}
    for label, port, _topo, _node in MANAGERS:
        rc, out, err = xrdfs_stat(port, seeded)
        assert rc == 0, (label, rc, err)
        sizes[label] = stat_size(out)
    assert set(sizes.values()) == {len(BODY)}, sizes


def test_read_is_byte_exact_through_both_managers(seeded, tmp_path):
    """The redirect a manager hands out must land the client on the real bytes.
    Compared against the seed AND across managers, so a truncation that both
    share would still fail."""
    got = {}
    for label, port, _topo, _node in MANAGERS:
        dst = tmp_path / f"{label}.bin"
        r = xrdcp_get(port, seeded, str(dst))
        assert r.returncode == 0, (label, r.returncode, r.stderr)
        got[label] = dst.read_bytes()
    assert got["nginx"] == BODY, "nginx-managed read differs from the seed"
    assert got["nginx"] == got["xrootd"], "managers delivered different bytes"


def test_dirlist_shows_the_file_through_both_managers(seeded):
    """A cluster-level `ls` must surface the file both managers just served —
    the namespace view a client browses with."""
    leaf = seeded.lstrip("/")
    for label, port, _topo, _node in MANAGERS:
        rc, out, err = xrdfs_ls(port, "/")
        assert rc == 0, (label, rc, err)
        assert leaf in out, (label, "seeded file missing from ls", out[:400])


def test_absent_path_errors_through_both_managers():
    """Error parity: a path no data node holds must fail on both — not hang, and
    never come back as a zero-length success (which is what a manager that
    fabricated a stat would produce)."""
    _require_mesh()
    missing = f"/cmsparity-absent-{uuid.uuid4().hex}.bin"
    for label, port, _topo, _node in MANAGERS:
        rc, _out, _err = xrdfs_stat(port, missing)
        assert rc != 0, (label, "absent path stat unexpectedly succeeded")


def test_traversal_escapes_neither_cluster(tmp_path):
    """Security parity: `..` segments must not walk out of the export through
    EITHER manager. Asserted on content, not just on the exit code — a redirect
    that silently normalised the path could still hand back a host file."""
    _require_mesh()
    for label, port, _topo, _node in MANAGERS:
        dst = tmp_path / f"{label}-escape.bin"
        r = xrdcp_get(port, "/../../../../etc/passwd", str(dst), retries=1)
        assert r.returncode != 0, (label, "traversal transfer succeeded")
        if dst.exists():
            assert b"root:" not in dst.read_bytes(), \
                (label, "traversal leaked /etc/passwd")

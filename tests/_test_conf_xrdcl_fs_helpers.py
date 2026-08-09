"""Differential conformance: XrdCl::FileSystem metadata / namespace ops.

Theme
-----
Drive the **real** ``libXrdCl`` python bindings (``from XRootD import client``) —
the exact code path gfal / FTS / Rucio use — against BOTH our nginx-xrootd server
and the stock ``xrootd`` v5.9.5 server, and assert the parsed result objects agree.
Stock is the source of truth: any divergence is OUR bug (pinned with xfail +
``# DIVERGENCE:``), unless positive evidence says otherwise.

Coverage
--------
* dirlist: ``/``, ``/sub``, ``/many``, ``/empty_dir``, ``/deep`` (recursive),
  missing dir — compare entry name-sets, and with ``Stat`` flag the per-entry
  flags + sizes, our-vs-stock.
* mkdir: new / existing (kXR_ItExists parity) / nested without MakePath
  (kXR_NotFound parity) / nested with MakePath.
* chmod: ``Access::Mode`` bit combinations, then stat-flag readback parity.
* rm: file / missing / directory (must NOT recurse — data-loss guard) ;
  rmdir: empty / non-empty (ENOTEMPTY parity).
* mv/rename: file / onto existing / into missing parent / missing source —
  compare status.code/errno AND resulting on-disk tree.
* truncate, and the simple query codes (Config / Space / Stats) + statvfs.

Every mutating op runs against a per-test scratch subdir created identically
under ``ctx['our_data']`` and ``ctx['off_data']`` so the two on-disk trees stay
byte-identical; after each mutating op we assert ``os.walk`` of the two roots
match exactly.

Contract citations
------------------
* DirListFlags / MkDirFlags / Access::Mode:
  ``/tmp/brix-src/src/XrdCl/XrdClFileSystem.hh:127-174``.
* DirectoryList / StatInfo wire parse: ``XrdClXRootDResponses.cc``.
* kXR error numbers (3005 FSError, 3011 NotFound, 3018 ItExists) and the
  errno->kXR mapping (ENOTEMPTY/EEXIST -> kXR_ItExists,
  ``XProtocol.hh:1407-1474``).
* Stock server handlers: ``/tmp/brix-src/src/XrdXrootd/``.
"""

import os

import pytest

import official_interop_lib as L
from _xrdcl_proxy import real_bindings_available

pytestmark = [
    pytest.mark.registry_servers("interop-our", "interop-off"),
    pytest.mark.xdist_group("interop-central"),
]

# kXR error numbers (XProtocol.hh:1032+)
kXR_FSError = 3005
kXR_NotFound = 3011
kXR_ItExists = 3018

# Import the shadow API; the fixture verifies its real worker dependency.
try:
    from XRootD import client  # noqa: E402
    from XRootD.client.flags import (  # noqa: E402
        AccessMode,
        DirListFlags,
        MkDirFlags,
        QueryCode,
    )

    _HAVE_BINDINGS = True
except Exception:  # noqa: BLE001
    _HAVE_BINDINGS = False

# --------------------------------------------------------------------------- #
# Module fixture: attach to the ONE registry-managed differential pair.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def pair():
    assert L.have_official(), "stock xrootd tools are required"
    assert real_bindings_available(), (
        "real libXrdCl bindings unavailable; run the suite with its configured venv")
    return L.central_pair()


def _fs(url):
    return client.FileSystem(url)


def _both(pair):
    return (
        ("our", pair["our"], pair["our_data"]),
        ("off", pair["off"], pair["off_data"]),
    )


# --------------------------------------------------------------------------- #
# Scratch-tree helpers: create the SAME structure under both data roots so the
# two trees start byte-identical for mutating ops, and so we can diff them after.
# --------------------------------------------------------------------------- #
def _walk(root):
    """Sorted list of (relpath, is_dir, size_if_file) for the whole tree."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            rel = os.path.relpath(os.path.join(dirpath, d), root)
            out.append((rel, True, -1))
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            out.append((rel, False, os.path.getsize(full)))
    return sorted(out)


def _mk_scratch(pair, name, builder):
    """Build identical scratch dir ``/<name>`` under both data roots.

    ``builder(disk_dir)`` populates the on-disk directory; called once per root
    with the absolute disk path. Returns the logical path ``/<name>``.
    """
    logical = "/" + name
    for tag, _, data in _both(pair):
        d = os.path.join(data, name)
        # fresh each time so re-runs are deterministic
        if os.path.isdir(d):
            _rmtree(d)
        os.makedirs(d, exist_ok=True)
        builder(d)
        # BOTH servers run their workers as `nobody` (nginx's compiled-in default
        # user; the stock xrootd via its -R nobody drop). chmod(2)/chown(2) require
        # OWNERSHIP, not a mode bit, so a nobody worker can only mutate a
        # nobody-owned file. The scratch is created here by the root pytest process,
        # so unless we hand it to `nobody` the worker gets EPERM and parity with
        # stock diverges — this was the whole "27 chmod failures under root" cluster.
        # Give BOTH scratch subtrees to `nobody` (best-effort; a no-op unprivileged,
        # where the invoking user already owns everything) so the two nobody workers
        # enforce identical ownership/permission semantics.
        L.chown_stock(d)
    return logical


def _rmtree(d):
    for dirpath, dirnames, filenames in os.walk(d, topdown=False):
        for fn in filenames:
            os.remove(os.path.join(dirpath, fn))
        for dn in dirnames:
            os.rmdir(os.path.join(dirpath, dn))
    if os.path.isdir(d):
        os.rmdir(d)


def _assert_trees_match(pair, subdir):
    """After a mutating op, the two scratch subtrees must be byte-structurally
    identical (same dir/file set, same file sizes). Stock is truth."""
    our = _walk(os.path.join(pair["our_data"], subdir))
    off = _walk(os.path.join(pair["off_data"], subdir))
    assert our == off, f"tree diverged under /{subdir}:\n our={our}\n off={off}"


# --------------------------------------------------------------------------- #
# 1. dirlist — name-set parity (plain), per-test path matrix
# --------------------------------------------------------------------------- #
# The real export root '/' is SHARED and, under `-n8 --dist load`, is polluted
# by other workers' working files — so the root-listing differentials enumerate
# this per-worker pseudo-root (seeded identically on both data roots below)
# instead of '/'. Every other path is a seeded dir no test writes into.
DLROOT = "/dlroot_" + L.worker_tag()


@pytest.fixture(scope="module", autouse=True)
def _seed_dlroot(pair):
    """Seed DLROOT identically on both data roots with a deterministic mix of
    files (varied sizes) and subdirs, giving the root-listing tests a stable,
    concurrency-isolated tree to compare our-vs-stock."""
    for _tag, _url, data in _both(pair):
        d = os.path.join(data, DLROOT.lstrip("/"))
        if os.path.isdir(d):
            _rmtree(d)
        os.makedirs(os.path.join(d, "sd1"), exist_ok=True)
        os.makedirs(os.path.join(d, "sd2"), exist_ok=True)
        open(os.path.join(d, "a.txt"), "w").write("AAA")
        open(os.path.join(d, "b.bin"), "wb").write(b"Z" * 100)
        open(os.path.join(d, "c.dat"), "wb").write(b"")
        open(os.path.join(d, "sd1", "inner.txt"), "w").write("inner")
    yield


# pytest.param with a STABLE id keeps every xdist worker's collected node id
# identical ([dlroot]) while the per-worker path value differs — otherwise xdist
# aborts with "different tests were collected between gwN and gwM".
DIRLIST_PATHS = [pytest.param(DLROOT, id="dlroot"), "/sub", "/many",
                 "/empty_dir", "/deep", "/deep/a/b/c"]

def _dir_with_child(d):
    inner = os.path.join(d, "victim")
    os.makedirs(inner)
    open(os.path.join(inner, "child.txt"), "w").write("must survive")

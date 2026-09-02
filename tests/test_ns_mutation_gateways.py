"""test_ns_mutation_gateways.py — namespace MUTATIONS through a storage driver.

The combinatorial-coverage audit's P2-14 cell: every mkdir/rm/rmdir/mv/dirlist
test in the suite ran against a plain POSIX export.  The driver-backed spellings
of those same operations — `sd_http` (WebDAV origin) and `sd_xroot` (root://
origin) under a root:// front end — had no coverage at any level, so a driver
could answer differently from the kernel and nothing would notice.

Three of them did, and this module is where they surface (see the header of
`configs/nginx_lc_ns_gateways.conf` for the topology):
  * `sd_http_unlink` reported SUCCESS for an object that was never there — a
    delete of a typo'd path looked like a delete of real data;
  * `sd_http_unlink` discarded its `is_dir` argument, so an rmdir aimed at a
    regular FILE issued a plain DELETE and destroyed the file (data loss on a
    path a client is entitled to expect a refusal from);
  * the recursive `mkdir -p` walk (`fs/path/mkdir.c`) swallowed EEXIST for the
    FINAL component, so `mkdir -p /somefile` reported that a directory existed
    where the client's own bytes were — on ALL THREE planes, POSIX included;
  * `dirlist` of the EXPORT ROOT through an http backend came back empty: the
    PROPFIND depth baseline dropped the multistatus self entry because the root's
    href (`/`) has no basename, so the shallowest surviving response was a CHILD
    and `min_depth` came out one level too deep.

The shape is a three-way comparison rather than a table of expected codes: the
plain-POSIX export is the CONTROL, and each driver is asked the same question on
the same operation.  Where the kernel refuses, a driver that succeeds is a bug —
which is exactly how the two `sd_http` defects above were caught.

Coverage (success + error + security-negative):
  * success           — mkdir/rm/rmdir/mv round-trip through both gateways and
    land in the ORIGIN tree (not the export root); `mkdir -p` over an existing
    DIRECTORY stays idempotent; dirlist of the export root and of a subdirectory
    enumerate through the http driver; an empty collection lists empty;
  * error             — `mkdir -p` over a regular file is refused kXR_ItExists on
    every plane and leaves the file's bytes intact; rm of a missing object is
    kXR_NotFound on every plane; rmdir of a regular file and rm of a directory
    are refused and the target SURVIVES; xattr through the http gateway
    round-trips as a WebDAV dead property and lands at the ORIGIN (the driver
    grew xattr slots in the storage-driver slot wave, item Q);
  * security-negative — a traversal-shaped mkdir/rm through either gateway
    writes nothing above the export and forwards nothing to the origin.

Run:
  PYTHONPATH=tests pytest tests/test_ns_mutation_gateways.py -v
"""

import os
import pathlib

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from official_interop_lib import worker_reachable
from server_registry import NginxInstanceSpec

try:
    from XRootD import client as xrdcl
    from XRootD.client.flags import MkDirFlags
    _HAVE_BINDINGS = True
except Exception:  # noqa: BLE001 — any import failure disables the module
    xrdcl = None
    MkDirFlags = None
    _HAVE_BINDINGS = False

pytestmark = [
    pytest.mark.serial,
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-ns-gateways"),
    pytest.mark.skipif(not _HAVE_BINDINGS,
                       reason="libXrdCl python bindings unavailable"),
]

# XProtocol.hh:1031+
kXR_FSError = 3005
kXR_IOError = 3007
kXR_NotFound = 3011
kXR_ItExists = 3018

NAME = "lc-ns-gateways"

# The three planes.  POSIX is the control; the other two are the same operations
# routed through a storage driver.
POSIX, GW_HTTP, GW_XROOT = "posix", "gw-http", "gw-xroot"
PLANES = [POSIX, GW_HTTP, GW_XROOT]
GATEWAYS = [GW_HTTP, GW_XROOT]

PAYLOAD = b"NS-MUTATION-PAYLOAD" * 16


class _Mesh:
    """One nginx: a WebDAV origin, a plain-POSIX root:// export, and the two
    root:// gateways that store through a driver."""

    def __init__(self, lifecycle, tmp_path):
        self._lifecycle = lifecycle
        root = pathlib.Path(tmp_path)
        # Backing stores.  The xroot gateway's origin IS the POSIX control
        # export (that is what makes their answers comparable), so tests name
        # their fixtures per-plane rather than sharing them.
        self.posix_dir = root / "posix-data"
        self.http_origin_dir = root / "http-origin"
        # Gateway export roots: bookkeeping only — object bytes belong to the
        # origin, and a test that finds content here has found a fallback.
        self.gw_http_export = root / "export-gw-http"
        self.gw_xroot_export = root / "export-gw-xroot"
        for d in (self.posix_dir, self.http_origin_dir,
                  self.gw_http_export, self.gw_xroot_export):
            d.mkdir(parents=True, exist_ok=True)
        worker_reachable(self.posix_dir, self.http_origin_dir,
                         self.gw_http_export, self.gw_xroot_export)
        self.ports = {}

    def start(self):
        ep = self._lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_lc_ns_gateways.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "POSIX_DIR": str(self.posix_dir),
                "HTTP_ORIGIN_DIR": str(self.http_origin_dir),
                "GW_HTTP_EXPORT": str(self.gw_http_export),
                "GW_XROOT_EXPORT": str(self.gw_xroot_export),
            },
            reason="namespace mutations compared across a POSIX control and "
                   "two driver-backed root:// gateways (sd_http, sd_xroot)",
        ))
        self.ports = {POSIX: ep.port,
                      GW_HTTP: ep.extra_ports["GW_HTTP_PORT"],
                      GW_XROOT: ep.extra_ports["GW_XROOT_PORT"]}
        return self

    def fs(self, plane):
        return xrdcl.FileSystem(f"root://{HOST}:{self.ports[plane]}")

    def store(self, plane):
        """The directory whose contents the plane's namespace describes."""
        return self.http_origin_dir if plane == GW_HTTP else self.posix_dir

    def seed_file(self, plane, name, payload=PAYLOAD):
        p = self.store(plane) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(payload)
        return p

    def seed_dir(self, plane, name):
        p = self.store(plane) / name
        p.mkdir(parents=True, exist_ok=True)
        return p


@pytest.fixture()
def mesh(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    return _Mesh(lifecycle, tmp_path).start()


def _mkpath(fs, path):
    """`mkdir -p` — the flag the recursive walk in fs/path/mkdir.c serves."""
    return fs.mkdir(path, MkDirFlags.MAKEPATH)


def _names(entries):
    return sorted(e.name for e in entries) if entries else []


def _perattr(resp):
    """First per-attribute status out of an fattr response, shape-agnostic (the
    bindings hand back a dict via the proxy, a Status object when imported
    directly)."""
    assert resp, "fattr response carried no per-attribute entry"
    st = resp[0][-1]
    if isinstance(st, dict):
        return bool(st.get("ok")), int(st.get("errno", 0) or 0)
    return bool(getattr(st, "ok", False)), int(getattr(st, "errno", 0) or 0)


# --------------------------------------------------------------------------- #
# Success — the mutations reach the ORIGIN through each driver                  #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("plane", PLANES)
def test_mkdir_and_rmdir_round_trip_to_the_origin(mesh, plane):
    """A collection created through the plane appears in the backing store and
    disappears again — on the gateways that means MKCOL/DELETE (http) and a
    forwarded mkdir/rmdir (xroot), never a directory quietly made under the
    gateway's own export root."""
    fs = mesh.fs(plane)
    name = f"made-{plane}"

    st, _ = _mkpath(fs, f"/{name}")
    assert st.ok, f"mkdir through {plane} failed: {st.message}"
    assert (mesh.store(plane) / name).is_dir(), \
        f"mkdir through {plane} did not reach the backing store"

    st, _ = fs.rmdir(f"/{name}")
    assert st.ok, f"rmdir through {plane} failed: {st.message}"
    assert not (mesh.store(plane) / name).exists(), \
        f"rmdir through {plane} reported success but the collection is still there"


@pytest.mark.parametrize("plane", PLANES)
def test_rm_removes_a_file_through_the_driver(mesh, plane):
    """The happy path the two `sd_http_unlink` negatives below are measured
    against: a real object really is deleted."""
    name = f"doomed-{plane}.bin"
    seeded = mesh.seed_file(plane, name)

    st, _ = mesh.fs(plane).rm(f"/{name}")

    assert st.ok, f"rm through {plane} failed: {st.message}"
    assert not seeded.exists(), f"rm through {plane} left the object behind"


@pytest.mark.parametrize("plane", PLANES)
def test_mkpath_over_an_existing_directory_stays_idempotent(mesh, plane):
    """The EEXIST tightening must not cost `mkdir -p` its whole point: a second
    call over an existing DIRECTORY is still success, on every plane."""
    fs = mesh.fs(plane)
    name = f"idem-{plane}/deep"
    mesh.seed_dir(plane, name)

    st, _ = _mkpath(fs, f"/{name}")

    assert st.ok, f"mkdir -p over an existing directory failed on {plane}: {st.message}"
    assert (mesh.store(plane) / name).is_dir()


@pytest.mark.parametrize("plane", PLANES)
def test_mv_renames_through_the_driver(mesh, plane):
    """MOVE (http) / forwarded rename (xroot) against the POSIX truth: the bytes
    follow the name."""
    src, dst = f"mv-src-{plane}.bin", f"mv-dst-{plane}.bin"
    mesh.seed_file(plane, src)

    st, _ = mesh.fs(plane).mv(f"/{src}", f"/{dst}")

    assert st.ok, f"mv through {plane} failed: {st.message}"
    assert not (mesh.store(plane) / src).exists(), "the source name survived the mv"
    assert (mesh.store(plane) / dst).read_bytes() == PAYLOAD, \
        "the moved object's bytes did not follow it"


def test_dirlist_of_the_export_root_enumerates_the_origin(mesh):
    """The min_depth regression pin.  PROPFIND's multistatus starts with a self
    entry, and at the export root that entry's href is `/` — no basename.  The
    depth baseline used to be computed only over NAMED entries, so the self
    response was dropped, the shallowest surviving response was a child, and
    every child then looked too shallow to be a child: `dirlist /` on an
    http-backed export returned NOTHING."""
    mesh.seed_file(GW_HTTP, "top.bin")
    mesh.seed_file(GW_HTTP, "d1/f1.bin")
    mesh.seed_dir(GW_HTTP, "d2")

    st, entries = mesh.fs(GW_HTTP).dirlist("/")

    assert st.ok, f"dirlist of the export root failed: {st.message}"
    assert _names(entries) == ["d1", "d2", "top.bin"], \
        "the export root enumerated the wrong set through the http driver"


def test_dirlist_of_a_subdirectory_and_of_an_empty_collection(mesh):
    """The two neighbouring depths the root fix must not have disturbed: a
    populated subdirectory still lists exactly its own children (no self entry
    leaking in as a member), and an empty collection lists empty."""
    mesh.seed_file(GW_HTTP, "sub/only.bin")
    mesh.seed_dir(GW_HTTP, "empty")
    fs = mesh.fs(GW_HTTP)

    st, entries = fs.dirlist("/sub")
    assert st.ok, f"dirlist of a subdirectory failed: {st.message}"
    assert _names(entries) == ["only.bin"], \
        f"subdirectory listing carried extra entries: {_names(entries)}"

    st, entries = fs.dirlist("/empty")
    assert st.ok, f"dirlist of an empty collection failed: {st.message}"
    assert _names(entries) == [], f"empty collection listed {_names(entries)}"


# --------------------------------------------------------------------------- #
# Error — a refusal on the control plane is a refusal on every plane            #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("plane", PLANES)
def test_mkpath_over_a_regular_file_is_refused(mesh, plane):
    """`mkdir -p /file` must NOT report that a directory exists where a regular
    file is: coreutils reports the conflict and so does the reference do_Mkdir.
    The recursive walk swallowed EEXIST for the final component, so this
    succeeded on all three planes — a client could believe it had a directory
    and then fail every subsequent operation inside it.

    Intermediate components never needed the probe (the next level's mkdir under
    a regular file fails ENOTDIR on its own); the FINAL component did."""
    name = f"blocker-{plane}.bin"
    seeded = mesh.seed_file(plane, name)

    st, _ = _mkpath(mesh.fs(plane), f"/{name}")

    assert not st.ok, f"mkdir -p over a regular file succeeded on {plane}"
    assert st.errno == kXR_ItExists, \
        f"mkdir -p over a regular file answered {st.errno} on {plane}, expected ItExists"
    assert seeded.read_bytes() == PAYLOAD, \
        f"the refused mkdir damaged the file it collided with on {plane}"
    assert seeded.is_file(), "the file was replaced by a directory"


@pytest.mark.parametrize("plane", PLANES)
def test_rm_of_a_missing_object_is_not_found(mesh, plane):
    """A delete that matched nothing must say so.  `sd_http_unlink` accepted the
    origin's 404 as a successful DELETE, so removing a typo'd path was
    indistinguishable from removing real data."""
    st, _ = mesh.fs(plane).rm(f"/nosuch-{plane}.bin")

    assert not st.ok, f"rm of a missing object succeeded on {plane}"
    assert st.errno == kXR_NotFound, \
        f"rm of a missing object answered {st.errno} on {plane}, expected NotFound"


@pytest.mark.parametrize("plane", PLANES)
def test_rmdir_of_a_regular_file_is_refused_and_the_file_survives(mesh, plane):
    """The data-loss defect.  `sd_http_unlink` ignored `is_dir`, so an rmdir of a
    FILE issued exactly the DELETE an rm would have — the file was gone and the
    client had asked for an operation that cannot legally touch it.  The driver
    now classifies the target (PROPFIND Depth:0 resourcetype) BEFORE any
    destructive request.

    The refusal codes differ by plane (the POSIX and http planes report ENOTDIR,
    the xroot gateway surfaces its origin's error) — what must not differ is that
    the file is still there afterwards."""
    name = f"notadir-{plane}.bin"
    seeded = mesh.seed_file(plane, name)

    st, _ = mesh.fs(plane).rmdir(f"/{name}")

    assert not st.ok, f"rmdir of a regular file succeeded on {plane}"
    assert st.errno in (kXR_FSError, kXR_IOError), \
        f"rmdir of a regular file answered {st.errno} on {plane}"
    assert seeded.exists() and seeded.read_bytes() == PAYLOAD, \
        f"rmdir of a regular file DESTROYED it on {plane}"


@pytest.mark.parametrize("plane", PLANES)
def test_rm_of_an_empty_directory_matches_the_posix_control(mesh, plane):
    """The control's `rm` removes an EMPTY directory (brix_ns_delete picks the
    removal kind from what the target actually is, which is stock XRootD's oss
    behaviour), so a driver must do the same rather than inventing an EISDIR
    refusal the POSIX plane does not give."""
    name = f"emptycoll-{plane}"
    seeded = mesh.seed_dir(plane, name)

    st, _ = mesh.fs(plane).rm(f"/{name}")

    assert st.ok, f"rm of an empty directory failed on {plane}: {st.message}"
    assert not seeded.exists(), f"rm of an empty directory left it behind on {plane}"


@pytest.mark.parametrize("plane", PLANES)
@pytest.mark.parametrize("op", ["rm", "rmdir"])
def test_a_populated_directory_is_never_deleted_non_recursively(mesh, plane, op):
    """The recursive-wipe pin, and the worst of the http defects.

    A WebDAV DELETE of a collection is RECURSIVE by spec, while this vtable slot
    is only ever called non-recursively (a recursive delete is walked by
    `brix_vfs_driver_rmtree`).  The driver handed the populated collection
    straight to DELETE: against a spec-conforming origin that erases the whole
    subtree, and against THIS origin it produced something arguably worse — a
    409 that the shared WebDAV status map read as ENOENT, which the root layer
    then treated as the idempotent "rmdir of a missing directory" SUCCESS.  The
    client was told its non-empty directory had been removed, and the data was
    still there.

    Both spellings must refuse, and every child must survive."""
    name = f"full-{plane}-{op}"
    seeded = mesh.seed_dir(plane, name)
    (seeded / "child.bin").write_bytes(PAYLOAD)
    (seeded / "subdir").mkdir()

    st, _ = getattr(mesh.fs(plane), op)(f"/{name}")

    assert not st.ok, f"{op} of a populated directory succeeded on {plane}"
    assert (seeded / "child.bin").read_bytes() == PAYLOAD, \
        f"{op} of a populated directory destroyed a child file on {plane}"
    assert (seeded / "subdir").is_dir(), \
        f"{op} of a populated directory destroyed a child collection on {plane}"


def test_xattr_through_the_http_gateway_lands_at_the_origin(mesh):
    """sd_http carries xattr slots (slot wave, item Q): a fattr set travels as
    a WebDAV PROPPATCH dead property and the origin's own backing file holds
    the persisted `user.nginx_xrootd.webdav.*` xattr — metadata stays in the same
    storage domain as the bytes, and the PER-ATTRIBUTE status is ok (an
    envelope-only reading of an fattr response proves nothing either way)."""
    mesh.seed_file(GW_HTTP, "attr.bin")

    _st, resp = mesh.fs(GW_HTTP).set_xattr("/attr.bin", [("user.ns", "v")])
    ok, err = _perattr(resp)

    assert ok, f"fattr set through the http gateway refused: errno={err}"
    names = os.listxattr(str(mesh.store(GW_HTTP) / "attr.bin"))
    assert names and all(n.startswith("user.nginx_xrootd.webdav.") for n in names), \
        f"the set did not land as a dead-property xattr at the origin: {names}"


# --------------------------------------------------------------------------- #
# Security-negative — a mutation must not escape the export in either direction #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("plane", GATEWAYS)
def test_traversal_mkdir_cannot_escape_the_gateway(mesh, plane):
    """A `..`-shaped mkdir is refused before the driver ever sees it: nothing is
    created above the export root, and nothing is forwarded to the origin (a
    driver that received the escaped path would create it in the ORIGIN's parent,
    which no confinement check downstream would catch)."""
    parent = mesh.store(plane).parent
    before = sorted(p.name for p in parent.iterdir())

    st, _ = _mkpath(mesh.fs(plane), f"/../ns_escape_{plane}")

    assert not st.ok, f"a traversal mkdir succeeded through {plane}"
    assert sorted(p.name for p in parent.iterdir()) == before, \
        f"a traversal mkdir changed the origin's parent through {plane}"
    assert not (mesh.store(plane) / f"ns_escape_{plane}").exists(), \
        "the escaped path was created inside the origin instead"


@pytest.mark.parametrize("plane", GATEWAYS)
def test_traversal_rm_cannot_reach_a_file_above_the_export(mesh, plane):
    """The destructive direction of the same negative: a file that exists just
    above the backing store must survive a traversal-shaped rm."""
    victim = mesh.store(plane).parent / f"ns_victim_{plane}.bin"
    victim.write_bytes(b"above-the-export")
    try:
        st, _ = mesh.fs(plane).rm(f"/../{victim.name}")

        assert not st.ok, f"a traversal rm succeeded through {plane}"
        assert victim.read_bytes() == b"above-the-export", \
            f"a traversal rm deleted a file above the export through {plane}"
    finally:
        victim.unlink(missing_ok=True)

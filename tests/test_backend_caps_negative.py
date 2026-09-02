"""test_backend_caps_negative.py — capability negatives against a REAL driver.

`tests/c/test_vfs_caps.c` proves the capability accessors on *synthetic* driver
structs: it invents a read-only backend, a writable one, a bearer-only one, and
checks the bits.  Nothing checked that a shipped driver's declared capabilities
match what a client actually gets when it asks for an operation the driver does
not implement.

The http backend (`fs/backend/http/sd_http.c`) is the probe: it declares no
truncate capability and has no `.truncate` / `.truncate_path` slots, so a
resize must come back as an honest refusal.  Its xattr surface is the OTHER
side of the same coin: since the storage-driver slot wave (item Q) the driver
carries all four xattr slots as RFC-4918 dead properties (PROPPATCH against
the origin, `bxa<hex(name)>` elements), so an fattr set must SUCCEED and land
at the ORIGIN — never as a silent fallback onto the local POSIX file under the
export root, which would put the metadata in a different storage domain from
the bytes.

Two exports share one origin so both dispatch spellings are covered:
  * STAGED  — the default write-stage tier composes over the http origin, so
    every xattr op travels through the decorator's relay to the leaf slot;
  * DIRECT  — `brix_stage off`, so sd_http is the top driver and the VFS
    dispatches the slot directly (`fs/vfs/vfs_xattr.c`).
Both paths must look identical to a client.  Historically they did not: before
the driver had xattr slots, fattr LIST mapped only ENOTSUP/EOPNOTSUPP to the
documented empty-list answer, so the staged arm answered `kXR_FSError
"listxattr failed"` for a perfectly healthy backend (fixed in
`protocols/root/fattr/list.c`); that empty-list contract is still pinned here.

Coverage (success + error + security-negative):
  * success           — a file that exists ONLY at the origin reads back
    byte-exact through both exports, and no copy appears in the export root
    (without this the whole module could pass against local POSIX storage);
    fattr set/get/del round-trip on both arms and persist at the ORIGIN as
    `user.nginx_xrootd.webdav.*` dead-property xattrs;
  * error             — fattr list of a file with no attributes is an empty
    success on both arms; truncate is refused (Unsupported through the stage
    tier, fsReadOnly on the direct export);
  * security-negative — a successful set beside a WORLD-WRITABLE local
    placeholder inside the export root leaves that file's xattrs and bytes
    untouched (no write into the wrong storage domain), and a traversal-shaped
    fattr target writes nothing above the export.

Run:
  PYTHONPATH=tests pytest tests/test_backend_caps_negative.py -v
"""

import os
import pathlib

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from official_interop_lib import worker_reachable
from server_registry import NginxInstanceSpec

try:
    from XRootD import client as xrdcl
    _HAVE_BINDINGS = True
except Exception:  # noqa: BLE001 — any import failure disables the module
    xrdcl = None
    _HAVE_BINDINGS = False

pytestmark = [
    pytest.mark.serial,
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-caps-http"),
    pytest.mark.skipif(not _HAVE_BINDINGS,
                       reason="libXrdCl python bindings unavailable"),
]

# XProtocol.hh:1031+
kXR_Unsupported = 3013
kXR_fsReadOnly = 3025

NAME = "lc-caps-http"
PROBE = "caps_probe.bin"
PROBE_BYTES = b"ORIGIN-ONLY-PAYLOAD" * 64

# The two arms, by the export they hit and the driver shape behind it.
STAGED, DIRECT = "staged", "direct"


class _Caps:
    """A WebDAV origin plus the two root:// exports that store through it."""

    def __init__(self, lifecycle, tmp_path):
        self._lifecycle = lifecycle
        self.origin = pathlib.Path(tmp_path) / "origin"
        self.staged = pathlib.Path(tmp_path) / "export-staged"
        self.direct = pathlib.Path(tmp_path) / "export-direct"
        for d in (self.origin, self.staged, self.direct):
            d.mkdir(parents=True, exist_ok=True)
        worker_reachable(self.origin, self.staged, self.direct)
        self.ports = {}

    def start(self):
        ep = self._lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_lc_caps_http.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_DATA": str(self.origin),
                "EXPORT_STAGED": str(self.staged),
                "EXPORT_DIRECT": str(self.direct),
            },
            reason="root:// exports backed by an http origin, to refuse the "
                   "capabilities sd_http does not advertise",
        ))
        self.ports = {STAGED: ep.port,
                      DIRECT: ep.extra_ports["STAGE_OFF_PORT"]}
        return self

    def export(self, arm):
        return self.staged if arm == STAGED else self.direct

    def fs(self, arm):
        return xrdcl.FileSystem(f"root://{HOST}:{self.ports[arm]}")

    def seed_origin(self, name, payload):
        p = self.origin / name
        p.write_bytes(payload)
        os.chmod(p, 0o666)
        return p


@pytest.fixture()
def caps(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    srv = _Caps(lifecycle, tmp_path).start()
    srv.seed_origin(PROBE, PROBE_BYTES)
    return srv


def _perattr(resp):
    """First per-attribute status out of an fattr response, shape-agnostic (the
    bindings hand back a dict via the proxy, a Status object when imported
    directly)."""
    assert resp, "fattr response carried no per-attribute entry"
    st = resp[0][-1]
    if isinstance(st, dict):
        return bool(st.get("ok")), int(st.get("errno", 0) or 0)
    return bool(getattr(st, "ok", False)), int(getattr(st, "errno", 0) or 0)


def _local_xattrs(path):
    try:
        return sorted(os.listxattr(str(path)))
    except OSError:
        return []


# --------------------------------------------------------------------------- #
# Success — the export really is driver-backed (non-vacuity for everything else)#
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("arm", [STAGED, DIRECT])
def test_reads_come_from_the_http_backend(caps, arm):
    """The probe exists only at the origin, so a byte-exact read proves the
    export is served by sd_http — and the export root stays empty, so no local
    copy is standing in for it."""
    f = xrdcl.File()
    st, _ = f.open(f"root://{HOST}:{caps.ports[arm]}//{PROBE}")
    assert st.ok, f"open through the http backend failed: {st.message}"
    try:
        rst, data = f.read(0, len(PROBE_BYTES))
        assert rst.ok, rst.message
        assert bytes(data) == PROBE_BYTES
    finally:
        f.close()

    # Dotfiles are the server's own bookkeeping (checkpoint-recovery lock);
    # what must not be here is object content.
    local = [p.name for p in caps.export(arm).iterdir()
             if not p.name.startswith(".")]
    assert local == [], \
        f"the export root holds local content — the read may not have been the backend's: {local}"


# --------------------------------------------------------------------------- #
# Error — every capability sd_http does not advertise is refused honestly       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("arm", [STAGED, DIRECT])
def test_xattr_round_trips_to_the_origin(caps, arm):
    """set → get → del round-trips through the driver's dead-property slots
    (slot wave, item Q): the value survives the PROPPATCH/PROPFIND hex
    encoding byte-exact, and the ORIGIN's backing file — not anything local —
    holds the persisted `user.nginx_xrootd.webdav.*` xattr for exactly as long
    as the attribute exists."""
    fs = caps.fs(arm)
    path = f"/{PROBE}"

    _st, resp = fs.set_xattr(path, [("user.caps", "v")])
    ok, err = _perattr(resp)
    assert ok, f"fattr set refused on an xattr-capable backend: errno={err}"

    names = _local_xattrs(caps.origin / PROBE)
    assert names and all(n.startswith("user.nginx_xrootd.webdav.") for n in names), \
        f"the set did not persist as a dead-property xattr at the origin: {names}"

    gst, attrs = fs.get_xattr(path, ["user.caps"])
    gok, gerr = _perattr(attrs)
    assert gst.ok and gok, f"fattr get of a set attribute refused: errno={gerr}"
    values = {t[0]: t[1] for t in attrs}
    assert values.get("user.caps") == "v", \
        f"the value did not survive the round trip: {values!r}"

    _st, resp = fs.del_xattr(path, ["user.caps"])
    ok, err = _perattr(resp)
    assert ok, f"fattr del of a set attribute refused: errno={err}"
    assert _local_xattrs(caps.origin / PROBE) == [], \
        "the deleted attribute's dead-property xattr survived at the origin"


@pytest.mark.parametrize("arm", [STAGED, DIRECT])
def test_xattr_list_is_an_empty_success(caps, arm):
    """A backend with no extended attributes lists EMPTY, not an error — the
    contract fattr/README.md documents and stock XRootD implements.  The staged
    arm reached it through the tier's relay, where the missing leaf slot reports
    ENOSYS instead of ENOTSUP; that used to surface as kXR_FSError."""
    st, names = caps.fs(arm).list_xattr(f"/{PROBE}")

    assert st.ok, f"fattr list on an xattr-less backend errored: {st.message}"
    assert list(names) == [], f"unexpected attributes: {names}"


@pytest.mark.parametrize("arm,code", [(STAGED, kXR_Unsupported),
                                      (DIRECT, kXR_fsReadOnly)])
def test_truncate_is_refused(caps, arm, code):
    """sd_http advertises no CAP_TRUNCATE and has no `.truncate` slot, so the
    resize is refused and the object keeps its size.  The two arms refuse with
    different-but-honest codes: through the stage tier the missing slot is
    Unsupported, while the direct export answers EROFS (the http backend is not
    randomly writable), which round-trips as kXR_fsReadOnly since phase-105's
    `error_mapping.c` closed the EROFS mapping — both are refusals, neither is
    a silent no-op."""
    st, _ = caps.fs(arm).truncate(f"/{PROBE}", 4)

    assert not st.ok, "truncate succeeded on a backend without CAP_TRUNCATE"
    assert st.errno == code, f"truncate answered {st.errno}, expected {code}"
    assert (caps.origin / PROBE).stat().st_size == len(PROBE_BYTES), \
        "the refused truncate resized the origin object anyway"


# --------------------------------------------------------------------------- #
# Security-negative — a refusal must not become a write somewhere else          #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("arm", [STAGED, DIRECT])
def test_xattr_does_not_touch_local_storage(caps, arm):
    """A driver-backed export's fattr set must write the attribute at the
    ORIGIN, never onto a local file under the export root: the bytes live at
    the origin, so metadata landing locally is a storage-domain split that
    survives no failover and is invisible to every other reader of the object.

    The decoy is world-writable and carries the same name as the object, so a
    local write would have succeeded — the assertion is about the code path
    taken, not about permissions."""
    decoy = caps.export(arm) / PROBE
    decoy.write_bytes(b"local-decoy")
    os.chmod(decoy, 0o666)
    try:
        _st, resp = caps.fs(arm).set_xattr(f"/{PROBE}", [("user.caps", "v")])
        ok, err = _perattr(resp)

        assert ok, f"fattr set refused on an xattr-capable backend: errno={err}"
        assert _local_xattrs(decoy) == [], \
            "the set landed on the local file under the export root"
        assert decoy.read_bytes() == b"local-decoy", "the local file was rewritten"
        assert _local_xattrs(caps.origin / PROBE) != [], \
            "the set went to neither the origin nor the decoy — where did it land?"
    finally:
        decoy.unlink(missing_ok=True)


@pytest.mark.parametrize("arm", [STAGED, DIRECT])
def test_xattr_target_above_the_export_is_refused(caps, arm):
    """An fattr aimed outside the export is refused and writes nothing above it —
    the confinement gate runs before the capability gate, so this stays a
    negative even on a backend that DOES support xattrs."""
    parent = caps.export(arm).parent
    before = sorted(p.name for p in parent.iterdir())

    st, resp = caps.fs(arm).set_xattr("/../caps_escape.bin",
                                      [("user.caps", "v")])
    if resp:
        ok, _err = _perattr(resp)
        assert not ok, "fattr set on a path above the export root succeeded"
    else:
        assert not st.ok, "fattr set on a path above the export root succeeded"

    def _assert_test_xattr_target_above_the_export_is_refused_1():
        assert not (parent / "caps_escape.bin").exists()
        assert sorted(p.name for p in parent.iterdir()) == before

    _assert_test_xattr_target_above_the_export_is_refused_1()
    assert not (caps.origin / "caps_escape.bin").exists(), \
        "the escape was forwarded to the backend"

"""
tests/test_mirror_upstream.py — nginx+xrootd traffic mirror in front of a
PROPERLY CONFIGURED official xrootd file server.

This stands up its own dedicated, cleanly-configured official xrootd
(/usr/bin/xrootd) — not the shared harness reference daemon, whose dirlist was
observed to intermittently return "Invalid response" after repeated restarts
under host load — and an nginx mirror front in front of it.  It then proves:

  * the properly-configured upstream xrootd dirlists and checksums correctly
    (so the earlier "malformed dirlist" was a degraded-daemon state, not config);
  * the mirror front serves dirlist/stat/checksum correctly to the client;
  * the mirror passes warnings/errors correctly — NO divergence is logged when
    the front and upstream agree, and a divergence IS logged when they differ;
  * query/Qcksum is mirrored and validated against a checksum-enabled upstream,
    and is gracefully treated as non-divergent against an upstream that lacks
    checksum support.

The front and upstream serve SEPARATE data roots so agreement vs divergence can
be exercised deterministically (a front-only file diverges; a common file does
not).

Run:
    PYTHONPATH=tests pytest tests/test_mirror_upstream.py -v
"""

import os
import socket
import subprocess
import time
import zlib

import pytest

from XRootD import client
from XRootD.client.flags import DirListFlags, OpenFlags, QueryCode

from config_templates import render_config
from settings import SERVER_HOST, HOST, free_port

# Self-provisions a stateful mirror front/sink + upstream mesh. Parallel
# co-execution with other suites contended the shared backends and flaked
# TestMirrorFrontServes (passes in isolation), so pin the module to the isolated
# serial lane — the pattern the other mesh/topology suites already use.
pytestmark = [pytest.mark.serial]

NGINX_BIN  = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REF_XROOTD_BIN = os.environ.get(
    "TEST_REF_BIN",
    os.environ.get("TEST_BRIX_BIN", "/usr/bin/xrootd"),
)
H = SERVER_HOST
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_mirror_upstream")

# Dedicated ports for this test's self-provisioned stack.  Each is a free OS
# port unless explicitly overridden via env, so this stack never collides with
# the managed fleet or with another self-contained test.
UP_CKS_PORT   = int(os.environ.get("TEST_MU_UP_CKS_PORT")   or free_port())  # checksum upstream
UP_BARE_PORT  = int(os.environ.get("TEST_MU_UP_BARE_PORT")  or free_port())  # no-checksum upstream
FRONT_PORT    = int(os.environ.get("TEST_MU_FRONT_PORT")    or free_port())  # mirror -> UP_CKS
FRONT_BARE_PORT = int(os.environ.get("TEST_MU_FRONT_BARE_PORT") or free_port())  # mirror -> UP_BARE

_COMMON = b"common-file-bytes-" * 512          # present on front AND upstream
_FRONTONLY = b"front-only-bytes-" * 256        # present on the front ONLY


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((H, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _wait_port(port, up=True, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _reachable(port, 0.5) == up:
            return True
        time.sleep(0.2)
    return False


def _mkdirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


def _start_xrootd(name, port, data_dir, checksum):
    """Start a dedicated, properly-configured official xrootd.  Returns the cfg
    path (used as the kill key)."""
    base = os.path.join(_DIR, name)
    _mkdirs(data_dir, os.path.join(base, "admin"), os.path.join(base, "run"))
    cfg = os.path.join(base, f"{name}.cfg")
    cks = "xrootd.chksum max 2 adler32\n" if checksum else ""
    with open(cfg, "w") as f:
        f.write(
            f"xrd.port {port}\n"
            f"oss.localroot {data_dir}\n"
            f"all.export /\n"
            f"{cks}"
            f"all.adminpath {os.path.join(base, 'admin')}\n"
            f"all.pidpath {os.path.join(base, 'run')}\n"
            f"xrd.trace off\n")
    subprocess.run([REF_XROOTD_BIN, "-b", "-c", cfg,
                    "-l", os.path.join(base, "xrootd.log")],
                   capture_output=True)
    return cfg


def _stop_xrootd(cfg):
    subprocess.run(["pkill", "-f", cfg], capture_output=True)


def _front_conf(name, port, data_dir, upstream_port, opcode_line=""):
    """Build a mirror-front nginx config.  opcode_line is an optional extra
    directive line (e.g. 'brix_mirror_exclude_opcodes stat;' or
    'brix_mirror_opcodes dirlist;').  When empty, the front uses the DEFAULT —
    mirror ALL ops."""
    base = os.path.join(_DIR, name)
    _mkdirs(os.path.join(base, "logs"))
    extra = f"        {opcode_line}\n" if opcode_line else ""
    conf = os.path.join(base, f"{name}.conf")
    with open(conf, "w") as f:
        f.write(render_config(
            "nginx_mirror_upstream_front.conf",
            BASE_DIR=base,
            PORT=port,
            DATA_DIR=data_dir,
            UPSTREAM_HOST=HOST,
            UPSTREAM_PORT=upstream_port,
            EXTRA_DIRECTIVE=extra,
        ))
    return conf


def _start_front(conf):
    chk = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        raise RuntimeError(f"front config rejected: {chk.stderr[-300:]}")
    subprocess.run([NGINX_BIN, "-c", conf], capture_output=True)


def _stop_front(conf):
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)


def _front_log(name):
    return os.path.join(_DIR, name, "logs", "error.log")


def _divergences_since(log_path, offset):
    """Return mirror-divergence log lines written after `offset`."""
    if not os.path.exists(log_path):
        return []
    with open(log_path, errors="replace") as f:
        f.seek(offset)
        return [ln for ln in f.read().splitlines()
                if "mirror divergence" in ln.lower()]


# ---------------------------------------------------------------------------
# Fixture: checksum-enabled upstream xrootd + nginx mirror front
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def stack():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not os.path.exists(REF_XROOTD_BIN):
        pytest.skip(f"official xrootd binary not found at {REF_XROOTD_BIN}")

    front_data = os.path.join(_DIR, "front_data")
    up_data    = os.path.join(_DIR, "up_data")
    _mkdirs(front_data, up_data, os.path.join(front_data, "sub"))

    # common.bin on BOTH; front_only.bin + /sub only on the front.
    with open(os.path.join(front_data, "common.bin"), "wb") as f:
        f.write(_COMMON)
    with open(os.path.join(up_data, "common.bin"), "wb") as f:
        f.write(_COMMON)
    with open(os.path.join(front_data, "front_only.bin"), "wb") as f:
        f.write(_FRONTONLY)
    with open(os.path.join(front_data, "sub", "deep.bin"), "wb") as f:
        f.write(b"deep")

    up_cfg = _start_xrootd("up_cks", UP_CKS_PORT, up_data, checksum=True)
    front_conf = _front_conf("front", FRONT_PORT, front_data, UP_CKS_PORT)
    started = {"up": up_cfg, "front": front_conf}
    try:
        if not _wait_port(UP_CKS_PORT):
            pytest.skip("upstream xrootd did not come up")
        _start_front(front_conf)
        if not _wait_port(FRONT_PORT):
            pytest.skip("mirror front did not come up")
        yield {
            "front_url": f"root://{H}:{FRONT_PORT}",
            "up_url":    f"root://{H}:{UP_CKS_PORT}",
            "front_data": front_data,
            "up_data": up_data,
            "front_log": _front_log("front"),
        }
    finally:
        _stop_front(started["front"])
        _stop_xrootd(started["up"])


# ---------------------------------------------------------------------------
# 1. The properly-configured upstream xrootd itself is correct
# ---------------------------------------------------------------------------

class TestUpstreamConfigured:

    def test_upstream_dirlist_ok(self, stack):
        """A cleanly-configured official xrootd dirlists without 'Invalid
        response' — the earlier breakage was a degraded daemon, not config."""
        st, listing = client.FileSystem(stack["up_url"]).dirlist(
            "/", DirListFlags.STAT)
        assert st.ok, f"upstream dirlist failed: {st.message}"
        names = {e.name for e in listing}
        assert "common.bin" in names

    def test_upstream_checksum_ok(self, stack):
        """Checksum-enabled upstream returns the correct adler32 (abs path)."""
        st, resp = client.FileSystem(stack["up_url"]).query(
            QueryCode.CHECKSUM, "/common.bin")
        assert st.ok, f"upstream checksum failed: {st.message}"
        algo, hexval = resp.decode().strip().split("\x00")[0].split()[:2]
        assert algo == "adler32"
        assert int(hexval, 16) == (zlib.adler32(_COMMON) & 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# 2. The mirror front serves correctly to the client
# ---------------------------------------------------------------------------

class TestMirrorFrontServes:

    def test_front_dirlist_correct(self, stack):
        st, listing = client.FileSystem(stack["front_url"]).dirlist(
            "/", DirListFlags.STAT)
        assert st.ok, f"front dirlist failed: {st.message}"
        names = {e.name for e in listing}
        assert {"common.bin", "front_only.bin"} <= names

    def test_front_checksum_correct(self, stack):
        st, resp = client.FileSystem(stack["front_url"]).query(
            QueryCode.CHECKSUM, "/common.bin")
        assert st.ok, f"front checksum failed: {st.message}"
        algo, hexval = resp.decode().strip().split("\x00")[0].split()[:2]
        assert int(hexval, 16) == (zlib.adler32(_COMMON) & 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# 3. The mirror passes warnings/errors correctly
# ---------------------------------------------------------------------------

class TestMirrorDivergenceReporting:

    def _offset(self, stack):
        log = stack["front_log"]
        return os.path.getsize(log) if os.path.exists(log) else 0

    def test_no_divergence_when_dirlist_agrees(self, stack):
        """dirlist('/') exists on both front and upstream -> both ok -> the
        mirror logs NO divergence."""
        off = self._offset(stack)
        st, _ = client.FileSystem(stack["front_url"]).dirlist("/", DirListFlags.STAT)
        assert st.ok
        time.sleep(1.5)
        assert _divergences_since(stack["front_log"], off) == []

    def test_no_divergence_when_checksum_agrees(self, stack):
        """Qcksum of a common file: front computes it AND the checksum-enabled
        upstream computes it -> both ok -> no divergence (query IS mirrored)."""
        off = self._offset(stack)
        st, _ = client.FileSystem(stack["front_url"]).query(
            QueryCode.CHECKSUM, "/common.bin")
        assert st.ok
        time.sleep(1.5)
        assert _divergences_since(stack["front_log"], off) == []

    def test_no_divergence_when_stat_agrees(self, stack):
        off = self._offset(stack)
        st, _ = client.FileSystem(stack["front_url"]).stat("/common.bin")
        assert st.ok
        time.sleep(1.5)
        assert _divergences_since(stack["front_log"], off) == []

    def test_divergence_logged_when_front_only_file(self, stack):
        """A file present on the front but ABSENT upstream: stat succeeds on the
        front, errors on the upstream -> the mirror MUST log a divergence (this
        is the warning/error being passed correctly)."""
        off = self._offset(stack)
        st, _ = client.FileSystem(stack["front_url"]).stat("/front_only.bin")
        assert st.ok, "front stat of front_only.bin should succeed"
        time.sleep(1.5)
        diverged = _divergences_since(stack["front_log"], off)
        assert diverged, "mirror should have logged a divergence for a front-only file"

    def test_divergence_logged_when_dirlist_subdir_front_only(self, stack):
        """dirlist of a subdir that exists only on the front diverges (front ok,
        upstream not-found)."""
        off = self._offset(stack)
        st, _ = client.FileSystem(stack["front_url"]).dirlist(
            "/sub", DirListFlags.STAT)
        assert st.ok
        time.sleep(1.5)
        assert _divergences_since(stack["front_log"], off), \
            "mirror should diverge on a front-only subdir dirlist"


# ---------------------------------------------------------------------------
# 4. Graceful behaviour against an upstream that LACKS checksum support
# ---------------------------------------------------------------------------

class TestMirrorGracefulUnsupported:

    def test_qcksum_graceful_against_no_checksum_upstream(self):
        """Mirroring Qcksum to an upstream xrootd with NO checksum configured
        must NOT be flagged as a divergence — the mirror 'just works' even when
        the official server supports fewer features than nginx."""
        if not os.path.exists(NGINX_BIN) or not os.path.exists(REF_XROOTD_BIN):
            pytest.skip("nginx or xrootd binary missing")

        front_data = os.path.join(_DIR, "front_bare_data")
        up_data    = os.path.join(_DIR, "up_bare_data")
        _mkdirs(front_data, up_data)
        for d in (front_data, up_data):
            with open(os.path.join(d, "common.bin"), "wb") as f:
                f.write(_COMMON)

        up_cfg = _start_xrootd("up_bare", UP_BARE_PORT, up_data, checksum=False)
        front_conf = _front_conf("front_bare", FRONT_BARE_PORT, front_data,
                                  UP_BARE_PORT)
        try:
            if not _wait_port(UP_BARE_PORT):
                pytest.skip("bare upstream xrootd did not come up")
            _start_front(front_conf)
            if not _wait_port(FRONT_BARE_PORT):
                pytest.skip("bare mirror front did not come up")

            log = _front_log("front_bare")
            off = os.path.getsize(log) if os.path.exists(log) else 0

            # Sanity: the bare upstream really does NOT support checksum.
            st_up, _ = client.FileSystem(f"root://{H}:{UP_BARE_PORT}").query(
                QueryCode.CHECKSUM, "/common.bin")
            assert not st_up.ok, "bare upstream unexpectedly supports checksum"

            # Front serves the checksum fine; the mirror replays it to the bare
            # upstream (which returns kXR_Unsupported) — must be benign.
            st, _ = client.FileSystem(f"root://{H}:{FRONT_BARE_PORT}").query(
                QueryCode.CHECKSUM, "/common.bin")
            assert st.ok, f"front checksum failed: {st.message}"
            time.sleep(1.5)
            assert _divergences_since(log, off) == [], \
                "Qcksum to a no-checksum upstream must be benign, not a divergence"
        finally:
            _stop_front(front_conf)
            _stop_xrootd(up_cfg)


# ---------------------------------------------------------------------------
# 5. Opcode selection: mirror ALL by default; de-select / restrict via config
# ---------------------------------------------------------------------------

# XRootD opcode numbers used in the mirror divergence log ("op=N").
_OP_QUERY   = 3001
_OP_DIRLIST = 3004
_OP_STAT    = 3017
_OP_STATX   = 3022

# Per-test front ports (one fresh front per opcode-config under test).  When the
# env override is set we keep the contiguous base+offset idiom; otherwise each
# front grabs a fresh free OS port at spawn time.
_SEL_PORT_BASE = int(os.environ["TEST_MU_SEL_PORT_BASE"]) \
    if os.environ.get("TEST_MU_SEL_PORT_BASE") else None


@pytest.fixture
def front_factory(stack):
    """Spawn mirror fronts (serving stack's front_data, mirroring to stack's
    checksum upstream) with arbitrary opcode directives; tear them all down."""
    confs = []
    state = {"n": 0}

    def make(opcode_line):
        port = (_SEL_PORT_BASE + state["n"]) if _SEL_PORT_BASE else free_port()
        name = f"sel_{state['n']}"
        state["n"] += 1
        conf = _front_conf(name, port, stack["front_data"], UP_CKS_PORT,
                           opcode_line)
        _start_front(conf)
        confs.append(conf)
        assert _wait_port(port), f"front {name} did not come up"
        return f"root://{H}:{port}", _front_log(name)

    yield make
    for c in confs:
        _stop_front(c)


def _diverges_for(front_url, log, op_num):
    """Issue the op `op_num` against a FRONT-ONLY path and report whether the
    mirror logged a divergence for that opcode (i.e. the op WAS mirrored).
    Front-only paths succeed on the front but are absent upstream, so a mirrored
    op diverges; a de-selected op produces no divergence line at all."""
    fs = client.FileSystem(front_url)
    off = os.path.getsize(log) if os.path.exists(log) else 0
    if op_num == _OP_STAT:
        fs.stat("/front_only.bin")
    elif op_num == _OP_DIRLIST:
        fs.dirlist("/sub", DirListFlags.STAT)
    elif op_num == _OP_QUERY:
        fs.query(QueryCode.CHECKSUM, "/front_only.bin")
    else:
        raise ValueError(op_num)
    time.sleep(1.5)
    return any(f"op={op_num} " in ln for ln in _divergences_since(log, off))


class TestMirrorOpcodeSelection:

    def test_default_mirrors_all_ops(self, front_factory):
        """No opcode directive -> mirror EVERYTHING: stat, dirlist and query all
        replay to the upstream and diverge on a front-only path."""
        url, log = front_factory("")          # default: mirror all
        assert _diverges_for(url, log, _OP_STAT),    "stat not mirrored by default"
        assert _diverges_for(url, log, _OP_DIRLIST), "dirlist not mirrored by default"
        assert _diverges_for(url, log, _OP_QUERY),   "query not mirrored by default"

    def test_exclude_one_op_disables_only_it(self, front_factory):
        """brix_mirror_exclude_opcodes stat -> stat is NOT mirrored; the rest
        (dirlist, query) still are."""
        url, log = front_factory("brix_mirror_exclude_opcodes stat;")
        assert not _diverges_for(url, log, _OP_STAT), \
            "excluded stat should NOT be mirrored"
        assert _diverges_for(url, log, _OP_DIRLIST), \
            "dirlist should still be mirrored when only stat is excluded"
        assert _diverges_for(url, log, _OP_QUERY), \
            "query should still be mirrored when only stat is excluded"

    def test_exclude_multiple_ops(self, front_factory):
        """Several ops can be de-selected at once; unlisted ops still mirror."""
        url, log = front_factory("brix_mirror_exclude_opcodes dirlist query;")
        assert not _diverges_for(url, log, _OP_DIRLIST), "dirlist should be excluded"
        assert not _diverges_for(url, log, _OP_QUERY),   "query should be excluded"
        assert _diverges_for(url, log, _OP_STAT), "stat should still be mirrored"

    def test_allowlist_restricts_to_listed_only(self, front_factory):
        """brix_mirror_opcodes dirlist -> ONLY dirlist is mirrored (the
        explicit-allowlist form still works and overrides the default-all)."""
        url, log = front_factory("brix_mirror_opcodes dirlist;")
        assert _diverges_for(url, log, _OP_DIRLIST), "allowlisted dirlist must mirror"
        assert not _diverges_for(url, log, _OP_STAT),  "non-listed stat must not mirror"
        assert not _diverges_for(url, log, _OP_QUERY), "non-listed query must not mirror"

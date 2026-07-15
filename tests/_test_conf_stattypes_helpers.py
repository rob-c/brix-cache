# _test_conf_stattypes_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_stattypes.py.  `from _test_conf_stattypes_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Differential conformance for stat / kXR_statx across FILE TYPES and
PERMISSION/flag combinations — pinned to the STOCK XRootD reference.

This file goes deeper than test_conf_stat.py / test_conf_statx.py: it builds a
matrix of special files (regular files at many modes, executables, directories
at several modes, named pipes, symlinks, 0-byte and setuid/setgid files)
IDENTICALLY on both data roots, then diffs OUR-vs-STOCK on the headline of a
stat reply: the StatGen FLAGS INTEGER.

StatGen flag derivation (XrdXrootdProtocol.cc:747 StatGen):
  readable  if (mode & any-r) AND (owner-r && euid==uid) | (grp-r && egid==gid)
                                  | other-r          -> kXR_readable (16)
  writable  same rule for write bits                  -> kXR_writable (32)
  xset      same rule for exec  bits                  -> kXR_xset     (1)
  isDir     S_ISDIR(mode)                             -> kXR_isDir    (2)
  other     !S_ISDIR && !S_ISREG (fifo/sock/dev/...)  -> kXR_other    (4)
  offline   only if devid (st_ino|st_dev) is zero     -> kXR_offline  (8)
Flag bits: XProtocol.hh:1261
  kXR_file=0 kXR_xset=1 kXR_isDir=2 kXR_other=4 kXR_offline=8
  kXR_readable=16 kXR_writable=32 kXR_poscpend=64 kXR_bkpexist=128

Because both trees are built byte-identically with identical modes, and both
servers run as the SAME uid (the test user, who OWNS every file), the OWNER
permission bits govern the readable/writable/xset computation and the FLAGS
INTEGER must be byte-identical between our server and stock. Any divergence in
a flag bit (readable/writable/xset/isDir/other) — or a wrong type
classification (fifo as file, symlink target wrong) — is a BUG IN OUR SERVER.
The stock server is the oracle; we pin to it.

The stock xrdfs client cannot drive kXR_statNoFollow and stock xrootd does not
honor it, so those probes go over RAW WIRE and pin OUR behavior to stock's.

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisioning; the whole
module skips without the stock xrootd toolchain.
"""

import os
import shutil
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs not installed")]

OUR_PORT = L.worker_port(14052)
OFF_PORT = L.worker_port(14053)
# --------------------------------------------------------------------------- #
# wire constants (XProtocol.hh)
# --------------------------------------------------------------------------- #
kXR_login, kXR_open, kXR_stat, kXR_statx, kXR_close = 3007, 3010, 3017, 3022, 3003
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003

# stat flag bits (XProtocol.hh:1261-1269)
kXR_file, kXR_xset, kXR_isDir, kXR_other = 0, 1, 2, 4
kXR_offline, kXR_readable, kXR_writable = 8, 16, 32

# stat options (XProtocol.hh)
kXR_vfs = 1

# open options (XProtocol.hh)
kXR_open_read = 0x0010


# --------------------------------------------------------------------------- #
# Special-file matrix — built IDENTICALLY on both data roots in the fixture.
#
# Each entry: (relpath, kind, mode|target, size_or_none). `kind` drives how the
# node is created; modes are applied with os.chmod AFTER creation so the bits
# are exact. We keep the two roots byte-identical so the StatGen flags integer
# is directly comparable.
# --------------------------------------------------------------------------- #
REG_MODES = [0o644, 0o600, 0o400, 0o755, 0o000, 0o444, 0o744, 0o640, 0o660]
DIR_MODES = [0o755, 0o700, 0o750, 0o500]
REG_SIZES = [0, 1, 2, 255, 511, 512, 4095, 4096, 4097, 8192, 65536]


def _build_matrix(root):
    """Create the type/mode matrix under `root`. Returns a list of
    (relpath, expect_kind) describing what was actually created (the caller
    skips probes for nodes the OS refused to make)."""
    created = []

    # Idempotence: the matrix lands in a FIXED data root shared by the A/B
    # module split (and surviving an aborted prior run).  It deliberately
    # contains read-only files (0400/0000) and dirs (0500), so a non-root
    # rebuild over the leftovers dies with EACCES on the open("wb") below —
    # root (the remote CI user) ignores file modes and never sees this.
    # Re-own the stale tree rw and remove it before rebuilding.
    types_dir = root + "/types"
    if os.path.isdir(types_dir):
        for dirpath, _dirnames, filenames in os.walk(types_dir):
            os.chmod(dirpath, 0o755)
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                if not os.path.islink(fp):
                    os.chmod(fp, 0o644)
        shutil.rmtree(types_dir)

    # Regular files at a spread of modes (owner perms govern the flags).
    for mode in REG_MODES:
        rel = f"/types/reg_{mode:04o}.bin"
        p = root + rel
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(b"\x5a" * 64)
        os.chmod(p, mode)
        created.append((rel, "file"))

    # Regular files at a spread of EXACT sizes (mode fixed 0644).
    for sz in REG_SIZES:
        rel = f"/types/sz_{sz}.dat"
        p = root + rel
        with open(p, "wb") as fh:
            fh.write(b"\x7e" * sz)
        os.chmod(p, 0o644)
        created.append((rel, "file"))

    # An executable regular file (0755): kXR_xset must be set.
    rel = "/types/exec.sh"
    p = root + rel
    with open(p, "wb") as fh:
        fh.write(b"#!/bin/sh\nexit 0\n")
    os.chmod(p, 0o755)
    created.append((rel, "file"))

    # An executable-but-not-readable-by-other file owned by us (0711): owner
    # has rwx, so all three bits set when we run as owner.
    rel = "/types/exec_711"
    p = root + rel
    with open(p, "wb") as fh:
        fh.write(b"x")
    os.chmod(p, 0o711)
    created.append((rel, "file"))

    # Directories at several modes.
    for mode in DIR_MODES:
        rel = f"/types/dir_{mode:04o}"
        p = root + rel
        os.makedirs(p, exist_ok=True)
        os.chmod(p, mode)
        created.append((rel, "dir"))

    # A FIFO / named pipe -> kXR_other (not file, not dir).
    rel = "/types/fifo1"
    p = root + rel
    try:
        os.mkfifo(p, 0o644)
        created.append((rel, "other"))
    except OSError:
        pass  # OS refused (e.g. perms) — skip this case, never to hide a diff.

    # A second FIFO at a restrictive mode.
    rel = "/types/fifo_600"
    p = root + rel
    try:
        os.mkfifo(p, 0o600)
        created.append((rel, "other"))
    except OSError:
        pass

    # Symlink to a regular file and to a directory (default stat follows).
    os.makedirs(root + "/types/linkdir", exist_ok=True)
    with open(root + "/types/linkdir/inside.txt", "wb") as fh:
        fh.write(b"target-file-12345")           # 17 bytes
    try:
        os.symlink(root + "/types/linkdir/inside.txt", root + "/types/lnk_file")
        created.append(("/types/lnk_file", "symlink->file"))
    except OSError:
        pass
    try:
        os.symlink(root + "/types/linkdir", root + "/types/lnk_dir")
        created.append(("/types/lnk_dir", "symlink->dir"))
    except OSError:
        pass
    # Broken symlink (target does not exist).
    try:
        os.symlink(root + "/types/nope_missing_target", root + "/types/lnk_broken")
        created.append(("/types/lnk_broken", "symlink->broken"))
    except OSError:
        pass

    # setuid / setgid regular files (creatable as non-root; the s-bits live in
    # the high mode octet, do not affect StatGen's r/w/x derivation but we keep
    # them in the matrix for completeness / parity).
    for name, mode in (("setuid", 0o4755), ("setgid", 0o2755)):
        rel = f"/types/{name}"
        p = root + rel
        with open(p, "wb") as fh:
            fh.write(b"s")
        try:
            os.chmod(p, mode)
            if (os.stat(p).st_mode & 0o7000) == (mode & 0o7000):
                created.append((rel, "file"))
        except OSError:
            pass

    return created


# --------------------------------------------------------------------------- #
# Fixture — our + stock server on byte-identical rich trees, then the type
# matrix layered identically on both data roots.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confstattypes"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair launch failed: {e}")
    # Layer the matrix on BOTH roots identically. The lists must agree (same
    # OS, same code path), so we take the intersection to be safe.
    our_made = _build_matrix(ctx["our_data"])
    off_made = _build_matrix(ctx["off_data"])
    # The fleet stock server runs as `nobody`; harmonize the just-built /types
    # matrix (owner triad mirrored into group+other, on BOTH roots identically) so
    # our root server's owner-match and the stock server's other-match report the
    # SAME kXR readable/writable/xset flags. Assertions are our==off, so mirroring
    # keeps them exact while eliminating the root-vs-nobody identity divergence.
    L.harmonize_perms(ctx["our_data"], ctx["off_data"])
    common = [x for x in our_made if x in off_made]
    ctx["matrix"] = common
    # Raw-wire client ports come from the fleet attach (start_pair); the module
    # OUR_PORT/OFF_PORT are legacy worker-shift values with no live server.
    ctx.setdefault("our_port", L.FLEET_OUR_PORT)
    ctx.setdefault("off_port", L.FLEET_OFF_PORT)
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# raw-wire client (port-parametric; mirrors test_conf_statx.py framing)
# --------------------------------------------------------------------------- #
def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed mid-frame")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    return sid, status, (_recv_exact(s, dlen) if dlen else b"")


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _connect(port):
    s = socket.create_connection((L.BIND, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))  # handshake
    _, st, _ = _resp(s)
    assert st == kXR_ok, "handshake reply not kXR_ok"
    return s


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, b"ctyp\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(port):
    s = _connect(port)
    _login(s)
    return s


def _stat_path(s, path, options=0, sid=b"\x00\x02"):
    """kXR_stat by PATH (ClientStatRequest, XProtocol.hh:806)."""
    p = path.encode()
    hdr = struct.pack("!2sHB7sI4sI", sid, kXR_stat, options, b"\x00" * 7,
                      0, b"\x00" * 4, len(p))
    s.sendall(hdr + p)
    return _resp(s)


def _statx(s, paths, sid=b"\x00\x12"):
    p = "\n".join(paths).encode()
    s.sendall(struct.pack("!2sH16sI", sid, kXR_statx, b"\x00" * 16, len(p)) + p)
    return _resp(s)


def _open(s, path, options=kXR_open_read, mode=0o644, sid=b"\x00\x04"):
    p = path.encode()
    hdr = struct.pack("!2sHHHH6s4sI", sid, kXR_open, mode, options, 0,
                      b"\x00" * 6, b"\x00" * 4, len(p))
    s.sendall(hdr + p)
    return _resp(s)


def _stat_handle(s, fhandle, options=0, sid=b"\x00\x03"):
    hdr = struct.pack("!2sHB7sI4sI", sid, kXR_stat, options, b"\x00" * 7,
                      0, fhandle, 0)
    s.sendall(hdr)
    return _resp(s)


def _close(s, fhandle, sid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0))
    try:
        return _resp(s)
    except EOFError:
        return None, kXR_ok, b""


def _open_handle(s, path, options=kXR_open_read):
    st, body = _open(s, path, options=options)[1:]
    assert st == kXR_ok, f"open {path} failed (status={st}, err={_err(body)})"
    assert len(body) >= 4, f"open reply too short: {len(body)} bytes"
    return body[0:4]


def _stat_fields(body):
    """Parse a StatGen reply 'id size flags mtime [ctime atime mode]'."""
    return body.rstrip(b"\x00").decode("ascii", "replace").split()


def _raw_stat(srv, path, options=0):
    """Stat one path over raw wire on BOTH servers -> (our_fields, off_fields,
    our_status, off_status)."""
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _stat_path(o, path, options=options)[1:]
        fst, fbody = _stat_path(f, path, options=options)[1:]
        return (_stat_fields(obody) if ost == kXR_ok else obody,
                _stat_fields(fbody) if fst == kXR_ok else fbody, ost, fst)
    finally:
        o.close(); f.close()


def _flags_int(fields):
    """The 3rd StatGen field is the flags integer."""
    assert len(fields) >= 4, f"short statinfo: {fields}"
    return int(fields[2])


def _size_int(fields):
    return int(fields[1])


def _decode_flags(n):
    parts = []
    if n & kXR_xset:
        parts.append("xset")
    if n & kXR_isDir:
        parts.append("isDir")
    if n & kXR_other:
        parts.append("other")
    if n & kXR_offline:
        parts.append("offline")
    if n & kXR_readable:
        parts.append("readable")
    if n & kXR_writable:
        parts.append("writable")
    return "|".join(parts) or "file"


# --------------------------------------------------------------------------- #
# Matrix selectors (resolved at collection time from the static lists so the
# parametrize ids are stable; the fixture guarantees these exist on both roots
# because both roots are built by the same code on the same OS).
# --------------------------------------------------------------------------- #
def _present(srv, rel):
    """Skip ONLY if the OS refused to create this node on either root (never to
    hide a divergence)."""
    if rel not in [r for r, _ in srv["matrix"]]:
        pytest.skip(f"{rel} not creatable on this OS/filesystem")


# =========================================================================== #
# SYMLINK with kXR_statNoFollow (raw option bit) -> stock xrootd does not honor
# it, so it follows the link like a default stat. Whatever stock does, pin OUR
# behavior to it (status + type classification + flags integer agree).
# Reference: stock has no lstat path; both should resolve to the target.
# =========================================================================== #
kXR_statNoFollow = 2  # XProtocol.hh stat option bit (best-effort; stock ignores)

__all__ = [n for n in dir() if not n.startswith('__')]

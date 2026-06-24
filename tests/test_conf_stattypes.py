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
    common = [x for x in our_made if x in off_made]
    ctx["matrix"] = common
    ctx["our_port"] = OUR_PORT
    ctx["off_port"] = OFF_PORT
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
# REGULAR FILE @ each mode -> flags integer matches stock EXACTLY.
# Owner perms govern (we run as owner). 0644 -> readable|writable;
# 0400 -> readable; 0000 -> no r/w/x bits; 0755 -> readable|writable|xset; etc.
# =========================================================================== #
@pytest.mark.parametrize("mode", REG_MODES)
def test_regfile_flags_int_matches_stock(srv, mode):
    rel = f"/types/reg_{mode:04o}.bin"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle) body={ff!r}"
    assert ost == kXR_ok, f"our stat {rel} status={ost} body={of!r}"
    on, fn = _flags_int(of), _flags_int(ff)
    assert on == fn, (
        f"FLAGS divergence {rel}: ours={on}({_decode_flags(on)}) "
        f"stock={fn}({_decode_flags(fn)})")
    # not a dir, not other
    assert not (on & kXR_isDir) and not (on & kXR_other), \
        f"our {rel} misclassified: 0x{on:02x} ({_decode_flags(on)})"


# =========================================================================== #
# REGULAR FILE @ each mode -> derive the EXPECTED owner-governed bits and pin
# BOTH servers to that derivation (catches a server that ignores perms).
# =========================================================================== #
@pytest.mark.parametrize("mode", REG_MODES)
def test_regfile_owner_bits_derivation(srv, mode):
    rel = f"/types/reg_{mode:04o}.bin"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed ours={ost} stock={fst}"
    # We run as the file's owner, so owner bits decide r/w/x.
    want = 0
    if mode & 0o400:
        want |= kXR_readable
    if mode & 0o200:
        want |= kXR_writable
    if mode & 0o100:
        want |= kXR_xset
    on, fn = _flags_int(of), _flags_int(ff)
    # mask off only the r/w/x bits for the derivation check
    rwx_mask = kXR_readable | kXR_writable | kXR_xset
    assert (fn & rwx_mask) == want, (
        f"stock {rel} owner-bit derivation wrong (oracle): "
        f"flags={fn}({_decode_flags(fn)}) want r/w/x bits 0x{want:02x}")
    assert (on & rwx_mask) == want, (
        f"our {rel} owner-bit derivation wrong: "
        f"flags={on}({_decode_flags(on)}) want r/w/x bits 0x{want:02x}")


# =========================================================================== #
# 0000-perm file -> readable/writable/xset bits ALL CLEARED on both (owner has
# no perms; owner bits govern when we are the owner).
# =========================================================================== #
def test_zero_perm_file_clears_rwx(srv):
    rel = "/types/reg_0000.bin"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    rwx = kXR_readable | kXR_writable | kXR_xset
    assert (_flags_int(ff) & rwx) == 0, \
        f"stock {rel} has r/w/x bits set on a 0000 file (oracle): {_flags_int(ff)}"
    assert (_flags_int(of) & rwx) == 0, \
        f"our {rel} has r/w/x bits set on a 0000 file: {_flags_int(of)}"


# =========================================================================== #
# Executable files -> kXR_xset SET on both; full flags integer matches.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/exec.sh", "/types/exec_711",
                                 "/types/reg_0755.bin", "/types/reg_0744.bin"])
def test_executable_xset_set(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    assert _flags_int(ff) & kXR_xset, \
        f"stock {rel} missing kXR_xset on an executable (oracle): {_flags_int(ff)}"
    assert _flags_int(of) & kXR_xset, \
        f"our {rel} missing kXR_xset on an executable: {_flags_int(of)}"
    assert _flags_int(of) == _flags_int(ff), \
        f"FLAGS divergence {rel}: ours={_flags_int(of)} stock={_flags_int(ff)}"


# =========================================================================== #
# Non-executable files -> kXR_xset CLEAR on both.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/reg_0644.bin", "/types/reg_0600.bin",
                                 "/types/reg_0400.bin", "/types/reg_0640.bin"])
def test_nonexecutable_xset_clear(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    assert not (_flags_int(ff) & kXR_xset), \
        f"stock {rel} sets kXR_xset on a non-exec file (oracle): {_flags_int(ff)}"
    assert not (_flags_int(of) & kXR_xset), \
        f"our {rel} sets kXR_xset on a non-exec file: {_flags_int(of)}"


# =========================================================================== #
# DIRECTORY @ each mode -> kXR_isDir set + r/w/x bits match stock exactly.
# =========================================================================== #
@pytest.mark.parametrize("mode", DIR_MODES)
def test_dir_flags_int_matches_stock(srv, mode):
    rel = f"/types/dir_{mode:04o}"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat {rel} status={ost}"
    on, fn = _flags_int(of), _flags_int(ff)
    assert fn & kXR_isDir, f"stock {rel} missing kXR_isDir (oracle): {fn}"
    assert on & kXR_isDir, f"our {rel} missing kXR_isDir: {on}"
    assert on == fn, (
        f"FLAGS divergence {rel}: ours={on}({_decode_flags(on)}) "
        f"stock={fn}({_decode_flags(fn)})")


# =========================================================================== #
# DIRECTORY @ each mode -> owner-governed r/w/x derivation pinned on both.
# =========================================================================== #
@pytest.mark.parametrize("mode", DIR_MODES)
def test_dir_owner_bits_derivation(srv, mode):
    rel = f"/types/dir_{mode:04o}"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    want = 0
    if mode & 0o400:
        want |= kXR_readable
    if mode & 0o200:
        want |= kXR_writable
    if mode & 0o100:
        want |= kXR_xset
    rwx = kXR_readable | kXR_writable | kXR_xset
    assert (_flags_int(ff) & rwx) == want, \
        f"stock {rel} dir owner-bit derivation wrong (oracle): {_flags_int(ff)}"
    assert (_flags_int(of) & rwx) == want, \
        f"our {rel} dir owner-bit derivation wrong: {_flags_int(of)}"


# =========================================================================== #
# FIFO / named pipe -> kXR_other (not file, not dir) on both; full parity.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/fifo1", "/types/fifo_600"])
def test_fifo_is_other(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle) body={ff!r}"
    assert ost == kXR_ok, f"our stat {rel} status={ost} body={of!r}"
    fn, on = _flags_int(ff), _flags_int(of)
    assert fn & kXR_other and not (fn & kXR_isDir), \
        f"stock {rel} not classified kXR_other (oracle): {fn}({_decode_flags(fn)})"
    assert on & kXR_other and not (on & kXR_isDir), \
        f"our {rel} not classified kXR_other: {on}({_decode_flags(on)})"
    assert on == fn, (
        f"FIFO FLAGS divergence {rel}: ours={on}({_decode_flags(on)}) "
        f"stock={fn}({_decode_flags(fn)})")


# =========================================================================== #
# FIFO via statx -> the single flag byte must be byte-IDENTICAL to stock. (The
# stock do_Statx flag byte is NOT the same as its do_Stat flags integer for a
# fifo — it does not surface kXR_other in statx — so this is a pure differential
# pinned to the oracle, not a guess about which bit "should" be set.)
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/fifo1", "/types/fifo_600"])
def test_fifo_statx_matches_stock(srv, rel):
    _present(srv, rel)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert fst == kXR_ok, f"stock statx {rel} status={fst} (oracle)"
        assert ost == kXR_ok, f"our statx {rel} status={ost} err={_err(obody)}"
        assert len(fbody) == 1 and len(obody) == 1, "statx flag byte count != 1"
        # neither stock nor we may classify a fifo as a directory
        assert not (fbody[0] & kXR_isDir), \
            f"stock statx {rel} flag 0x{fbody[0]:02x} sets kXR_isDir (oracle)"
        assert obody == fbody, \
            f"statx FIFO byte divergence {rel}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# SYMLINK -> target (default follow): a link to a FILE resolves to the file's
# type+size; a link to a DIR resolves to kXR_isDir. Parity vs stock.
# =========================================================================== #
def test_symlink_to_file_follows(srv):
    rel = "/types/lnk_file"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle) body={ff!r}"
    assert ost == kXR_ok, f"our stat {rel} status={ost} body={of!r}"
    fn, on = _flags_int(ff), _flags_int(of)
    assert not (fn & kXR_isDir) and not (fn & kXR_other), \
        f"stock {rel} did not follow link to file (oracle): {fn}({_decode_flags(fn)})"
    assert not (on & kXR_isDir) and not (on & kXR_other), \
        f"our {rel} did not follow link to file: {on}({_decode_flags(on)})"
    # the target file is 17 bytes ("target-file-12345")
    assert _size_int(ff) == 17, f"stock {rel} size={_size_int(ff)} want 17 (oracle)"
    assert _size_int(of) == 17, f"our {rel} size={_size_int(of)} want 17"
    assert on == fn, f"FLAGS divergence {rel}: ours={on} stock={fn}"


def test_symlink_to_dir_follows(srv):
    rel = "/types/lnk_dir"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat {rel} status={ost} body={of!r}"
    fn, on = _flags_int(ff), _flags_int(of)
    assert fn & kXR_isDir, f"stock {rel} did not follow link to dir (oracle): {fn}"
    assert on & kXR_isDir, f"our {rel} did not follow link to dir: {on}"
    assert on == fn, f"FLAGS divergence {rel}: ours={on} stock={fn}"


# =========================================================================== #
# SYMLINK via statx (default follow) -> the flag byte reflects the TARGET type.
# =========================================================================== #
@pytest.mark.parametrize("rel,want_dir", [
    ("/types/lnk_file", False),
    ("/types/lnk_dir", True),
])
def test_symlink_statx_follows_target(srv, rel, want_dir):
    _present(srv, rel)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert fst == kXR_ok, f"stock statx {rel} status={fst} (oracle)"
        assert ost == kXR_ok, f"our statx {rel} status={ost} err={_err(obody)}"
        assert bool(fbody[0] & kXR_isDir) == want_dir, \
            f"stock statx {rel} isDir={bool(fbody[0] & kXR_isDir)} want {want_dir}"
        assert bool(obody[0] & kXR_isDir) == want_dir, \
            f"our statx {rel} flag 0x{obody[0]:02x} isDir wrong (want {want_dir})"
        assert obody == fbody, \
            f"statx symlink byte divergence {rel}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# SYMLINK with kXR_statNoFollow (raw option bit) -> stock xrootd does not honor
# it, so it follows the link like a default stat. Whatever stock does, pin OUR
# behavior to it (status + type classification + flags integer agree).
# Reference: stock has no lstat path; both should resolve to the target.
# =========================================================================== #
kXR_statNoFollow = 2  # XProtocol.hh stat option bit (best-effort; stock ignores)


@pytest.mark.parametrize("rel", ["/types/lnk_file", "/types/lnk_dir"])
def test_symlink_nofollow_matches_stock(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel, options=kXR_statNoFollow)
    assert ost == fst, \
        f"statNoFollow status divergence {rel}: ours={ost} stock={fst}"
    if fst == kXR_ok and ost == kXR_ok:
        on, fn = _flags_int(of), _flags_int(ff)
        assert on == fn, (
            f"statNoFollow FLAGS divergence {rel}: "
            f"ours={on}({_decode_flags(on)}) stock={fn}({_decode_flags(fn)})")


# =========================================================================== #
# BROKEN SYMLINK -> error (or type) parity vs stock. A dangling link's stat()
# fails on both (the target ENOENT propagates). Pin status + error category.
# =========================================================================== #
def test_broken_symlink_error_parity(srv):
    rel = "/types/lnk_broken"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == fst, \
        f"broken-symlink status divergence {rel}: ours={ost} stock={fst}"
    if fst == kXR_error:
        assert _err(of) == _err(ff), \
            f"broken-symlink error code divergence {rel}: ours={_err(of)} stock={_err(ff)}"
    elif fst == kXR_ok:
        # if stock somehow succeeds, our flags must match
        assert _flags_int(of) == _flags_int(ff), \
            f"broken-symlink FLAGS divergence {rel}: ours={of} stock={ff}"


def test_broken_symlink_statx_parity(srv):
    rel = "/types/lnk_broken"
    _present(srv, rel)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert ost == fst, \
            f"broken-symlink statx status divergence {rel}: ours={ost} stock={fst}"
        if fst == kXR_error:
            assert _err(obody) == _err(fbody), \
                f"statx error code divergence {rel}: ours={_err(obody)} stock={_err(fbody)}"
        else:
            assert obody == fbody, \
                f"statx broken-symlink byte divergence {rel}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# SIZE exactness across many sizes (mode fixed) -> ours==stock==expected, and
# the flags integer (0644 -> readable|writable) agrees too.
# =========================================================================== #
@pytest.mark.parametrize("sz", REG_SIZES)
def test_size_exact_and_flags(srv, sz):
    rel = f"/types/sz_{sz}.dat"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat {rel} status={ost}"
    assert _size_int(ff) == sz, f"stock {rel} size={_size_int(ff)} want {sz} (oracle)"
    assert _size_int(of) == sz, f"our {rel} size={_size_int(of)} want {sz}"
    assert _size_int(of) == _size_int(ff), \
        f"size divergence {rel}: ours={_size_int(of)} stock={_size_int(ff)}"
    assert _flags_int(of) == _flags_int(ff), \
        f"FLAGS divergence {rel}: ours={_flags_int(of)} stock={_flags_int(ff)}"


# =========================================================================== #
# MTime — 4th StatGen field numeric & positive on both (trees are independent
# so no equality requirement); the STRUCTURAL fields (isDir/size/flags) agree.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/reg_0644.bin", "/types/dir_0755",
                                 "/types/sz_4096.dat", "/types/exec.sh"])
def test_mtime_numeric_structurals_match(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    for who, fields in (("our", of), ("stock", ff)):
        assert len(fields) >= 4 and fields[3].lstrip("-").isdigit(), \
            f"{who} {rel} mtime field non-int: {fields}"
        assert int(fields[3]) > 0, f"{who} {rel} mtime not positive: {fields[3]}"
    # structural agreement
    assert (_flags_int(of) & kXR_isDir) == (_flags_int(ff) & kXR_isDir), \
        f"isDir divergence {rel}: ours={_flags_int(of)} stock={_flags_int(ff)}"
    assert _size_int(of) == _size_int(ff), \
        f"size divergence {rel}: ours={_size_int(of)} stock={_size_int(ff)}"
    assert _flags_int(of) == _flags_int(ff), \
        f"FLAGS divergence {rel}: ours={_flags_int(of)} stock={_flags_int(ff)}"


# =========================================================================== #
# statx across the FULL type matrix -> one flag byte per path, correct type bit
# (file / dir / other), byte-identical to stock.
# =========================================================================== #
@pytest.mark.parametrize("rel,kind", [
    ("/types/reg_0644.bin", "file"),
    ("/types/reg_0000.bin", "file"),
    ("/types/reg_0755.bin", "file"),
    ("/types/sz_0.dat", "file"),
    ("/types/sz_65536.dat", "file"),
    ("/types/exec.sh", "file"),
    ("/types/dir_0755", "dir"),
    ("/types/dir_0700", "dir"),
    ("/types/dir_0500", "dir"),
    ("/types/fifo1", "other"),
])
def test_statx_type_bit_matches(srv, rel, kind):
    _present(srv, rel)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert fst == kXR_ok, f"stock statx {rel} status={fst} (oracle)"
        assert ost == kXR_ok, f"our statx {rel} status={ost} err={_err(obody)}"
        assert len(fbody) == 1 and len(obody) == 1, "statx must return 1 flag byte"
        # The directory bit is reliably surfaced by stock's do_Statx; the
        # non-regular ("other") classification is NOT (stock emits 0x00 for a
        # fifo in statx even though its do_Stat flags integer sets kXR_other),
        # so we pin "other" purely by the byte-for-byte differential below.
        want_dir = (kind == "dir")
        assert bool(fbody[0] & kXR_isDir) == want_dir, \
            f"stock statx {rel} isDir wrong (oracle): 0x{fbody[0]:02x}"
        assert obody == fbody, \
            f"statx flag-byte divergence {rel}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# statx MULTI-PATH mixing types -> N flag bytes, byte-identical to stock.
# =========================================================================== #
@pytest.mark.parametrize("paths", [
    ["/types/reg_0644.bin", "/types/dir_0755"],
    ["/types/dir_0700", "/types/reg_0400.bin"],
    ["/types/fifo1", "/types/reg_0644.bin", "/types/dir_0755"],
    ["/types/reg_0755.bin", "/types/exec.sh", "/types/dir_0500"],
    ["/types/sz_0.dat", "/types/sz_4096.dat", "/types/sz_65536.dat"],
    ["/types/dir_0755", "/types/dir_0700", "/types/dir_0500"],
    ["/types/reg_0644.bin", "/types/fifo1", "/types/dir_0755", "/types/exec.sh"],
])
def test_statx_multipath_mixed_types(srv, paths):
    for p in paths:
        _present(srv, p)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, paths)[1:]
        fst, fbody = _statx(f, paths)[1:]
        assert fst == kXR_ok, f"stock statx {paths} status={fst} (oracle)"
        assert ost == kXR_ok, f"our statx {paths} status={ost} err={_err(obody)}"
        assert len(fbody) == len(paths), \
            f"stock statx returned {len(fbody)} bytes for {len(paths)} paths"
        assert len(obody) == len(paths), \
            f"our statx returned {len(obody)} bytes for {len(paths)} paths"
        assert obody == fbody, \
            f"statx multi byte divergence {paths}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# statx MISSING path -> error parity vs stock (NOT an offline byte). A single
# missing path errors on both; do_Statx early-returns kXR_error.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/no_such_node.bin",
                                 "/types/missing_dir/x",
                                 "/types/reg_0644.bin/nope"])
def test_statx_missing_error_parity(srv, rel):
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert fst == kXR_error, f"stock statx {rel} did not error (oracle): st={fst}"
        assert ost == kXR_error, \
            f"our statx {rel} status={ost} (stock errored) body={obody!r}"
        assert _err(obody) == _err(fbody), \
            f"statx missing error code divergence {rel}: ours={_err(obody)} stock={_err(fbody)}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# stat via OPEN HANDLE for a regular file -> matches the path-stat flags+size.
# Reference do_Stat: !dlen => fstat the open fd.
# =========================================================================== #
@pytest.mark.parametrize("rel,sz", [
    ("/types/reg_0644.bin", 64),
    ("/types/reg_0400.bin", 64),
    ("/types/sz_0.dat", 0),
    ("/types/sz_4096.dat", 4096),
    ("/types/sz_65536.dat", 65536),
    ("/types/exec.sh", None),
])
def test_handle_stat_matches_path(srv, rel, sz):
    _present(srv, rel)
    s = _session(srv["our_port"])
    try:
        pst, pbody = _stat_path(s, rel)[1:]
        assert pst == kXR_ok, f"our path-stat {rel} status={pst}"
        fh = _open_handle(s, rel)
        hst, hbody = _stat_handle(s, fh)[1:]
        assert hst == kXR_ok, f"our handle-stat {rel} status={hst} err={_err(hbody)}"
        pf, hf = _stat_fields(pbody), _stat_fields(hbody)
        assert pf[1] == hf[1], \
            f"size path vs handle {rel}: path={pf[1]} handle={hf[1]}"
        assert pf[2] == hf[2], \
            f"flags path vs handle {rel}: path={pf[2]} handle={hf[2]}"
        if sz is not None:
            assert int(pf[1]) == sz, f"our {rel} size={pf[1]} want {sz}"
        _close(s, fh)
    finally:
        s.close()


# =========================================================================== #
# stat with TRAILING SLASH on each type -> ok/error parity vs stock (file with
# trailing slash should ENOTDIR; dir with trailing slash should succeed).
# =========================================================================== #
@pytest.mark.parametrize("rel", [
    "/types/reg_0644.bin/", "/types/exec.sh/",
    "/types/dir_0755/", "/types/dir_0700/",
    "/types/fifo1/",
])
def test_trailing_slash_parity(srv, rel):
    _present(srv, rel.rstrip("/"))
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert (ost == kXR_ok) == (fst == kXR_ok), \
        f"trailing-slash success divergence {rel!r}: ours={ost} stock={fst}"
    if ost == kXR_ok and fst == kXR_ok:
        assert _flags_int(of) == _flags_int(ff), \
            f"trailing-slash FLAGS divergence {rel}: ours={of} stock={ff}"


# =========================================================================== #
# stat the export ROOT "/" -> kXR_isDir + flags parity.
# =========================================================================== #
def test_stat_root_isdir_parity(srv):
    of, ff, ost, fst = _raw_stat(srv, "/")
    assert fst == kXR_ok, f"stock stat / status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat / status={ost}"
    assert _flags_int(ff) & kXR_isDir, f"stock / missing kXR_isDir (oracle)"
    assert _flags_int(of) & kXR_isDir, f"our / missing kXR_isDir"
    assert (_flags_int(of) & kXR_isDir) == (_flags_int(ff) & kXR_isDir), \
        "root isDir divergence"


# =========================================================================== #
# FLAGS determinism — repeating the raw stat yields the identical flags integer.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/reg_0644.bin", "/types/dir_0755",
                                 "/types/exec.sh", "/types/fifo1"])
def test_flags_determinism(srv, rel):
    _present(srv, rel)
    s = _session(srv["our_port"])
    try:
        seen = []
        for _ in range(4):
            st, body = _stat_path(s, rel)[1:]
            assert st == kXR_ok, f"our stat {rel} status={st}"
            seen.append(_flags_int(_stat_fields(body)))
        assert len(set(seen)) == 1, \
            f"our stat {rel} non-deterministic flags: {seen}"
    finally:
        s.close()


# =========================================================================== #
# setuid / setgid files -> the StatGen flags integer (which ignores the s-bits)
# matches stock; type stays regular-file (no isDir/other).
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/setuid", "/types/setgid"])
def test_setuid_setgid_flags_match(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat {rel} status={ost}"
    on, fn = _flags_int(of), _flags_int(ff)
    assert not (on & kXR_isDir) and not (on & kXR_other), \
        f"our {rel} misclassified: {on}({_decode_flags(on)})"
    assert on == fn, \
        f"FLAGS divergence {rel}: ours={on}({_decode_flags(on)}) stock={fn}({_decode_flags(fn)})"


# =========================================================================== #
# xrdfs (stock client) rendered Flags string parity across the matrix — pins
# the human-facing rendering on top of the raw integer.
# =========================================================================== #
@pytest.mark.parametrize("rel", [
    "/types/reg_0644.bin", "/types/reg_0400.bin", "/types/reg_0000.bin",
    "/types/reg_0755.bin", "/types/exec.sh", "/types/dir_0755",
    "/types/dir_0700",
])
def test_xrdfs_flags_string_parity(srv, rel):
    _present(srv, rel)

    def _statf(out):
        d = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                d[k.strip()] = v.strip()
        return d
    o = _statf(L.run([L.OFF_XRDFS, srv["our"], "stat", rel])[1])
    f = _statf(L.run([L.OFF_XRDFS, srv["off"], "stat", rel])[1])
    assert "Flags" in f, f"stock xrdfs stat {rel} produced no Flags (oracle): {f}"
    assert "Flags" in o, f"our xrdfs stat {rel} produced no Flags: {o}"
    assert o.get("Flags") == f.get("Flags"), \
        f"xrdfs Flags string divergence {rel}: ours={o.get('Flags')!r} stock={f.get('Flags')!r}"
    assert o.get("Size") == f.get("Size"), \
        f"xrdfs Size divergence {rel}: ours={o.get('Size')!r} stock={f.get('Size')!r}"

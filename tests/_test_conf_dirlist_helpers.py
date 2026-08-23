"""Differential conformance for directory listing (kXR_dirlist).

Every probe is run against BOTH our nginx-xrootd server and the STOCK xrootd
data server on byte-identical data trees, then OUR behavior is pinned to the
STOCK reference: any divergence (missing/extra entry, wrong size or dir flag,
leaked internal artifact, wrong error category, truncation at large N) is
assumed to be a bug in OUR implementation.

Coverage (kXR_dirlist plain / kXR_dstat with-stat / kXR_dcksm with-checksum):
  * stock-client `ls` / `ls -l` / `ls -R` against both servers (name-set,
    per-entry size, dir-flag column, recursive leaf-set).
  * RAW WIRE kXR_dirlist plain  -> newline-separated names, OKSOFAR chunking.
  * RAW WIRE kXR_dirlist+kXR_dstat -> "." lead-in sentinel + per-entry stat
    line (size / IsDir flag), differential count + sizes.
  * RAW WIRE kXR_dirlist+kXR_dcksm -> per-entry `[ algo:value ]` checksum token;
    spot-checked against an independent zlib.adler32 of the file (the stock data
    server may lack the checksum plugin -> then we pin OUR output against the
    independent computation and require OUR success).
  * edge cases: empty dir, file-not-dir, nonexistent dir, 200-entry dir (no
    truncation), special names (spaces / dots / case), nested, trailing slash,
    no internal-artifact leak.

Response framing follows XrdXrootdXeq.cc do_Dirlist / do_DirStat:
  plain  : "<name>\n<name>\n...<name>"  (final entry NUL-terminated, OKSOFAR
           chunking on overflow; empty dir -> empty kXR_ok body).
  dstat  : ".\n0 0 0 0\n" lead-in sentinel, then per entry
           "<name>\n<id> <size> <flags> <mtime>[ [ algo:value ]]\n".

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisioning; the whole
module skips without the stock xrootd toolchain.
"""

import os
import socket
import struct
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs not installed")]

# Raw-socket connections go straight to these ports, so they must be the live
# fleet pair (worker_port() shifts into an unbound per-worker band → refused).
OUR_PORT = L.worker_port(14060)   # per-worker band (was shared L.FLEET_OUR_PORT → 20003 collisions)
OFF_PORT = L.worker_port(14061)
# wire constants (XProtocol.hh)
kXR_login, kXR_dirlist, kXR_locate = 3007, 3004, 3027
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003
kXR_dstat, kXR_dcksm = 2, 4          # XDirlistRequestOption
kXR_isDir = 0x02                      # StatGen flag bit


# --------------------------------------------------------------------------- #
# Fixture — launch our + stock server on identical rich trees, then graft on
# the extra dirs (bigdir / special names / nested / mixed) byte-identically on
# BOTH data roots so every differential probe is exact.
# --------------------------------------------------------------------------- #
SPECIAL_NAMES = ["a-b", "a.b.c", "UPPER", "with space", "dot.txt",
                 "MixedCase", "two words here", "trailing.dot."]

# Per-xdist-worker pseudo-root. The real export '/' is SHARED, so under
# `-n8 --dist load` other workers' working files show up in a listing of '/' and
# break any FULL our-vs-stock set comparison. Every test that compares the whole
# root listing enumerates this isolated per-worker dir instead (seeded
# identically on both data roots by _build_extra_dirs). Its contents mirror what
# '/' exercised: files of varied sizes + subdirs (for ls -l sizes / dir-flag /
# recursion). Tests that only check a SUBSET of '/' (baseline sizes present, no
# artifact leak) are pollution-immune and keep using the real '/'.
WROOT = "/wroot_" + L.worker_tag()
WROOT_FILES = {"walpha.txt": b"alpha\n", "wbeta.bin": bytes(range(64)),
               "wempty.txt": b""}
WROOT_SUBDIRS = {"wsub": {"leaf.txt": b"leaf\n"},
                 "wmix": {"m1.txt": b"one\n", "m2.bin": bytes(range(32))}}
WROOT_BASELINE = set(WROOT_FILES) | set(WROOT_SUBDIRS)


def _write_files(directory, files):
    j = os.path.join
    os.makedirs(directory, exist_ok=True)
    for name, data in files.items():
        with open(j(directory, name), "wb") as f:
            f.write(data)


def _build_worker_root(root):
    j = os.path.join
    worker_root = j(root, WROOT.lstrip("/"))
    _write_files(worker_root, WROOT_FILES)
    for d, files in WROOT_SUBDIRS.items():
        _write_files(j(worker_root, d), files)


def _build_large_directory(root):
    j = os.path.join
    bigdir = j(root, "bigdir")
    os.makedirs(bigdir, exist_ok=True)
    for i in range(200):
        with open(j(bigdir, f"e{i:03d}"), "w") as f:
            f.write(f"entry {i}\n")


def _build_special_directory(root):
    j = os.path.join
    spec = j(root, "special")
    os.makedirs(spec, exist_ok=True)
    for name in SPECIAL_NAMES:
        with open(j(spec, name), "w") as f:
            f.write(f"contents of {name}\n")


def _build_nested_directories(root):
    j = os.path.join
    os.makedirs(j(root, "nest", "x", "y", "z"), exist_ok=True)
    with open(j(root, "nest", "x", "y", "z", "bottom.txt"), "w") as f:
        f.write("bottom\n")
    mix = j(root, "mixed")
    os.makedirs(j(mix, "subA"), exist_ok=True)
    os.makedirs(j(mix, "subB"), exist_ok=True)
    _write_files(mix, {"file1.txt": b"one\n", "file2.bin": bytes(range(64))})


def _build_extra_dirs(root):
    """Create the additional trees this module needs, identically on a root."""
    _build_worker_root(root)
    _build_large_directory(root)
    _build_special_directory(root)
    _build_nested_directories(root)


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confdir"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair launch failed: {e}")
    _build_extra_dirs(ctx["our_data"])
    _build_extra_dirs(ctx["off_data"])
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# stock xrdfs runner + parsers
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def _is_artifact(base):
    return base.startswith(".nginx-xrootd")


def _ls_set(out):
    """Basenames of a plain `ls` listing, dropping our internal artifacts."""
    names = set()
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        base = os.path.basename(s.rstrip("/"))
        if not base or _is_artifact(base):
            continue
        names.add(base)
    return names


def _listed_basename(path):
    base = os.path.basename(path.rstrip("/"))
    return None if not base or _is_artifact(base) else base


def _last_size(tokens):
    sizes = [int(token) for token in tokens if token.isdigit()]
    return sizes[-1] if sizes else None


def _ls_l_row(line):
    tokens = line.split()
    if len(tokens) < 2:
        return None
    path = tokens[-1]
    base = _listed_basename(path)
    if base is None:
        return None
    size = _last_size(tokens[:-1])
    if size is None:
        return None
    is_dir = path.endswith("/") or tokens[0].startswith("d")
    return base, (size, is_dir)


def _ls_l_rows(out):
    """Map basename -> (size, is_dir) from `ls -l` output.

    xrdfs -l column layout differs between builds/servers; the size is the last
    bare all-digit token (date/time tokens carry '-'/':'), the path is the final
    token, and a directory is marked by a leading 'd' in the permission column
    or a trailing '/' on the path.
    """
    rows = {}
    for line in out.splitlines():
        row = _ls_l_row(line)
        if row is not None:
            rows[row[0]] = row[1]
    return rows


def _ls_l_sizes(out):
    return {k: v[0] for k, v in _ls_l_rows(out).items()}


# =========================================================================== #
# RAW-WIRE kXR_dirlist client (plain / dstat / dcksm) — copied framing from
# test_brix_conformance.py, extended for the options byte and dstat parsing.
# =========================================================================== #
def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    return sid, status, (_recv_exact(s, dlen) if dlen else b"")


def _session(port):
    s = socket.create_connection((L.BIND, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, st, _ = _resp(s)                      # handshake reply
    assert st == kXR_ok, "handshake failed"
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0x7fffffff, b"conf\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"
    return s


def _dirlist_raw(s, path, options=0, sid=b"\x00\x04"):
    """Send a kXR_dirlist. The request header is streamid[2] requestid[2]
    reserved[15] options[1] dlen[4]; options lives in the last filler byte."""
    p = path.encode()
    filler = b"\x00" * 15 + bytes([options])
    s.sendall(struct.pack("!2sH16sI", sid, kXR_dirlist, filler, len(p)) + p)


def _drain_dirlist(s):
    """Read OKSOFAR chunks until the terminating kXR_ok; return the joined body
    or raise AssertionError carrying the wire error code on kXR_error."""
    chunks = b""
    while True:
        _, st, body = _resp(s)
        if st == kXR_error:
            errnum = struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None
            raise _DirlistError(errnum, body)
        assert st in (kXR_ok, kXR_oksofar), f"dirlist status={st}"
        chunks += body
        if st == kXR_ok:
            return chunks


class _DirlistError(Exception):
    def __init__(self, errnum, body):
        super().__init__(f"dirlist error {errnum}")
        self.errnum = errnum
        self.body = body


def _wire_plain_names(port, path):
    """Plain dirlist -> set of names (filtering artifacts). Raises _DirlistError
    on a server error reply."""
    s = _session(port)
    try:
        _dirlist_raw(s, path, options=0)
        body = _drain_dirlist(s)
    finally:
        s.close()
    names = set()
    for tok in body.replace(b"\x00", b"\n").decode("utf-8", "replace").split("\n"):
        tok = tok.strip()
        if tok and not _is_artifact(tok):
            names.add(tok)
    return names


def _trim_empty_lines(lines):
    while lines and lines[-1] == "":
        lines.pop()


def _sentinel_offset(lines):
    expected = ["0", "0", "0", "0"]
    present = len(lines) >= 2 and lines[0] == "." and lines[1].split() == expected
    return present, 2 if present else 0


def _checksum_fields(statline, with_cksum):
    if not with_cksum or "[" not in statline:
        return statline, None
    prefix, _, suffix = statline.partition("[")
    return prefix, suffix.rstrip("]").strip()


def _integer_field(tokens, index):
    if index >= len(tokens):
        return None
    value = tokens[index]
    return int(value) if value.lstrip("-").isdigit() else None


def _dstat_entry(lines, offset, with_cksum):
    name = lines[offset]
    statline, checksum = _checksum_fields(lines[offset + 1], with_cksum)
    tokens = statline.split()
    entry = (name, _integer_field(tokens, 1), _integer_field(tokens, 2), checksum)
    return entry, offset + 2


def _parse_dstat(body, with_cksum=False):
    """Parse a kXR_dstat body into (had_sentinel, [(name, size, flags, cksum)]).

    Layout: ".\n0 0 0 0\n" lead-in sentinel, then per entry
      "<name>\n<id> <size> <flags> <mtime>[ [ algo:value ]]\n".
    """
    text = body.replace(b"\x00", b"\n").decode("utf-8", "replace")
    lines = text.split("\n")
    _trim_empty_lines(lines)
    had_sentinel, offset = _sentinel_offset(lines)
    entries = []
    while offset + 1 < len(lines):
        entry, offset = _dstat_entry(lines, offset, with_cksum)
        if not _is_artifact(entry[0]):
            entries.append(entry)
    return had_sentinel, entries


def _locate_raw(s, path, sid=b"\x00\x05"):
    """Send a kXR_locate. Header: streamid[2] requestid[2] options[2]
    reserved[14] dlen[4] path. We send options/reserved all-zero (the server
    always stores its registered hostname, so kXR_prefname is a no-op)."""
    p = path.encode()
    s.sendall(struct.pack("!2sH16sI", sid, kXR_locate, b"\x00" * 16, len(p)) + p)


def _wire_locate(port, path):
    """Send one kXR_locate and return (status, body_text). The kXR_ok body for a
    data server is an 'S<access><host>:<port>' location token (NUL-terminated);
    a kXR_error body leads with the 4-byte errnum."""
    s = _session(port)
    try:
        _locate_raw(s, path)
        _sid, st, body = _resp(s)
    finally:
        s.close()
    return st, body.decode("utf-8", "replace")


def _wire_dstat(port, path, with_cksum=False):
    opt = kXR_dcksm if with_cksum else kXR_dstat
    s = _session(port)
    try:
        # for checksum, request a concrete type via opaque so the server picks it
        req = path + ("?cks.type=adler32" if with_cksum else "")
        _dirlist_raw(s, req, options=opt)
        body = _drain_dirlist(s)
    finally:
        s.close()
    return _parse_dstat(body, with_cksum=with_cksum)


# =========================================================================== #
# 1) plain `ls /D` — basename SET equals stock's set (parametrized)
# =========================================================================== #
@pytest.mark.parametrize("path", [
    pytest.param(WROOT, id="wroot"), "/sub", "/empty_dir", "/many", "/deep",
    "/bigdir", "/special", "/mixed", "/nest", "/nest/x/y/z", "/deep/a/b/c",
])

def _adler32_hex(path):
    with open(path, "rb") as f:
        return f"{zlib.adler32(f.read()) & 0xffffffff:08x}"

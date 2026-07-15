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
OUR_PORT = L.FLEET_OUR_PORT
OFF_PORT = L.FLEET_OFF_PORT
# wire constants (XProtocol.hh)
kXR_login, kXR_dirlist = 3007, 3004
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


def _build_extra_dirs(root):
    """Create the additional trees this module needs, identically on a root."""
    j = os.path.join
    # per-worker pseudo-root for the full-listing differentials
    w = j(root, WROOT.lstrip("/"))
    os.makedirs(w, exist_ok=True)
    for name, data in WROOT_FILES.items():
        with open(j(w, name), "wb") as f:
            f.write(data)
    for d, files in WROOT_SUBDIRS.items():
        os.makedirs(j(w, d), exist_ok=True)
        for name, data in files.items():
            with open(j(w, d, name), "wb") as f:
                f.write(data)
    # 200-entry dir (no truncation at large N)
    bigdir = j(root, "bigdir")
    os.makedirs(bigdir, exist_ok=True)
    for i in range(200):
        with open(j(bigdir, f"e{i:03d}"), "w") as f:
            f.write(f"entry {i}\n")
    # special-name entries (spaces / dots / case)
    spec = j(root, "special")
    os.makedirs(spec, exist_ok=True)
    for name in SPECIAL_NAMES:
        with open(j(spec, name), "w") as f:
            f.write(f"contents of {name}\n")
    # deeper nested dirs
    os.makedirs(j(root, "nest", "x", "y", "z"), exist_ok=True)
    with open(j(root, "nest", "x", "y", "z", "bottom.txt"), "w") as f:
        f.write("bottom\n")
    # a dir holding a MIX of files and subdirs
    mix = j(root, "mixed")
    os.makedirs(j(mix, "subA"), exist_ok=True)
    os.makedirs(j(mix, "subB"), exist_ok=True)
    with open(j(mix, "file1.txt"), "w") as f:
        f.write("one\n")
    with open(j(mix, "file2.bin"), "wb") as f:
        f.write(bytes(range(64)))


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


def _ls_l_rows(out):
    """Map basename -> (size, is_dir) from `ls -l` output.

    xrdfs -l column layout differs between builds/servers; the size is the last
    bare all-digit token (date/time tokens carry '-'/':'), the path is the final
    token, and a directory is marked by a leading 'd' in the permission column
    or a trailing '/' on the path.
    """
    rows = {}
    for line in out.splitlines():
        toks = line.split()
        if len(toks) < 2:
            continue
        path = toks[-1]
        base = os.path.basename(path.rstrip("/"))
        if not base or _is_artifact(base):
            continue
        size = None
        for t in toks[:-1]:
            if t.isdigit():
                size = int(t)
        if size is None:
            continue
        is_dir = path.endswith("/") or toks[0].startswith("d")
        rows[base] = (size, is_dir)
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


def _parse_dstat(body, with_cksum=False):
    """Parse a kXR_dstat body into (had_sentinel, [(name, size, flags, cksum)]).

    Layout: ".\n0 0 0 0\n" lead-in sentinel, then per entry
      "<name>\n<id> <size> <flags> <mtime>[ [ algo:value ]]\n".
    """
    text = body.replace(b"\x00", b"\n").decode("utf-8", "replace")
    lines = text.split("\n")
    # strip trailing empties
    while lines and lines[-1] == "":
        lines.pop()
    had_sentinel = len(lines) >= 2 and lines[0] == "." and \
        lines[1].split() == ["0", "0", "0", "0"]
    i = 2 if had_sentinel else 0
    entries = []
    while i + 1 < len(lines) + 1 and i + 1 <= len(lines):
        if i >= len(lines):
            break
        name = lines[i]
        if i + 1 >= len(lines):
            break
        statline = lines[i + 1]
        i += 2
        if _is_artifact(name):
            continue
        cksum = None
        sl = statline
        if with_cksum and "[" in sl:
            # "<id> <size> <flags> <mtime> [ algo:value ]"
            pre, _, post = sl.partition("[")
            inside = post.rstrip("]").strip()
            cksum = inside
            sl = pre
        toks = sl.split()
        # robust: size is field[1], flags field[2] of the leading int quad
        size = int(toks[1]) if len(toks) >= 2 and toks[1].lstrip("-").isdigit() else None
        flags = int(toks[2]) if len(toks) >= 3 and toks[2].lstrip("-").isdigit() else None
        entries.append((name, size, flags, cksum))
    return had_sentinel, entries


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
def test_ls_basename_set_matches(srv, path):
    orc, oout, _ = fs(srv["our"], "ls", path)
    frc, fout, _ = fs(srv["off"], "ls", path)
    assert orc == 0, f"our ls {path} failed"
    assert frc == 0, f"stock ls {path} failed"
    assert _ls_set(oout) == _ls_set(fout), \
        f"ls {path} divergence: ours={_ls_set(oout)} stock={_ls_set(fout)}"


# =========================================================================== #
# 2) `ls -l` — per-entry size column matches stock (parametrized incl bigdir)
# =========================================================================== #
@pytest.mark.parametrize("path", [pytest.param(WROOT, id="wroot"), "/many",
                                  "/bigdir", "/sub", "/mixed"])
def test_ls_l_sizes_match_stock(srv, path):
    o = _ls_l_sizes(fs(srv["our"], "ls", "-l", path)[1])
    f = _ls_l_sizes(fs(srv["off"], "ls", "-l", path)[1])
    assert set(o) == set(f), \
        f"ls -l {path} name-set divergence: ours={set(o)} stock={set(f)}"
    for name in f:
        assert o.get(name) == f.get(name), \
            f"ls -l {path} size for {name}: ours={o.get(name)} stock={f.get(name)}"


# =========================================================================== #
# 3) `ls -l` — per-entry dir-flag column matches stock (parametrized)
# =========================================================================== #
@pytest.mark.parametrize("path", [pytest.param(WROOT, id="wroot"), "/mixed",
                                  "/deep", "/nest"])
def test_ls_l_dirflag_matches_stock(srv, path):
    o = _ls_l_rows(fs(srv["our"], "ls", "-l", path)[1])
    f = _ls_l_rows(fs(srv["off"], "ls", "-l", path)[1])
    assert set(o) == set(f), \
        f"ls -l {path} name-set divergence: ours={set(o)} stock={set(f)}"
    for name in f:
        assert o[name][1] == f[name][1], \
            f"ls -l {path} dir-flag for {name}: ours={o[name][1]} stock={f[name][1]}"


# =========================================================================== #
# 4) mixed dir — a subdir appears flagged as a directory in -l on both
# =========================================================================== #
@pytest.mark.parametrize("subdir", ["subA", "subB"])
def test_ls_l_subdir_flagged_dir(srv, subdir):
    o = _ls_l_rows(fs(srv["our"], "ls", "-l", "/mixed")[1])
    f = _ls_l_rows(fs(srv["off"], "ls", "-l", "/mixed")[1])
    assert o.get(subdir, (None, None))[1] is True, \
        f"our ls -l /mixed: {subdir} not flagged dir: {o.get(subdir)}"
    assert f.get(subdir, (None, None))[1] is True, \
        f"stock ls -l /mixed: {subdir} not flagged dir: {f.get(subdir)}"


# =========================================================================== #
# 5) `ls -R /` — full recursive leaf-name set equals stock's
# =========================================================================== #
def test_ls_recursive_leaf_set_matches(srv):
    orc, oout, _ = fs(srv["our"], "ls", "-R", WROOT)
    frc, fout, _ = fs(srv["off"], "ls", "-R", WROOT)
    assert orc == 0 and frc == 0, "ls -R should succeed on both"
    assert _ls_set(oout) == _ls_set(fout), \
        f"ls -R {WROOT} leaf-set divergence: missing-from-ours={_ls_set(fout) - _ls_set(oout)} " \
        f"extra-in-ours={_ls_set(oout) - _ls_set(fout)}"


def test_ls_recursive_bigdir_all_present(srv):
    """ls -R must carry all 200 bigdir entries on both (no truncation)."""
    our = _ls_set(fs(srv["our"], "ls", "-R", "/bigdir")[1])
    off = _ls_set(fs(srv["off"], "ls", "-R", "/bigdir")[1])
    expected = {f"e{i:03d}" for i in range(200)}
    assert our == expected, f"our ls -R /bigdir missing: {expected - our}"
    assert off == expected, f"stock ls -R /bigdir missing: {expected - off}"


# =========================================================================== #
# 6) 200-entry dir — all 200 present, no truncation, compared as a set
# =========================================================================== #
def test_ls_bigdir_200_no_truncation(srv):
    our = _ls_set(fs(srv["our"], "ls", "/bigdir")[1])
    off = _ls_set(fs(srv["off"], "ls", "/bigdir")[1])
    expected = {f"e{i:03d}" for i in range(200)}
    assert len(our) == 200, f"our /bigdir has {len(our)} entries (want 200)"
    assert our == expected, f"our /bigdir set wrong: missing={expected - our}"
    assert our == off, f"/bigdir set divergence vs stock: {our ^ off}"


def test_wire_bigdir_200_no_truncation(srv):
    """Raw-wire plain dirlist over /bigdir returns all 200 (OKSOFAR chunking)."""
    our = _wire_plain_names(OUR_PORT, "/bigdir")
    off = _wire_plain_names(OFF_PORT, "/bigdir")
    expected = {f"e{i:03d}" for i in range(200)}
    assert our == expected, f"our wire /bigdir missing: {expected - our}"
    assert off == expected, f"stock wire /bigdir missing: {expected - off}"


# =========================================================================== #
# 7) special names (spaces / dots / case) — all present and exact on both
# =========================================================================== #
def test_ls_special_names_match(srv):
    our = _ls_set(fs(srv["our"], "ls", "/special")[1])
    off = _ls_set(fs(srv["off"], "ls", "/special")[1])
    expected = set(SPECIAL_NAMES)
    assert our == expected, f"our /special set wrong: missing={expected - our} extra={our - expected}"
    assert off == expected, f"stock /special set wrong: {off ^ expected}"
    assert our == off, f"/special divergence vs stock: {our ^ off}"


@pytest.mark.parametrize("name", SPECIAL_NAMES)
def test_ls_special_name_present_each(srv, name):
    our = _ls_set(fs(srv["our"], "ls", "/special")[1])
    off = _ls_set(fs(srv["off"], "ls", "/special")[1])
    assert name in our, f"our /special lost {name!r}: {our}"
    assert name in off, f"stock /special lost {name!r}: {off}"


def test_wire_special_names_match(srv):
    """Raw-wire plain dirlist preserves spaced/dotted/cased names exactly."""
    our = _wire_plain_names(OUR_PORT, "/special")
    off = _wire_plain_names(OFF_PORT, "/special")
    expected = set(SPECIAL_NAMES)
    assert our == expected, f"our wire /special set wrong: {our ^ expected}"
    assert off == expected, f"stock wire /special set wrong: {off ^ expected}"


# =========================================================================== #
# 8) nested — `ls /nest/x/y/z` -> [bottom.txt]; `/deep/a/b/c` -> [leaf.txt]
# =========================================================================== #
@pytest.mark.parametrize("path,leaf", [
    ("/nest/x/y/z", "bottom.txt"),
    ("/deep/a/b/c", "leaf.txt"),
])
def test_ls_nested_single_leaf(srv, path, leaf):
    our = _ls_set(fs(srv["our"], "ls", path)[1])
    off = _ls_set(fs(srv["off"], "ls", path)[1])
    assert our == {leaf}, f"our ls {path} = {our}, want {{{leaf!r}}}"
    assert off == {leaf}, f"stock ls {path} = {off}, want {{{leaf!r}}}"


# =========================================================================== #
# 9) trailing slash — `ls /D/` == `ls /D`
# =========================================================================== #
@pytest.mark.parametrize("path", ["/sub", "/mixed", "/special", "/bigdir"])
def test_ls_trailing_slash_equiv(srv, path):
    for url, who in ((srv["our"], "our"), (srv["off"], "stock")):
        a = _ls_set(fs(url, "ls", path)[1])
        b = _ls_set(fs(url, "ls", path + "/")[1])
        assert a == b, f"{who} ls {path} vs {path}/ differ: {a ^ b}"
    # and across servers
    assert _ls_set(fs(srv["our"], "ls", path + "/")[1]) == \
        _ls_set(fs(srv["off"], "ls", path + "/")[1]), \
        f"trailing-slash ls {path}/ divergence vs stock"


# =========================================================================== #
# 10) empty dir — empty listing on both (no synthetic '.'/'..'); pin stock
# =========================================================================== #
def test_ls_empty_dir(srv):
    orc, oout, _ = fs(srv["our"], "ls", "/empty_dir")
    frc, fout, _ = fs(srv["off"], "ls", "/empty_dir")
    assert orc == 0 and frc == 0, "ls /empty_dir should succeed on both"
    assert _ls_set(oout) == _ls_set(fout), \
        f"empty-dir divergence: ours={_ls_set(oout)} stock={_ls_set(fout)}"
    # pin stock: whatever stock emits (typically nothing), ours must equal it.
    assert _ls_set(oout) == set(), f"our /empty_dir not empty: {_ls_set(oout)}"


def test_wire_empty_dir(srv):
    """Raw-wire plain dirlist of an empty dir -> empty name set on both."""
    our = _wire_plain_names(OUR_PORT, "/empty_dir")
    off = _wire_plain_names(OFF_PORT, "/empty_dir")
    assert our == off == set(), f"wire empty-dir: ours={our} stock={off}"


# =========================================================================== #
# 11) listing a FILE (not a dir) — error-category parity vs stock
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/special/a-b"])
def test_ls_on_file_error_parity(srv, path):
    orc, oout, oerr = fs(srv["our"], "ls", path)
    frc, fout, ferr = fs(srv["off"], "ls", path)
    # stock pins the category; if stock errors, ours must error with same coarse
    # category. (Some xrdfs builds list a file as a single-entry result.)
    if frc != 0:
        assert orc != 0, f"our ls {path} (a file) succeeded but stock errored: {oout}"
        oc = L.err_code(oerr + oout)
        fc = L.err_code(ferr + fout)
        assert oc == fc, f"ls-on-file error category divergence {path}: ours={oc!r} stock={fc!r}"
    else:
        # stock tolerated it -> ours must agree on the resulting set
        assert _ls_set(oout) == _ls_set(fout), \
            f"ls-on-file {path} divergence vs stock: ours={_ls_set(oout)} stock={_ls_set(fout)}"


# =========================================================================== #
# 12) listing a nonexistent dir — error parity vs stock
# =========================================================================== #
@pytest.mark.parametrize("path", ["/no_such_dir", "/sub/missing", "/bigdir/nope"])
def test_ls_nonexistent_dir_error_parity(srv, path):
    orc, oout, oerr = fs(srv["our"], "ls", path)
    frc, fout, ferr = fs(srv["off"], "ls", path)
    assert orc != 0, f"our ls {path} unexpectedly succeeded: {oout}"
    assert frc != 0, f"stock ls {path} unexpectedly succeeded: {fout}"
    oc = L.err_code(oerr + oout)
    fc = L.err_code(ferr + fout)
    assert oc == fc, f"nonexistent-dir error category divergence {path}: ours={oc!r} stock={fc!r}"


def test_wire_nonexistent_dir_error_parity(srv):
    """Raw-wire dirlist of a nonexistent dir -> kXR_error with same errnum."""
    def probe(port):
        try:
            _wire_plain_names(port, "/no_such_dir")
            return None
        except _DirlistError as e:
            return e.errnum
    our = probe(OUR_PORT)
    off = probe(OFF_PORT)
    assert our is not None, "our wire dirlist of missing dir did not error"
    assert off is not None, "stock wire dirlist of missing dir did not error"
    assert our == off, f"wire dirlist errnum divergence: ours={our} stock={off}"


# =========================================================================== #
# 13) no internal-artifact leak — no name starting with ".nginx-xrootd"
# =========================================================================== #
@pytest.mark.parametrize("path", ["/", "/sub", "/bigdir", "/mixed", "/special"])
def test_no_artifact_leak(srv, path):
    raw = fs(srv["our"], "ls", path)[1]
    leaked = [os.path.basename(l.strip().rstrip("/"))
              for l in raw.splitlines() if l.strip()
              and os.path.basename(l.strip().rstrip("/")).startswith(".nginx-xrootd")]
    assert not leaked, f"our ls {path} leaks internal artifacts: {leaked}"


def test_no_artifact_leak_wire_root(srv):
    """Raw-wire dirlist of '/' must not surface any internal artifact name."""
    s = _session(OUR_PORT)
    try:
        _dirlist_raw(s, "/", options=0)
        body = _drain_dirlist(s)
    finally:
        s.close()
    names = body.replace(b"\x00", b"\n").decode("utf-8", "replace").split("\n")
    leaked = [n for n in names if n.strip().startswith(".nginx-xrootd")]
    assert not leaked, f"wire dirlist '/' leaks internal artifacts: {leaked}"


# =========================================================================== #
# 14) raw-wire PLAIN dirlist — name set equals stock's wire set (parametrized)
# =========================================================================== #
@pytest.mark.parametrize("path", [pytest.param(WROOT, id="wroot"), "/sub",
                                  "/many", "/mixed", "/nest/x/y/z"])
def test_wire_plain_set_matches_stock(srv, path):
    our = _wire_plain_names(OUR_PORT, path)
    off = _wire_plain_names(OFF_PORT, path)
    assert our == off, f"wire plain dirlist {path} divergence: ours={our} stock={off}"


def test_wire_plain_root_includes_baseline(srv):
    """Sanity anchor: the wire dirlist carries the known baseline tree on both,
    and the full set agrees. Uses the per-worker pseudo-root (WROOT) so a
    concurrent worker's files under the shared '/' can't perturb the equality."""
    our = _wire_plain_names(OUR_PORT, WROOT)
    off = _wire_plain_names(OFF_PORT, WROOT)
    assert WROOT_BASELINE <= our, f"our wire {WROOT} missing baseline: {WROOT_BASELINE - our}"
    assert WROOT_BASELINE <= off, f"stock wire {WROOT} missing baseline: {WROOT_BASELINE - off}"
    assert our == off, f"wire {WROOT} set divergence: {our ^ off}"


# =========================================================================== #
# 15) dirlist WITH-STAT (kXR_dstat) — "." lead-in sentinel present on both
# =========================================================================== #
@pytest.mark.parametrize("path", ["/", "/many", "/mixed"])
def test_wire_dstat_sentinel_present(srv, path):
    our_sent, _ = _wire_dstat(OUR_PORT, path)
    off_sent, _ = _wire_dstat(OFF_PORT, path)
    assert off_sent, f"stock dstat {path} lacks the '.' lead-in sentinel"
    assert our_sent, f"our dstat {path} lacks the '.' lead-in sentinel (stock has it)"


# =========================================================================== #
# 16) dirlist WITH-STAT — entry count matches stock (excl sentinel)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/many", "/mixed", "/bigdir", "/sub"])
def test_wire_dstat_entry_count_matches(srv, path):
    _, our_e = _wire_dstat(OUR_PORT, path)
    _, off_e = _wire_dstat(OFF_PORT, path)
    our_names = {n for n, *_ in our_e}
    off_names = {n for n, *_ in off_e}
    assert our_names == off_names, \
        f"dstat {path} name-set divergence: missing-from-ours={off_names - our_names} " \
        f"extra={our_names - off_names}"


# =========================================================================== #
# 17) dirlist WITH-STAT — per-entry size matches the real file size + stock
# =========================================================================== #
def test_wire_dstat_sizes_match(srv):
    """For /many each entry's stat-line size == real on-disk size, and == stock."""
    _, our_e = _wire_dstat(OUR_PORT, "/many")
    _, off_e = _wire_dstat(OFF_PORT, "/many")
    our_sz = {n: sz for n, sz, *_ in our_e}
    off_sz = {n: sz for n, sz, *_ in off_e}
    for name in sorted(our_sz):
        real = os.path.getsize(os.path.join(srv["our_data"], "many", name))
        assert our_sz[name] == real, \
            f"our dstat /many {name} size={our_sz[name]} real={real}"
        assert our_sz[name] == off_sz.get(name), \
            f"dstat /many {name} size divergence: ours={our_sz[name]} stock={off_sz.get(name)}"


@pytest.mark.parametrize("name,size", [
    ("hello.txt", 12), ("data.bin", 4096), ("empty.txt", 0),
    ("cksum.bin", 10000), ("big1m.bin", 1048576),
])
def test_wire_dstat_root_known_sizes(srv, name, size):
    _, our_e = _wire_dstat(OUR_PORT, "/")
    _, off_e = _wire_dstat(OFF_PORT, "/")
    our_sz = {n: sz for n, sz, *_ in our_e}
    off_sz = {n: sz for n, sz, *_ in off_e}
    assert our_sz.get(name) == size, f"our dstat / {name} size={our_sz.get(name)} want {size}"
    assert off_sz.get(name) == size, f"stock dstat / {name} size={off_sz.get(name)} want {size}"


# =========================================================================== #
# 18) dirlist WITH-STAT — directory entries carry the IsDir flag bit on both
# =========================================================================== #
def test_wire_dstat_isdir_flag(srv):
    """In /mixed dstat, subA/subB are flagged IsDir and files are not, on both."""
    _, our_e = _wire_dstat(OUR_PORT, "/mixed")
    _, off_e = _wire_dstat(OFF_PORT, "/mixed")
    our_fl = {n: fl for n, _sz, fl, _ck in our_e}
    off_fl = {n: fl for n, _sz, fl, _ck in off_e}
    for d in ("subA", "subB"):
        assert our_fl.get(d) is not None and our_fl[d] & kXR_isDir, \
            f"our dstat /mixed {d} not flagged IsDir: flags={our_fl.get(d)}"
        assert off_fl.get(d) is not None and off_fl[d] & kXR_isDir, \
            f"stock dstat /mixed {d} not flagged IsDir: flags={off_fl.get(d)}"
    for fil in ("file1.txt", "file2.bin"):
        assert not (our_fl.get(fil, 0) & kXR_isDir), \
            f"our dstat /mixed {fil} wrongly flagged IsDir: {our_fl.get(fil)}"
        assert not (off_fl.get(fil, 0) & kXR_isDir), \
            f"stock dstat /mixed {fil} wrongly flagged IsDir: {off_fl.get(fil)}"


# =========================================================================== #
# 19) dstat flags presence parity — every entry carries a non-empty stat line
# =========================================================================== #
@pytest.mark.parametrize("path", ["/many", "/mixed"])
def test_wire_dstat_flags_present_each_entry(srv, path):
    for port, who in ((OUR_PORT, "our"), (OFF_PORT, "stock")):
        _, entries = _wire_dstat(port, path)
        assert entries, f"{who} dstat {path} returned no entries"
        for name, size, flags, _ck in entries:
            assert size is not None, f"{who} dstat {path} {name} missing size field"
            assert flags is not None, f"{who} dstat {path} {name} missing flags field"


# =========================================================================== #
# 20) dstat mtime presence parity — the stat line has the 4th (mtime) int field
# =========================================================================== #
def test_wire_dstat_mtime_field_present(srv):
    """The per-entry stat line is 'id size flags mtime' -> >=4 leading ints, on
    both servers (StatGen)."""
    def quad_ok(port, path):
        s = _session(port)
        try:
            _dirlist_raw(s, path, options=kXR_dstat)
            body = _drain_dirlist(s)
        finally:
            s.close()
        text = body.replace(b"\x00", b"\n").decode("utf-8", "replace")
        lines = [l for l in text.split("\n") if l]
        # find the stat line for the first real entry after the sentinel
        # sentinel = lines[0]=="." , lines[1]=="0 0 0 0"
        idx = 2 if (len(lines) >= 2 and lines[0] == ".") else 0
        # entry name at idx, stat line at idx+1
        if idx + 1 >= len(lines):
            return False
        toks = lines[idx + 1].split()
        return len(toks) >= 4 and all(t.lstrip("-").isdigit() for t in toks[:4])
    assert quad_ok(OFF_PORT, "/many"), "stock dstat stat line lacks 4 leading ints"
    assert quad_ok(OUR_PORT, "/many"), "our dstat stat line lacks 4 leading ints (stock has it)"


# =========================================================================== #
# 21) dirlist WITH-CHECKSUM (kXR_dcksm) on /many — each entry carries a token,
#     spot-checked == zlib.adler32 of that file. If stock errors on dcksm (no
#     plugin), pin OUR output against the independent computation + require OUR
#     success.
# =========================================================================== #
def _adler32_hex(path):
    with open(path, "rb") as f:
        return f"{zlib.adler32(f.read()) & 0xffffffff:08x}"


def test_wire_dcksm_tokens_and_value(srv):
    # OUR server: every entry must carry a checksum token, and a spot-checked
    # one must equal the independent adler32 of that file.
    try:
        _, our_e = _wire_dstat(OUR_PORT, "/many", with_cksum=True)
    except _DirlistError as e:
        pytest.fail(f"our server errored on kXR_dcksm dirlist (errnum={e.errnum})")
    assert our_e, "our dcksm dirlist returned no entries"
    for name, _sz, _fl, ck in our_e:
        assert ck, f"our dcksm /many {name} missing checksum token: {ck!r}"

    # spot-check one entry's value against an independent adler32
    spot = "f00.txt"
    our_map = {n: ck for n, _s, _f, ck in our_e}
    assert spot in our_map, f"{spot} absent from our dcksm output"
    want = _adler32_hex(os.path.join(srv["our_data"], "many", spot))
    got_field = our_map[spot]
    # token form is "algo:value"; extract the hex value
    got = got_field.split(":")[-1].strip().lower()
    assert got == want, \
        f"our dcksm /many {spot} adler32={got!r} expected {want!r} (full token {got_field!r})"

    # STOCK comparison if its data server supports dcksm; else just pin ours.
    try:
        _, off_e = _wire_dstat(OFF_PORT, "/many", with_cksum=True)
        off_map = {n: (ck or "") for n, _s, _f, ck in off_e}
        if off_map.get(spot) and ":" in off_map[spot] and \
           off_map[spot].split(":")[-1].strip().lower() not in ("none", ""):
            off_val = off_map[spot].split(":")[-1].strip().lower()
            assert got == off_val, \
                f"dcksm /many {spot} value divergence: ours={got!r} stock={off_val!r}"
    except _DirlistError:
        # stock lacks the plugin -> ours is pinned to the independent value above
        pass


def test_wire_dcksm_every_entry_has_token(srv):
    """Across /mixed files, OUR dcksm gives a token per regular file entry."""
    try:
        _, our_e = _wire_dstat(OUR_PORT, "/mixed", with_cksum=True)
    except _DirlistError as e:
        pytest.fail(f"our server errored on kXR_dcksm /mixed (errnum={e.errnum})")
    by = {n: ck for n, _s, _f, ck in our_e}
    for fil in ("file1.txt", "file2.bin"):
        assert by.get(fil), f"our dcksm /mixed {fil} missing checksum token: {by.get(fil)!r}"


# =========================================================================== #
# 22) dcksm implies dstat — the response still has the sentinel + sizes on ours
# =========================================================================== #
def test_wire_dcksm_implies_dstat(srv):
    try:
        sent, entries = _wire_dstat(OUR_PORT, "/many", with_cksum=True)
    except _DirlistError as e:
        pytest.fail(f"our dcksm dirlist errored (errnum={e.errnum})")
    assert sent, "our dcksm dirlist lacks the '.' lead-in sentinel (dcksm implies dstat)"
    sizes = {n: sz for n, sz, _f, _c in entries}
    spot = "f05.txt"
    real = os.path.getsize(os.path.join(srv["our_data"], "many", spot))
    assert sizes.get(spot) == real, \
        f"our dcksm /many {spot} size={sizes.get(spot)} real={real} (dstat info missing)"


# =========================================================================== #
# 23) plain vs dstat name-set agreement on OUR server (internal consistency,
#     each pinned to stock's plain set)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/many", "/mixed", "/sub"])
def test_plain_and_dstat_agree(srv, path):
    plain = _wire_plain_names(OUR_PORT, path)
    _, dstat_e = _wire_dstat(OUR_PORT, path)
    dstat_names = {n for n, *_ in dstat_e}
    assert plain == dstat_names, \
        f"our plain vs dstat name divergence {path}: plain-only={plain - dstat_names} " \
        f"dstat-only={dstat_names - plain}"
    # and both equal stock's plain set
    off_plain = _wire_plain_names(OFF_PORT, path)
    assert plain == off_plain, f"plain {path} divergence vs stock: {plain ^ off_plain}"


# =========================================================================== #
# 24) special-name dir under dstat — spaced/dotted names survive intact + size
# =========================================================================== #
def test_wire_dstat_special_names(srv):
    _, our_e = _wire_dstat(OUR_PORT, "/special")
    _, off_e = _wire_dstat(OFF_PORT, "/special")
    our_names = {n for n, *_ in our_e}
    off_names = {n for n, *_ in off_e}
    expected = set(SPECIAL_NAMES)
    assert our_names == expected, \
        f"our dstat /special name-set wrong: missing={expected - our_names} extra={our_names - expected}"
    assert off_names == expected, f"stock dstat /special name-set wrong: {off_names ^ expected}"
    # a spaced name carries its real size on ours
    our_sz = {n: sz for n, sz, *_ in our_e}
    real = os.path.getsize(os.path.join(srv["our_data"], "special", "with space"))
    assert our_sz.get("with space") == real, \
        f"our dstat /special 'with space' size={our_sz.get('with space')} real={real}"

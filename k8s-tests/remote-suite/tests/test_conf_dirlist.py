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

OUR_PORT = L.worker_port(14028)
OFF_PORT = L.worker_port(14029)
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


def _build_extra_dirs(root):
    """Create the additional trees this module needs, identically on a root."""
    j = os.path.join
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


def _last_integer(tokens):
    value = None
    for token in tokens:
        if token.isdigit():
            value = int(token)
    return value


def _listed_basename(path):
    base = os.path.basename(path.rstrip("/"))
    if not base or _is_artifact(base):
        return None
    return base


def _ls_l_row(line):
    tokens = line.split()
    if len(tokens) < 2:
        return None
    path = tokens[-1]
    base = _listed_basename(path)
    if base is None:
        return None
    size = _last_integer(tokens[:-1])
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


def _dstat_lines(body):
    text = body.replace(b"\x00", b"\n").decode("utf-8", "replace")
    stripped = text.rstrip("\n")
    if not stripped:
        return []
    return stripped.split("\n")


def _has_dstat_sentinel(lines):
    if len(lines) < 2 or lines[0] != ".":
        return False
    return lines[1].split() == ["0", "0", "0", "0"]


def _split_stat_checksum(statline, with_cksum):
    if not with_cksum or "[" not in statline:
        return statline, None
    prefix, _, suffix = statline.partition("[")
    return prefix, suffix.rstrip("]").strip()


def _integer_field(tokens, index):
    if index >= len(tokens):
        return None
    value = tokens[index]
    if not value.lstrip("-").isdigit():
        return None
    return int(value)


def _parse_dstat_entry(name, statline, with_cksum):
    if _is_artifact(name):
        return None
    stat_fields, checksum = _split_stat_checksum(statline, with_cksum)
    tokens = stat_fields.split()
    size = _integer_field(tokens, 1)
    flags = _integer_field(tokens, 2)
    return name, size, flags, checksum


def _dstat_pairs(lines, offset):
    return zip(lines[offset::2], lines[offset + 1::2])


def _parse_dstat(body, with_cksum=False):
    """Parse a kXR_dstat body into (had_sentinel, [(name, size, flags, cksum)]).

    Layout: ".\n0 0 0 0\n" lead-in sentinel, then per entry
      "<name>\n<id> <size> <flags> <mtime>[ [ algo:value ]]\n".
    """
    lines = _dstat_lines(body)
    had_sentinel = _has_dstat_sentinel(lines)
    offset = 2 if had_sentinel else 0
    entries = []
    for name, statline in _dstat_pairs(lines, offset):
        entry = _parse_dstat_entry(name, statline, with_cksum)
        if entry is not None:
            entries.append(entry)
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


def _assert_expected_names(actual, expected, label):
    assert actual == expected, f"{label}: got {actual!r}, expected {expected!r}"


def _assert_contains_names(actual, expected, label):
    assert expected <= actual, f"{label}: got {actual!r}, expected at least {expected!r}"


def _assert_dstat_size(name, actual, stock, real):
    assert actual == real, f"our dstat /many {name} size={actual} real={real}"
    assert actual == stock, (
        f"dstat /many {name} size divergence: ours={actual} stock={stock}"
    )


def _assert_named_size(sizes, name, real, label):
    assert sizes.get(name) == real, (
        f"{label} {name!r} size={sizes.get(name)} real={real}"
    )


def _flag_map(entries):
    return {name: flags for name, _size, flags, _checksum in entries}


def _assert_directory_flag(name, our_flags, stock_flags):
    assert our_flags.get(name) is not None and our_flags[name] & kXR_isDir, (
        f"our dstat /mixed {name} not IsDir: {our_flags.get(name)}"
    )
    assert stock_flags.get(name) is not None and stock_flags[name] & kXR_isDir, (
        f"stock dstat /mixed {name} not IsDir: {stock_flags.get(name)}"
    )


def _assert_regular_file_flag(name, our_flags, stock_flags):
    assert not (our_flags.get(name, 0) & kXR_isDir), (
        f"our dstat /mixed {name} wrongly IsDir: {our_flags.get(name)}"
    )
    assert not (stock_flags.get(name, 0) & kXR_isDir), (
        f"stock dstat /mixed {name} wrongly IsDir: {stock_flags.get(name)}"
    )


def _first_entry_stat_line(lines):
    offset = 2 if _has_dstat_sentinel(lines) else 0
    if offset + 1 >= len(lines):
        return ""
    return lines[offset + 1]


def _leading_integer_quad(statline):
    tokens = statline.split()
    if len(tokens) < 4:
        return False
    return all(token.lstrip("-").isdigit() for token in tokens[:4])


def _dstat_quad_ok(port, path):
    session = _session(port)
    try:
        _dirlist_raw(session, path, options=kXR_dstat)
        body = _drain_dirlist(session)
    finally:
        session.close()
    return _leading_integer_quad(_first_entry_stat_line(_dstat_lines(body)))


def _required_dcksm_entries(port, path, label):
    try:
        _, entries = _wire_dstat(port, path, with_cksum=True)
    except _DirlistError as error:
        pytest.fail(f"{label} errored on kXR_dcksm (errnum={error.errnum})")
    return entries


def _assert_checksum_tokens(entries, label):
    assert entries, f"{label} returned no entries"
    for name, _size, _flags, checksum in entries:
        assert checksum, f"{label} {name} missing checksum token: {checksum!r}"


def _checksum_map(entries):
    return {name: (checksum or "") for name, _size, _flags, checksum in entries}


def _checksum_value(field):
    return field.split(":")[-1].strip().lower()


def _assert_spot_checksum(srv, checksums, spot):
    assert spot in checksums, f"{spot} absent from our dcksm output"
    expected = _adler32_hex(os.path.join(srv["our_data"], "many", spot))
    actual = _checksum_value(checksums[spot])
    assert actual == expected, (
        f"our dcksm /many {spot} adler32={actual!r} expected {expected!r} "
        f"(full token {checksums[spot]!r})"
    )
    return actual


def _optional_stock_checksum(spot):
    try:
        _, entries = _wire_dstat(OFF_PORT, "/many", with_cksum=True)
    except _DirlistError:
        return None
    field = _checksum_map(entries).get(spot, "")
    if not field or ":" not in field:
        return None
    value = _checksum_value(field)
    if value in ("none", ""):
        return None
    return value


def _load_continuation(filename):
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, encoding="utf-8") as source:
        exec(compile(source.read(), path, "exec"), globals())


_load_continuation("_test_conf_dirlist_cases.py")


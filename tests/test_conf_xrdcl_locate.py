"""Differential conformance for XrdCl::FileSystem locate / deeplocate / query —
driven through the REAL libXrdCl bindings (``from XRootD import client``, hosted
out-of-process by the tests/_xrdcl_worker proxy) against BOTH our nginx-xrootd
server AND the stock xrootd data server, on identical data trees.

This is exactly gfal/FTS/Rucio's code path: they call ``FileSystem::Locate`` /
``DeepLocate`` / ``Query`` and parse the binding result objects (LocationInfo,
raw query buffers). A divergence from stock is treated as a BUG IN OUR SERVER
(stock is truth), unless there is positive evidence otherwise (e.g. the bare
stock data server simply lacks a checksum/prepare plugin, in which case we pin
OUR value against an INDEPENDENT reference rather than against the stock error).

Contract citations (consulted, never modified):
  * LocationInfo wire parse — XrdClXRootDResponses.cc:26 (ProcessLocation):
    space-split; token[0] = type char M/m/S/s (ManagerOnline/ManagerPending/
    ServerOnline/ServerPending), token[1] = access char r (Read) / w (ReadWrite),
    rest = host:port; a bad type/access char makes XrdCl reject the WHOLE
    response; a token shorter than its 2-char prefix + host is rejected.
    LocationType enum — XrdClXRootDResponses.hh:49  (0=ManagerOnline,
    1=ManagerPending, 2=ServerOnline, 3=ServerPending).
    AccessType enum   — XrdClXRootDResponses.hh:60  (0=Read, 1=ReadWrite).
  * QueryCode enum — XrdClFileSystem.hh:48 (Config/ChecksumCancel/Checksum/
    Opaque/OpaqueFile/Prepare/Space/Stats/Visa/XAttr/...).
  * do_Qconf bare-value format / unknown-key echo / role / sitename cases —
    XrdXrootd/XrdXrootdXeq.cc:2168-2268.
  * do_Query reqcode dispatch (Qvisa has NO case -> rejected; Qprep ->
    do_Prepare(true) -> unknown reqid rejected) — XrdXrootdXeq.cc::do_Query.

Because the binding REJECTS the entire locate response on a single malformed
token, ``status.ok`` on a locate is itself a strong structural assertion: it
proves every emitted token had a valid type char, a valid access char, and a
non-empty host:port. We additionally compare the parsed type/access enum values
our-vs-stock, and parity of status.ok / errno across the whole tree.

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisions both servers
on high ports; skips cleanly when the stock toolchain or the bindings are absent.
"""

import os
import zlib
import hashlib

import pytest

import official_interop_lib as L

# The bindings are reached through the in-repo shadow XRootD package (proxy to
# an out-of-process real-libXrdCl worker). If neither the shadow nor the real
# package import, skip the whole module rather than ERROR.
try:
    from XRootD import client
    from XRootD.client.flags import OpenFlags, QueryCode
    _HAVE_BINDINGS = True
except Exception:  # noqa: BLE001 - any import failure -> skip module
    _HAVE_BINDINGS = False

pytestmark = [
    pytest.mark.timeout(360),
    pytest.mark.skipif(not L.have_official(),
                       reason="stock xrootd/xrdfs/xrdcp not installed"),
    pytest.mark.skipif(not _HAVE_BINDINGS,
                       reason="XRootD python bindings (proxy) unavailable"),
]


# --------------------------------------------------------------------------- #
# Module-scoped server pair on the assigned port range.                       #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confxrdcllocate"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14916), off_port=L.worker_port(14917))
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    except Exception as e:  # noqa: BLE001 - any launch failure -> skip
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


@pytest.fixture(scope="module")
def fs_our(srv):
    return client.FileSystem(srv["our"])


@pytest.fixture(scope="module")
def fs_off(srv):
    return client.FileSystem(srv["off"])


# --------------------------------------------------------------------------- #
# LocationInfo enum constants (XrdClXRootDResponses.hh).                       #
# --------------------------------------------------------------------------- #
LT_MGR_ONLINE, LT_MGR_PENDING, LT_SRV_ONLINE, LT_SRV_PENDING = 0, 1, 2, 3
ACC_READ, ACC_READWRITE = 0, 1


# Tree contents (make_rich_tree). Each entry: (path, is_dir).
TREE_FILES = [
    "/hello.txt", "/data.bin", "/empty.txt", "/sub/nested.txt",
    "/deep/a/b/c/leaf.txt", "/with space.txt", "/cksum.bin", "/big1m.bin",
    "/sz_1.bin", "/sz_255.bin", "/sz_4095.bin", "/sz_4096.bin",
    "/sz_4097.bin", "/sz_8192.bin", "/sz_65536.bin",
    "/many/f00.txt", "/many/f05.txt", "/many/f11.txt",
]
TREE_DIRS = ["/", "/sub", "/deep", "/deep/a", "/deep/a/b", "/deep/a/b/c",
             "/empty_dir", "/many"]
TREE_MISSING = ["/nope.bin", "/sub/missing.txt", "/deep/a/zzz/none.txt",
                "/no_such_dir/", "/missing_top_level"]

# The binding exposes a subset of OpenFlags; PREFNAME is absent in some builds,
# so we fall back to FORCE (also a benign locate hint) to keep three variants.
_THIRD_FLAG = ("PREFNAME", getattr(OpenFlags, "PREFNAME", None))
if _THIRD_FLAG[1] is None:
    _THIRD_FLAG = ("FORCE", OpenFlags.FORCE)

LOCATE_FLAGS = [
    ("NONE", OpenFlags.NONE),
    ("REFRESH", OpenFlags.REFRESH),
    _THIRD_FLAG,
]


# --------------------------------------------------------------------------- #
# Helpers.                                                                     #
# --------------------------------------------------------------------------- #
def _locs(loc):
    """LocationInfo -> list of (type, accesstype, address) tuples."""
    out = []
    if loc:
        for l in loc:
            out.append((l.type, l.accesstype, l.address))
    return out


def _read_bytes(ctx, path):
    with open(os.path.join(ctx["our_data"], path.lstrip("/")), "rb") as f:
        return f.read()


def ref_adler32(data):
    return f"{zlib.adler32(data) & 0xffffffff:08x}"


def ref_crc32(data):
    return f"{zlib.crc32(data) & 0xffffffff:08x}"


def _crc32c_table():
    poly = 0x82F63B78
    tab = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ poly if (c & 1) else (c >> 1)
        tab.append(c & 0xFFFFFFFF)
    return tab


_CRC32C_TAB = _crc32c_table()


def ref_crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TAB[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return f"{crc ^ 0xFFFFFFFF:08x}"


# =========================================================================== #
# 1. LOCATE — every tree FILE, every flag. The binding rejects the whole       #
#    response on a single malformed token, so status.ok already proves the     #
#    type/access chars and host:port are well-formed.                          #
# =========================================================================== #
@pytest.mark.parametrize("path", TREE_FILES)
@pytest.mark.parametrize("flagname,flag", LOCATE_FLAGS)
def test_locate_file_ok_both(srv, fs_our, fs_off, path, flagname, flag):
    """locate(<file>) must PARSE WITHOUT ERROR on BOTH servers for every flag —
    a single bad type/access char or short token would make XrdCl reject the
    whole response and set status.ok=False (XrdClXRootDResponses.cc:26)."""
    st_o, loc_o = fs_our.locate(path, flag)
    st_f, loc_f = fs_off.locate(path, flag)
    assert st_o.ok, (f"OUR locate {path!r} ({flagname}) not ok "
                     f"(malformed LocationInfo token?): code={st_o.code} "
                     f"errno={st_o.errno} {st_o.message!r}")
    assert st_f.ok == st_o.ok, (
        f"locate ok-parity differs for {path!r} ({flagname}): "
        f"our={st_o.ok} stock={st_f.ok}")
    assert len(loc_o) >= 1, f"OUR locate {path!r} returned no locations"


@pytest.mark.parametrize("path", TREE_FILES)
def test_locate_file_type_char_is_server(srv, fs_our, fs_off, path):
    """Every located file lives on a SERVER node — the type char must be S/s
    (ServerOnline/ServerPending), never M/m, and must MATCH stock. A direct
    data server never advertises a Manager location for a real file."""
    _, loc_o = fs_our.locate(path, OpenFlags.NONE)
    _, loc_f = fs_off.locate(path, OpenFlags.NONE)
    types_o = {t for t, _, _ in _locs(loc_o)}
    types_f = {t for t, _, _ in _locs(loc_f)}
    assert types_o <= {LT_SRV_ONLINE, LT_SRV_PENDING}, (
        f"OUR locate {path!r} advertised a non-server type char: {types_o}")
    assert types_o == types_f, (
        f"locate type-char differs for {path!r}: our={types_o} stock={types_f}")


@pytest.mark.parametrize("path", TREE_FILES)
def test_locate_file_access_char_matches_stock(srv, fs_our, fs_off, path):
    """The access char (r=Read / w=ReadWrite) must MATCH stock for every file.
    Both servers run anon + allow_write, so a writable file should report 'w'
    on both; a divergence in the writability char is a real bug."""
    _, loc_o = fs_our.locate(path, OpenFlags.NONE)
    _, loc_f = fs_off.locate(path, OpenFlags.NONE)
    acc_o = {a for _, a, _ in _locs(loc_o)}
    acc_f = {a for _, a, _ in _locs(loc_f)}
    assert acc_o <= {ACC_READ, ACC_READWRITE}, (
        f"OUR locate {path!r} has an out-of-range access type: {acc_o}")
    assert acc_o == acc_f, (
        f"locate access-char differs for {path!r}: "
        f"our={acc_o} stock={acc_f} (writability mismatch)")


@pytest.mark.parametrize("path", TREE_FILES)
def test_locate_file_address_nonempty(srv, fs_our, path):
    """Each location's host:port (token.substr(2)) must be non-empty — a token
    with no host after the 2-char prefix is malformed (length < 5 check in
    ProcessLocation). The address is host-specific so we assert presence + a
    ':' separator, not literal parity with stock."""
    _, loc_o = fs_our.locate(path, OpenFlags.NONE)
    locs = _locs(loc_o)
    assert locs, f"OUR locate {path!r} produced zero locations"
    for _, _, addr in locs:
        assert addr and ":" in addr, \
            f"OUR locate {path!r} address malformed: {addr!r}"


# =========================================================================== #
# 2. LOCATE — directories. A directory is a valid namespace object; locate of  #
#    a dir must behave identically (ok-parity, type/access parity) to stock.    #
# =========================================================================== #
@pytest.mark.parametrize("path", TREE_DIRS)
@pytest.mark.parametrize("flagname,flag", LOCATE_FLAGS)
def test_locate_dir_parity(srv, fs_our, fs_off, path, flagname, flag):
    """locate(<dir>) ok-parity + type/access parity our-vs-stock for every flag."""
    st_o, loc_o = fs_our.locate(path, flag)
    st_f, loc_f = fs_off.locate(path, flag)
    assert st_o.ok == st_f.ok, (
        f"locate dir ok-parity differs for {path!r} ({flagname}): "
        f"our={st_o.ok}({st_o.errno}) stock={st_f.ok}({st_f.errno})")
    if st_o.ok and st_f.ok:
        sig_o = {(t, a) for t, a, _ in _locs(loc_o)}
        sig_f = {(t, a) for t, a, _ in _locs(loc_f)}
        assert sig_o == sig_f, (
            f"locate dir type/access differs for {path!r} ({flagname}): "
            f"our={sig_o} stock={sig_f}")


# =========================================================================== #
# 3. LOCATE — missing paths. ok-parity AND errno parity (the binding surfaces  #
#    the server's XErrorCode as status.errno). A NotFound must be NotFound on   #
#    both, not silently ok=True.                                                #
# =========================================================================== #
@pytest.mark.parametrize("path", TREE_MISSING)
@pytest.mark.parametrize("flagname,flag", LOCATE_FLAGS)
def test_locate_missing_parity(srv, fs_our, fs_off, path, flagname, flag):
    """locate(<missing>) must FAIL on OUR server and match stock's ok-category
    and errno (XErrorCode). Silently succeeding on a missing path is a bug."""
    st_o, _ = fs_our.locate(path, flag)
    st_f, _ = fs_off.locate(path, flag)
    assert not st_o.ok, (
        f"OUR locate missing {path!r} ({flagname}) succeeded (BUG): "
        f"code={st_o.code}")
    assert st_o.ok == st_f.ok, (
        f"locate missing ok-parity differs for {path!r} ({flagname}): "
        f"our={st_o.ok} stock={st_f.ok}")
    assert st_o.errno == st_f.errno, (
        f"locate missing errno differs for {path!r} ({flagname}): "
        f"our={st_o.errno} stock={st_f.errno}")


# =========================================================================== #
# 4. DEEPLOCATE — recursive locate; on a single data server it resolves to the #
#    same server location. ok-parity + type/access parity our-vs-stock.        #
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sub/nested.txt",
                                  "/deep/a/b/c/leaf.txt", "/cksum.bin"])
def test_deeplocate_file_parity(srv, fs_our, fs_off, path):
    """deeplocate(<file>) ok + type/access parity our-vs-stock."""
    st_o, loc_o = fs_our.deeplocate(path, OpenFlags.NONE)
    st_f, loc_f = fs_off.deeplocate(path, OpenFlags.NONE)
    assert st_o.ok, (f"OUR deeplocate {path!r} not ok: code={st_o.code} "
                     f"{st_o.message!r}")
    assert st_o.ok == st_f.ok, (
        f"deeplocate ok-parity differs for {path!r}: "
        f"our={st_o.ok} stock={st_f.ok}")
    sig_o = {(t, a) for t, a, _ in _locs(loc_o)}
    sig_f = {(t, a) for t, a, _ in _locs(loc_f)}
    assert sig_o == sig_f, (
        f"deeplocate type/access differs for {path!r}: "
        f"our={sig_o} stock={sig_f}")


@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/cksum.bin"])
def test_deeplocate_refresh_parity(srv, fs_our, fs_off, path):
    """deeplocate with REFRESH must not change the ok-category our-vs-stock."""
    st_o, _ = fs_our.deeplocate(path, OpenFlags.REFRESH)
    st_f, _ = fs_off.deeplocate(path, OpenFlags.REFRESH)
    assert st_o.ok == st_f.ok, (
        f"deeplocate REFRESH ok-parity differs for {path!r}: "
        f"our={st_o.ok} stock={st_f.ok}")


@pytest.mark.parametrize("path", TREE_MISSING)
def test_deeplocate_missing_parity(srv, fs_our, fs_off, path):
    """deeplocate(<missing>) must fail and match stock's ok-category."""
    st_o, _ = fs_our.deeplocate(path, OpenFlags.NONE)
    st_f, _ = fs_off.deeplocate(path, OpenFlags.NONE)
    assert not st_o.ok, f"OUR deeplocate missing {path!r} succeeded (BUG)"
    assert st_o.ok == st_f.ok, (
        f"deeplocate missing ok-parity differs for {path!r}: "
        f"our={st_o.ok} stock={st_f.ok}")


# =========================================================================== #
# 5. QUERY CONFIG — broad key list, bare-value format (do_Qconf). Each known   #
#    key -> a bare value '\n'-terminated (NEVER "key=..."); an unknown key is   #
#    ECHOED verbatim + '\n'. Numeric keys are integer lines.                   #
# =========================================================================== #
# Keys whose SHAPE we pin on OUR server (bare value, no "key=").
QCONFIG_KEYS = [
    "bind_max", "readv_ior_max", "readv_iov_max", "chksum", "version",
    "role", "pio_max", "tpc", "tpcdlg", "sitename", "cms", "cid", "fattr",
]
QCONFIG_NUMERIC = ["bind_max", "readv_ior_max", "readv_iov_max", "pio_max"]


def _q(fs, key):
    st, r = fs.query(QueryCode.CONFIG, key)
    text = (r or b"").rstrip(b"\x00").decode("latin-1") if r else ""
    return st, text


@pytest.mark.parametrize("key", QCONFIG_KEYS)
def test_qconfig_bare_value_no_keyeq(srv, fs_our, key):
    """do_Qconf emits a bare value + '\\n', never "<key>=...". OUR server must
    answer every key with a non-empty, newline-terminated, bare value line."""
    st, text = _q(fs_our, key)
    assert st.ok, f"OUR query config {key} failed: code={st.code}"
    assert text.strip() != "", f"OUR query config {key} empty"
    assert "\n" in text, f"OUR query config {key} not newline-terminated: {text!r}"
    line = text.strip().splitlines()[0].strip()
    assert not line.startswith(f"{key}="), \
        f"OUR query config {key} has a key= prefix (BUG): {line!r}"
    first = line.split()[0] if line.split() else ""
    assert "=" not in first, \
        f"OUR query config {key} first token looks like key=value: {first!r}"


@pytest.mark.parametrize("key", QCONFIG_NUMERIC)
def test_qconfig_numeric_integer(srv, fs_our, key):
    """Numeric do_Qconf keys (snprintf("%d\\n")) must be an integer first token."""
    st, text = _q(fs_our, key)
    assert st.ok, f"OUR query config {key} failed: code={st.code}"
    first = text.strip().split()[0] if text.strip().split() else ""
    assert first.lstrip("-").isdigit(), \
        f"OUR query config {key} not an integer: {text!r}"


@pytest.mark.parametrize("key", QCONFIG_NUMERIC)
def test_qconfig_numeric_value_parity(srv, fs_our, fs_off, key):
    """Numeric protocol-limit keys (bind_max / readv_ior_max / readv_iov_max /
    pio_max) advertise wire LIMITS the client relies on — these must EQUAL stock
    exactly (a smaller readv_iov_max would silently truncate gfal's vector reads)."""
    st_o, text_o = _q(fs_our, key)
    st_f, text_f = _q(fs_off, key)
    assert st_o.ok and st_f.ok, f"query config {key} failed (our/stock)"
    v_o = text_o.strip().split()[0]
    v_f = text_f.strip().split()[0]
    assert v_o == v_f, (
        f"query config {key} value differs our={v_o!r} stock={v_f!r} "
        f"(advertised wire limit mismatch)")


# `role`/`sitename`/`fattr` are known do_Qconf keys OUR config.c does not yet
# implement (it echoes them), so they would fail the integer-shape parity below;
# they get dedicated pinned-divergence tests instead.
QCONFIG_SHAPE_KEYS = [k for k in QCONFIG_KEYS
                      if k not in ("role", "sitename", "fattr")]


@pytest.mark.parametrize("key", QCONFIG_SHAPE_KEYS)
def test_qconfig_shape_parity(srv, fs_our, fs_off, key):
    """Differential SHAPE: where stock answers a key, OUR answer must share the
    shape — neither uses "key=", and if stock's value is an integer ours is too.
    The literal value may legitimately differ (build/site/role)."""
    st_o, text_o = _q(fs_our, key)
    st_f, text_f = _q(fs_off, key)
    assert st_o.ok, f"OUR query config {key} failed"
    if not st_f.ok:
        pytest.skip(f"stock did not answer config {key}")
    line_o = text_o.strip().splitlines()[0].strip() if text_o.strip() else ""
    line_f = text_f.strip().splitlines()[0].strip() if text_f.strip() else ""
    assert not line_o.startswith(f"{key}="), \
        f"OUR config {key} uses key= but stock does not: {line_o!r}"
    f_first = line_f.split()[0] if line_f.split() else ""
    o_first = line_o.split()[0] if line_o.split() else ""
    if f_first.lstrip("-").isdigit():
        assert o_first.lstrip("-").isdigit(), (
            f"stock config {key} is integer ({line_f!r}) but OUR is not "
            f"({line_o!r})")


def test_qconfig_version_v_prefixed(srv, fs_our):
    """version -> XrdVSTRING, a 'v'-prefixed dotted version (do_Qconf). The value
    differs from stock (different build) — pin only the canonical shape."""
    st, text = _q(fs_our, "version")
    assert st.ok, "OUR query config version failed"
    head = text.strip().splitlines()[0].split()[0]
    assert head[:1].lower() == "v" and "." in head and any(c.isdigit() for c in head), \
        f"OUR version not a v-prefixed dotted string: {head!r}"


def test_qconfig_unknown_key_echoed_bare(srv, fs_our, fs_off):
    """do_Qconf default branch ECHOES an unknown key verbatim + '\\n' (not an
    error, not "key=0"). OUR server must echo it, and match stock's echo."""
    bogus = "no_such_config_key_xyzzy"
    st_o, text_o = _q(fs_our, bogus)
    st_f, text_f = _q(fs_off, bogus)
    assert st_o.ok, f"OUR unknown config key errored (BUG): code={st_o.code}"
    assert text_o.strip() == bogus, \
        f"OUR did not echo unknown key bare (BUG): {text_o.strip()!r}"
    if st_f.ok:
        assert text_f.strip() == bogus, \
            f"stock echoed unknown key differently: {text_f.strip()!r}"


def test_qconfig_chksum_advertises_adler32(srv, fs_our):
    """chksum -> bare cslist; OUR server must advertise adler32 (the default it
    then answers). Stock's bare data server has no checksum plugin and echoes
    'chksum', so this is pinned on OUR value, not differential."""
    st, text = _q(fs_our, "chksum")
    assert st.ok, "OUR query config chksum failed"
    line = text.strip()
    assert not line.startswith("chksum="), \
        f"OUR chksum config has key= prefix (BUG): {line!r}"
    advertised = {a.strip() for a in line.replace("\n", ",").split(",") if a.strip()}
    assert "adler32" in advertised, \
        f"OUR chksum config does not advertise adler32: {advertised}"


def test_qconfig_multikey_one_line_per_key(srv, fs_our):
    """Multiple keys in one Config query -> one bare line per key, in request
    order (do_Qconf loops GetToken and appends "%s\\n" per token)."""
    keys = "bind_max readv_iov_max version"
    st, r = fs_our.query(QueryCode.CONFIG, keys)
    assert st.ok, "OUR multi-key query config failed"
    body = (r or b"").rstrip(b"\x00").decode("latin-1")
    lines = [l for l in body.split("\n") if l != ""]
    assert len(lines) == 3, \
        f"OUR multi-key expected 3 lines, got {len(lines)}: {body!r}"
    assert lines[0].split()[0].lstrip("-").isdigit(), \
        f"bind_max line not integer-first: {lines[0]!r}"
    assert lines[1].split()[0].lstrip("-").isdigit(), \
        f"readv_iov_max line not integer-first: {lines[1]!r}"


# --- do_Qconf coverage (FIXED: role/fattr cases added to src/protocols/root/query/config.c) - #
# query config `role` — stock recognises `role` (do_Qconf, XrdXrootdXeq.cc:2216
# -> "%s\n" of XRDROLE, e.g. "server"/"none").  src/protocols/root/query/config.c now emits
# "server" (or "manager" in manager mode) instead of echoing the key.
def test_qconfig_role_recognised_like_stock(srv, fs_our, fs_off):
    """`role` is a known do_Qconf key on stock; OUR server must not echo it back
    as if it were unknown."""
    st_o, text_o = _q(fs_our, "role")
    st_f, text_f = _q(fs_off, "role")
    assert st_o.ok and st_f.ok
    line_o = text_o.strip()
    line_f = text_f.strip()
    # Stock returns the role string; ours must not be a verbatim echo of "role".
    assert not (line_f != "role" and line_o == "role"), (
        f"OUR echoed unknown key for known config `role` "
        f"(our={line_o!r} stock={line_f!r})")


# DIVERGENCE: query config `sitename` — do_Qconf (XrdXrootdXeq.cc:2221) returns
# the configured site name or the literal "sitename" when XRDSITE is unset; OUR
# server has no `sitename` case and echoes the key. Here both happen to yield
# "sitename" (neither has XRDSITE set), so this case is a shape probe only and
# stays green; it documents the missing case.
def test_qconfig_sitename_shape(srv, fs_our, fs_off):
    """`sitename` shape parity (both bare-value; literal may be 'sitename')."""
    st_o, text_o = _q(fs_our, "sitename")
    st_f, text_f = _q(fs_off, "sitename")
    assert st_o.ok and st_f.ok
    assert not text_o.strip().startswith("sitename=")


# query config `fattr` — do_Qconf (XrdXrootdXeq.cc:2265) returns the
# extended-attribute parameters (usxParms, two integers e.g. "248 65536").
# FIXED: src/protocols/root/query/config.c now emits "248 65536" (the Linux user.* xattr
# name/value limits) instead of echoing the key.
def test_qconfig_fattr_recognised_like_stock(srv, fs_our, fs_off):
    """`fattr` is a known do_Qconf key returning integer params on stock; OUR
    server must not echo it back as if it were unknown."""
    st_o, text_o = _q(fs_our, "fattr")
    st_f, text_f = _q(fs_off, "fattr")
    assert st_o.ok and st_f.ok
    f_first = text_f.strip().split()[0] if text_f.strip().split() else ""
    o_first = text_o.strip().split()[0] if text_o.strip().split() else ""
    if f_first.lstrip("-").isdigit():
        assert o_first.lstrip("-").isdigit(), (
            f"stock config fattr is integer ({text_f.strip()!r}) but OUR "
            f"echoes the key ({text_o.strip()!r})")


# =========================================================================== #
# 6. QUERY CHECKSUM — '<algo> <hex>\0'. The bare stock data server ships NO     #
#    checksum plugin (every Checksum query fails on stock), so checksum VALUE   #
#    parity is pinned against an INDEPENDENT reference over the on-disk bytes,   #
#    not against the stock error.                                              #
# =========================================================================== #
CKSUM_FILES = ["/cksum.bin", "/data.bin", "/hello.txt"]
CKSUM_ALGOS = [("adler32", ref_adler32), ("crc32", ref_crc32),
               ("crc32c", ref_crc32c)]


def _cksum(fs, arg):
    st, r = fs.query(QueryCode.CHECKSUM, arg)
    text = (r or b"").rstrip(b"\x00").decode("latin-1") if r else ""
    return st, text


@pytest.mark.parametrize("name", CKSUM_FILES)
def test_cksum_default_two_tokens(srv, fs_our, name):
    """Default Checksum -> exactly '<algo> <8+hex>' on OUR server."""
    st, text = _cksum(fs_our, name)
    assert st.ok, f"OUR checksum {name} failed: code={st.code}"
    toks = text.split()
    assert len(toks) == 2, f"OUR checksum not '<algo> <hex>' for {name}: {text!r}"
    algo, hexv = toks
    assert "=" not in algo and algo, f"bad algo token: {algo!r}"
    assert all(c in "0123456789abcdefABCDEF" for c in hexv), \
        f"non-hex checksum value: {hexv!r}"


@pytest.mark.parametrize("name", CKSUM_FILES)
def test_cksum_default_adler32_matches_reference(srv, fs_our, name):
    """Default Checksum hex equals the independent zlib.adler32 over the bytes
    (stock has no plugin, so the reference is the oracle)."""
    st, text = _cksum(fs_our, name)
    assert st.ok, f"OUR checksum {name} failed"
    got = text.split()[-1].lower()
    want = ref_adler32(_read_bytes(srv, name))
    assert got == want, f"OUR adler32 {name} wrong: server={got} ref={want}"


@pytest.mark.parametrize("name", CKSUM_FILES)
@pytest.mark.parametrize("algo,ref", CKSUM_ALGOS)
def test_cksum_explicit_algo_matches_reference(srv, fs_our, name, algo, ref):
    """`?cks.type=<algo>` selects the algorithm; the returned hex equals the
    independent reference over the bytes, and the algo token is echoed."""
    st, text = _cksum(fs_our, f"{name}?cks.type={algo}")
    assert st.ok, f"OUR checksum {name} {algo} failed: code={st.code}"
    toks = text.split()
    assert len(toks) == 2, f"OUR checksum not two tokens: {text!r}"
    assert toks[0] == algo, f"requested {algo} but server echoed {toks[0]!r}"
    want = ref(_read_bytes(srv, name)).lower()
    assert toks[1].lower() == want, \
        f"OUR {algo} {name} wrong: server={toks[1]} ref={want}"


def test_cksum_md5_matches_reference(srv, fs_our):
    """md5 checksum (if advertised) equals hashlib.md5 over the bytes."""
    _, cfg = _q(fs_our, "chksum")
    if "md5" not in cfg:
        pytest.skip("md5 not advertised by OUR chksum config")
    st, text = _cksum(fs_our, "/data.bin?cks.type=md5")
    assert st.ok, f"OUR md5 checksum failed: code={st.code}"
    algo, hexv = text.split()
    assert algo == "md5"
    want = hashlib.md5(_read_bytes(srv, "/data.bin")).hexdigest()
    assert hexv.lower() == want, f"OUR md5 wrong: server={hexv} ref={want}"


def test_cksum_stock_has_no_plugin_oracle(srv, fs_off):
    """Oracle: the bare stock data server ships no checksum plugin, so a
    Checksum query fails on it. This documents WHY checksum value parity is
    pinned against an independent reference, not against stock."""
    st, _ = _cksum(fs_off, "/data.bin")
    assert not st.ok, (
        "stock unexpectedly answered a Checksum query — re-evaluate whether "
        "checksum value parity should be differential vs stock")


def test_cksum_missing_path_rejected(srv, fs_our):
    """Checksum of a missing path must be an error on OUR server."""
    st, _ = _cksum(fs_our, "/no_such_cksum_file.bin")
    assert not st.ok, "OUR checksum of a missing file succeeded (BUG)"


def test_cksum_directory_rejected(srv, fs_our):
    """Checksum of a directory must be an error on OUR server."""
    st, _ = _cksum(fs_our, "/sub")
    assert not st.ok, "OUR checksum of a directory succeeded (BUG)"


def test_cksum_determinism(srv, fs_our):
    """Same Checksum query twice -> identical hex (default + explicit crc32c)."""
    _, a1 = _cksum(fs_our, "/data.bin")
    _, a2 = _cksum(fs_our, "/data.bin")
    assert a1 == a2 and a1, f"non-deterministic default cksum: {a1!r} {a2!r}"
    _, c1 = _cksum(fs_our, "/data.bin?cks.type=crc32c")
    _, c2 = _cksum(fs_our, "/data.bin?cks.type=crc32c")
    assert c1 == c2 and c1, f"non-deterministic crc32c: {c1!r} {c2!r}"


def test_cksum_different_files_differ(srv, fs_our):
    """Two files with different content yield different checksums."""
    _, c1 = _cksum(fs_our, "/hello.txt")
    _, c2 = _cksum(fs_our, "/data.bin")
    assert c1.split()[-1] != c2.split()[-1], "distinct files collided"


# =========================================================================== #
# 7. QUERY SPACE — oss.* key=value&... response. Both servers answer; OUR must  #
#    carry the required keys with sane values, and match stock's ok-category.   #
# =========================================================================== #
def _parse_oss(text):
    out = {}
    for pair in text.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v
    return out


def _space(fs, path="/"):
    st, r = fs.query(QueryCode.SPACE, path)
    text = (r or b"").rstrip(b"\x00").decode("latin-1") if r else ""
    return st, text


def test_space_ok_parity(srv, fs_our, fs_off):
    """query space / must succeed on BOTH servers (ok-parity)."""
    st_o, _ = _space(fs_our)
    st_f, _ = _space(fs_off)
    assert st_o.ok, "OUR query space / failed"
    assert st_o.ok == st_f.ok, \
        f"query space ok-parity differs: our={st_o.ok} stock={st_f.ok}"


def test_space_required_keys(srv, fs_our):
    """OUR space response carries all oss.* keys gfal/quota tooling reads."""
    st, text = _space(fs_our)
    assert st.ok, "OUR query space / failed"
    oss = _parse_oss(text)
    for key in ("oss.cgroup", "oss.space", "oss.free", "oss.maxf",
                "oss.used", "oss.quota"):
        assert key in oss, f"OUR space response missing {key!r}: {text!r}"


def test_space_values_sane(srv, fs_our):
    """OUR space numeric fields are internally consistent (free<=total, etc.)."""
    st, text = _space(fs_our)
    assert st.ok
    oss = _parse_oss(text)
    total, free = int(oss["oss.space"]), int(oss["oss.free"])
    used, maxf = int(oss["oss.used"]), int(oss["oss.maxf"])
    assert total > 0 and free >= 0 and free <= total
    assert maxf >= 0 and maxf <= free + 1
    assert used >= 0 and used + free <= total + 1


def test_space_keys_parity(srv, fs_our, fs_off):
    """The SET of oss.* keys must match stock (gfal keys off these names). The
    values legitimately differ (cgroup name etc.) but the key set must not."""
    st_o, text_o = _space(fs_our)
    st_f, text_f = _space(fs_off)
    if not (st_o.ok and st_f.ok):
        pytest.skip("space not answered by one server")
    keys_o = set(_parse_oss(text_o)) & {
        "oss.cgroup", "oss.space", "oss.free", "oss.maxf", "oss.used",
        "oss.quota"}
    keys_f = set(_parse_oss(text_f)) & {
        "oss.cgroup", "oss.space", "oss.free", "oss.maxf", "oss.used",
        "oss.quota"}
    assert keys_o == keys_f, \
        f"space oss.* key set differs: our={keys_o} stock={keys_f}"


# DIVERGENCE: query space "" (empty path) — stock validates the path and REJECTS
# an empty/relative path (XrdXrootdXeq.cc:4405 "Stating relative path '' is
# disallowed.", XErrorCode 3010 kXR_FSError), but OUR server accepts it (ok=True).
# Our: ok=True ; Stock: ok=False errno=3010. Suspected fix: apply the same
# relative/empty path rejection in OUR Qspace handler (src/protocols/root/query/*).
# FIXED: src/protocols/root/query/space.c now applies the reference rpCheck guard and rejects an
# empty/relative Qspace path with kXR_NotAuthorized (3010).
def test_space_empty_path_rejected_like_stock(srv, fs_our, fs_off):
    """An empty-path space query is rejected by stock; OUR server must match its
    ok-category rather than silently accepting an empty path."""
    st_o, _ = _space(fs_our, "")
    st_f, _ = _space(fs_off, "")
    assert st_o.ok == st_f.ok, \
        f"empty-path space ok-parity differs: our={st_o.ok} stock={st_f.ok}"


# =========================================================================== #
# 8. QUERY STATS — XrdStats XML. Both servers answer; OUR must be non-empty,    #
#    XML-ish, and match stock's ok-category. The volatile counters differ so we #
#    pin liveness + shape, not the literal bytes.                              #
# =========================================================================== #
def _stats(fs, arg="a"):
    st, r = fs.query(QueryCode.STATS, arg)
    text = (r or b"").rstrip(b"\x00").decode("latin-1", "replace") if r else ""
    return st, text


def test_stats_ok_parity(srv, fs_our, fs_off):
    """query stats must succeed on BOTH servers (needs no namespace plugin)."""
    st_o, _ = _stats(fs_our)
    st_f, _ = _stats(fs_off)
    assert st_o.ok, "OUR query stats failed"
    assert st_o.ok == st_f.ok, \
        f"query stats ok-parity differs: our={st_o.ok} stock={st_f.ok}"


def test_stats_xmlish_nonempty(srv, fs_our):
    """OUR stats body is non-empty and XML-ish (XrdStats emits '<statistics ...>')."""
    st, text = _stats(fs_our)
    assert st.ok and text.strip() != "", "OUR query stats empty"
    assert "<" in text, f"OUR stats not XML-ish: {text[:120]!r}"


def test_stats_has_statistics_root(srv, fs_our, fs_off):
    """Both servers wrap the body in a <statistics ...> root element."""
    _, text_o = _stats(fs_our)
    _, text_f = _stats(fs_off)
    assert "<statistics" in text_o, \
        f"OUR stats missing <statistics root: {text_o[:120]!r}"
    if "<statistics" not in text_f:
        pytest.skip("stock stats shape unexpected")


def test_stats_determinism_shape(srv, fs_our):
    """Two stats queries keep the same XML-ish shape (open bracket present); the
    volatile counters may change but the envelope must not vanish."""
    _, t1 = _stats(fs_our)
    _, t2 = _stats(fs_our)
    assert ("<" in t1) and ("<" in t2), "OUR stats lost its XML envelope"


# =========================================================================== #
# 9. QUERY XATTR — oss.* attribute string. Both servers answer for a real file. #
# =========================================================================== #
def _xattr(fs, path):
    st, r = fs.query(QueryCode.XATTR, path)
    text = (r or b"").rstrip(b"\x00").decode("latin-1", "replace") if r else ""
    return st, text


@pytest.mark.parametrize("path", ["/data.bin", "/hello.txt", "/cksum.bin"])
def test_xattr_ok_parity(srv, fs_our, fs_off, path):
    """query xattr <file> ok-parity our-vs-stock."""
    st_o, _ = _xattr(fs_our, path)
    st_f, _ = _xattr(fs_off, path)
    assert st_o.ok == st_f.ok, (
        f"xattr ok-parity differs for {path!r}: our={st_o.ok} stock={st_f.ok}")


def test_xattr_has_oss_fields(srv, fs_our):
    """OUR xattr response carries oss.* descriptor fields (oss.type/oss.used)."""
    st, text = _xattr(fs_our, "/data.bin")
    if not st.ok:
        pytest.skip("OUR xattr not answered")
    assert "oss." in text, f"OUR xattr lacks oss.* fields: {text[:120]!r}"


def test_xattr_key_set_parity(srv, fs_our, fs_off):
    """The set of oss.* attribute KEYS for a file must match stock (gfal reads
    these by name); values differ (cgroup/mtime) but keys must not."""
    st_o, text_o = _xattr(fs_our, "/data.bin")
    st_f, text_f = _xattr(fs_off, "/data.bin")
    if not (st_o.ok and st_f.ok):
        pytest.skip("xattr not answered by one server")
    keys_o = {p.split("=", 1)[0] for p in text_o.split("&") if "=" in p}
    keys_f = {p.split("=", 1)[0] for p in text_f.split("&") if "=" in p}
    common = {"oss.type", "oss.used", "oss.cgroup"}
    assert (keys_o & common) == (keys_f & common), (
        f"xattr core key set differs: our={keys_o & common} "
        f"stock={keys_f & common}")


# =========================================================================== #
# 10. QUERY VISA / PREPARE — reqcode dispatch. do_Query has NO kXR_Qvisa case   #
#     -> rejected; Qprep -> do_Prepare(true) -> unknown reqid rejected on stock.#
# =========================================================================== #
def test_visa_rejected_both(srv, fs_our, fs_off):
    """do_Query has no kXR_Qvisa case -> default branch rejects it. OUR server
    must reject Visa, matching stock's rejection category."""
    st_o, _ = fs_our.query(QueryCode.VISA, "/data.bin")
    st_f, _ = fs_off.query(QueryCode.VISA, "/data.bin")
    assert not st_o.ok, "OUR Visa query succeeded (reference rejects it)"
    assert st_o.ok == st_f.ok, \
        f"Visa rejection category differs: our={st_o.ok} stock={st_f.ok}"


# DIVERGENCE: query prepare (Qprep status) — do_Query routes Qprep ->
# do_Prepare(true); the reference tracks prepare request-ids and REJECTS a
# status query for a reqid it never issued ("Prepare requestid owned by an
# unknown server"). Stock fails (errno 3000). OUR server returns ok with an
# empty body, i.e. it accepts an unknown prepare reqid. Our: ok=True, body=b'';
# Stock: ok=False (errno 3000). Suspected fix: track issued prepare reqids in
# OUR prepare/query path and reject unknown ones.
# FIXED: src/protocols/root/query/prepare.c now rejects a Qprep status query for a reqid it has
# no record of (no stored paths and no FRM queue record) with kXR_ArgInvalid
# "Prepare requestid owned by an unknown server", matching do_Prepare(isQuery).
def test_prepare_unknown_reqid_rejected_like_stock(srv, fs_our, fs_off):
    """A Prepare-status query for a reqid the server never issued must be
    rejected, matching stock."""
    st_o, _ = fs_our.query(QueryCode.PREPARE, "reqid-never-issued-0001")
    st_f, _ = fs_off.query(QueryCode.PREPARE, "reqid-never-issued-0001")
    assert not st_f.ok, "oracle: stock unexpectedly accepted an unknown reqid"
    assert st_o.ok == st_f.ok, (
        f"Prepare unknown-reqid ok-parity differs: our={st_o.ok} "
        f"stock={st_f.ok}")

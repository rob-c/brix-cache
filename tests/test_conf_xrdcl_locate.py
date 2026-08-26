from split_continuation import reexport as _reexport
def _expression_1(text_o):
    return (
        text_o.strip().splitlines()[0].strip() if text_o.strip() else ""
    )

def _expression_2(text_f):
    return (
        text_f.strip().splitlines()[0].strip() if text_f.strip() else ""
    )

def _expression_3(line_f):
    return (
        line_f.split()[0] if line_f.split() else ""
    )

def _expression_4(line_o):
    return (
        line_o.split()[0] if line_o.split() else ""
    )


def _phase_test_qconfig_shape_parity_1(f_first, key, line_f, line_o, o_first):
    if f_first.lstrip("-").isdigit():
        _check_test_qconfig_shape_parity_2(key, line_f, line_o, o_first)


def _check_test_qconfig_shape_parity_1(key, line_o):
    assert not line_o.startswith(f"{key}="), \
        f"OUR config {key} uses key= but stock does not: {line_o!r}"

def _check_test_qconfig_shape_parity_2(key, line_f, line_o, o_first):
    assert o_first.lstrip("-").isdigit(), (
        f"stock config {key} is integer ({line_f!r}) but OUR is not "
        f"({line_o!r})")


_reexport(globals(), "_test_conf_xrdcl_locate_helpers")

pytestmark = pytest.mark.xdist_group("conf_xrdcl_locate")

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
    def _assert_test_qconfig_shape_parity_1():
        assert st_o.ok, f"OUR query config {key} failed"
        assert st_f.ok, f"stock did not answer required config key {key}"

    _assert_test_qconfig_shape_parity_1()
    line_o = _expression_1(text_o)
    line_f = _expression_2(text_f)
    _check_test_qconfig_shape_parity_1(key, line_o)
    f_first = _expression_3(line_f)
    o_first = _expression_4(line_o)
    _phase_test_qconfig_shape_parity_1(f_first, key, line_f, line_o, o_first)


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
    def _assert_test_qconfig_multikey_one_line_per_key_2():
        assert len(lines) == 3, \
            f"OUR multi-key expected 3 lines, got {len(lines)}: {body!r}"
        assert lines[0].split()[0].lstrip("-").isdigit(), \
            f"bind_max line not integer-first: {lines[0]!r}"

    _assert_test_qconfig_multikey_one_line_per_key_2()
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

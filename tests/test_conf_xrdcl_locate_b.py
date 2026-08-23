from split_continuation import reexport as _reexport
def _check_test_xattr_key_set_parity_1(st_o, st_f):
    assert st_o.ok and st_f.ok, "xattr must be answered by both servers"

def _check_test_xattr_key_set_parity_2(keys_o, common, keys_f):
    assert (keys_o & common) == (keys_f & common), (
        f"xattr core key set differs: our={keys_o & common} "
        f"stock={keys_f & common}")


_reexport(globals(), "_test_conf_xrdcl_locate_helpers")

CKSUM_FILES = ["/cksum.bin", "/data.bin", "/hello.txt"]
CKSUM_ALGOS = [("adler32", ref_adler32), ("crc32", ref_crc32),
               ("crc32c", ref_crc32c)]

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
    assert "md5" in cfg, "md5 must be advertised by OUR chksum config"
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
    assert st_o.ok and st_f.ok, "space must be answered by both servers"
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
    assert "<statistics" in text_f, "stock stats response lacks statistics root"


def test_stats_determinism_shape(srv, fs_our):
    """Two stats queries keep the same XML-ish shape (open bracket present); the
    volatile counters may change but the envelope must not vanish."""
    _, t1 = _stats(fs_our)
    _, t2 = _stats(fs_our)
    assert ("<" in t1) and ("<" in t2), "OUR stats lost its XML envelope"


# =========================================================================== #
# 9. QUERY XATTR — oss.* attribute string. Both servers answer for a real file. #
# =========================================================================== #

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
    assert st.ok, "OUR server must answer xattr"
    assert "oss." in text, f"OUR xattr lacks oss.* fields: {text[:120]!r}"


def test_xattr_key_set_parity(srv, fs_our, fs_off):
    """The set of oss.* attribute KEYS for a file must match stock (gfal reads
    these by name); values differ (cgroup/mtime) but keys must not."""
    st_o, text_o = _xattr(fs_our, "/data.bin")
    st_f, text_f = _xattr(fs_off, "/data.bin")
    _check_test_xattr_key_set_parity_1(st_o, st_f)
    keys_o = {p.split("=", 1)[0] for p in text_o.split("&") if "=" in p}
    keys_f = {p.split("=", 1)[0] for p in text_f.split("&") if "=" in p}
    common = {"oss.type", "oss.used", "oss.cgroup"}
    _check_test_xattr_key_set_parity_2(keys_o, common, keys_f)


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

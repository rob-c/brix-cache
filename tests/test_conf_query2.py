from split_continuation import reexport as _reexport
def _expression_1(out_o):
    return (
        out_o.strip().splitlines()[0].strip() if out_o.strip() else ""
    )

def _expression_2(out_f):
    return (
        out_f.strip().splitlines()[0].strip() if out_f.strip() else ""
    )

def _expression_3(line_f):
    return (
        line_f.split()[0] if line_f.split() else ""
    )

def _expression_4(line_o):
    return (
        line_o.split()[0] if line_o.split() else ""
    )


def _phase_test_qconfig_differential_shape_1(f_first, key, line_f, line_o, o_first):
    if f_first.lstrip("-").isdigit():
        _check_test_qconfig_differential_shape_3(key, line_f, line_o, o_first)


def _check_test_qconfig_differential_shape_1(rc_o, key, raw_o):
    assert rc_o == 0, f"OUR query config {key} failed: {raw_o!r}"

def _guard_test_qconfig_differential_shape_1(rc_f, key, raw_f):
    if rc_f != 0:
        pytest.skip(f"stock did not answer config {key}: {raw_f!r}")

def _check_test_qconfig_differential_shape_2(key, line_o):
    assert not line_o.startswith(f"{key}="), \
        f"OUR config {key} uses key= but stock does not: {line_o!r}"

def _check_test_qconfig_differential_shape_3(key, line_f, line_o, o_first):
    assert o_first.lstrip("-").isdigit(), (
        f"stock config {key} is integer ({line_f!r}) but OUR is not "
        f"({line_o!r})")

def _check_test_qconfig_multi_key_matches_singletons_4(rc_m, raw_m):
    assert rc_m == 0, f"OUR multi-key failed: {raw_m!r}"

def _check_test_qconfig_multi_key_matches_singletons_5(multi, keys, out_m):
    assert len(multi) == len(keys), f"line count mismatch: {out_m!r}"

def _check_test_qconfig_multi_key_matches_singletons_6(rc_s):
    assert rc_s == 0

def _check_test_qconfig_multi_key_matches_singletons_7(single, k, ml):
    assert ml.strip() == single, (
        f"multi-key line for {k} ({ml.strip()!r}) != singleton "
        f"({single!r})")


_reexport(globals(), "_test_conf_query2_helpers")

pytestmark = pytest.mark.xdist_group("conf_query2")

@pytest.mark.parametrize("key", QCONFIG_KEYS)
def test_qconfig_key_bare_value(srv, key):
    """OUR `query config <key>` succeeds, is newline-terminated, and is a BARE
    value (or the echoed key) — never a "<key>=..." pair (do_Qconf reference)."""
    rc, out, raw = qconfig(srv["our"], key)
    assert rc == 0, f"OUR query config {key} failed: {raw!r}"
    assert out.strip() != "", f"OUR query config {key} returned an empty line"
    # do_Qconf emits the value '\n'-terminated; xrdfs prints it verbatim.
    assert "\n" in out, \
        f"OUR query config {key} not newline-terminated: {out!r}"
    line = out.strip().splitlines()[0].strip()
    assert not line.startswith(f"{key}="), \
        f"OUR query config {key} has a key= prefix (BUG): {line!r}"
    first = line.split()[0] if line.split() else ""
    assert "=" not in first, \
        f"OUR query config {key} first token looks like key=value: {first!r}"


@pytest.mark.parametrize("key", NUMERIC_KEYS)
def test_qconfig_numeric_is_integer(srv, key):
    """Numeric do_Qconf keys (snprintf("%d\\n", ...)) must be an integer line."""
    rc, out, raw = qconfig(srv["our"], key)
    assert rc == 0, f"OUR query config {key} failed: {raw!r}"
    first = out.strip().split()[0] if out.strip().split() else ""
    assert first.lstrip("-").isdigit(), \
        f"OUR query config {key} is not an integer: {out!r}"


@pytest.mark.parametrize("key", QCONFIG_KEYS)
def test_qconfig_no_trailing_space_on_value_line(srv, key):
    """The value line itself must not carry a trailing space before its '\\n'
    (do_Qconf writes "%s\\n"/"%d\\n" — no trailing blank)."""
    status, text = raw_qconfig(srv["our"], key)
    assert status == kXR_ok, \
        f"OUR raw query config {key} status {status} (BUG): {text!r}"
    assert text != "", f"OUR raw query config {key} returned no body"
    for ln in text.split("\n"):
        if ln == "":
            continue
        assert not ln.endswith(" "), \
            f"OUR query config {key} line has a trailing space: {ln!r}"


@pytest.mark.parametrize("key", QCONFIG_KEYS)
def test_qconfig_line_newline_terminated_raw(srv, key):
    """The raw do_Qconf payload must END with '\\n' (each key writes "...\\n").
    The stock buffer is fixed-size and padded; the last non-NUL char before
    padding is the terminator. We assert the first value line is newline-ended."""
    status, text = raw_qconfig(srv["our"], key)
    assert status == kXR_ok, f"OUR raw query config {key} not ok: {text!r}"
    body = text.rstrip("\x00")
    assert "\n" in body, \
        f"OUR raw query config {key} not newline-terminated: {body!r}"


@pytest.mark.parametrize("key", ["bind_max", "chksum", "tpc", "tpcdlg",
                                 "role", "sitename", "readv_iov_max",
                                 "readv_ior_max", "pio_max", "version",
                                 "cid", "cms", "vnid", "fattr"])
def test_qconfig_differential_shape(srv, key):
    """Differential: where the STOCK server answers a config key, OUR server must
    answer it with the same shape category — both bare-value (no "key="), and
    when stock yields an integer ours must too. Value text may legitimately
    differ (build/site), so we compare SHAPE, not the literal value."""
    rc_o, out_o, raw_o = qconfig(srv["our"], key)
    rc_f, out_f, raw_f = qconfig(srv["off"], key)
    _check_test_qconfig_differential_shape_1(rc_o, key, raw_o)
    _guard_test_qconfig_differential_shape_1(rc_f, key, raw_f)
    line_o = _expression_1(out_o)
    line_f = _expression_2(out_f)
    _check_test_qconfig_differential_shape_2(key, line_o)
    f_first = _expression_3(line_f)
    o_first = _expression_4(line_o)
    _phase_test_qconfig_differential_shape_1(f_first, key, line_f, line_o, o_first)


def test_qconfig_unknown_key_echoed_bare(srv):
    """do_Qconf default branch ECHOES an unknown key verbatim + '\\n' (NOT
    "key=0", NOT an error). Pin OUR server to that and diff against stock."""
    bogus = "no_such_config_key_xyzzy"
    rc_o, out_o, raw_o = qconfig(srv["our"], bogus)
    rc_f, out_f, raw_f = qconfig(srv["off"], bogus)
    assert rc_o == 0, f"OUR unknown config key errored (BUG): {raw_o!r}"
    line_o = out_o.strip()
    assert line_o == bogus, \
        f"OUR did not echo unknown key bare (BUG): {line_o!r}"
    assert not line_o.startswith(f"{bogus}="), \
        f"OUR echoed unknown key as key= (BUG): {line_o!r}"
    if rc_f == 0:
        assert out_f.strip() == bogus, \
            f"stock echoed unknown key differently: {out_f.strip()!r}"


def test_qconfig_unknown_key_raw_echo(srv):
    """Raw-wire confirmation that an unknown key echoes exactly "<key>\\n"."""
    bogus = "totally_unknown_cfgkey"
    status, text = raw_qconfig(srv["our"], bogus)
    assert status == kXR_ok, f"OUR raw unknown key status {status}: {text!r}"
    body = text.rstrip("\x00")
    assert body.split("\n")[0] == bogus, \
        f"OUR raw echo of unknown key wrong: {body!r}"


def test_qconfig_multi_key_order_and_lines(srv):
    """Multiple keys in ONE request -> one line per key, IN REQUEST ORDER
    (do_Qconf loops GetToken() and appends "%s\\n" per token)."""
    keys = ["tpc", "tpcdlg", "version"]
    rc_o, out_o, raw_o = qconfig(srv["our"], *keys)
    assert rc_o == 0, f"OUR multi-key query config failed: {raw_o!r}"
    lines_o = [l for l in out_o.split("\n") if l != ""]
    assert len(lines_o) == len(keys), (
        f"OUR multi-key returned {len(lines_o)} lines for {len(keys)} keys "
        f"(BUG): {out_o!r}")
    # version line must look like a version, tpc/tpcdlg must not be "key=".
    for k, ln in zip(keys, lines_o):
        assert not ln.strip().startswith(f"{k}="), \
            f"OUR multi-key line for {k} has key= prefix (BUG): {ln!r}"


def test_qconfig_multi_key_raw_order(srv):
    """Raw-wire: 'bind_max readv_iov_max version' -> exactly three lines, first
    two integers, in order (do_Qconf preserves token order)."""
    status, text = raw_qconfig(srv["our"], "bind_max readv_iov_max version")
    assert status == kXR_ok, f"OUR raw multi-key not ok: {text!r}"
    body = text.rstrip("\x00")
    lines = [l for l in body.split("\n") if l != ""]
    assert len(lines) == 3, \
        f"OUR raw multi-key expected 3 lines, got {len(lines)}: {body!r}"
    assert lines[0].split()[0].lstrip("-").isdigit(), \
        f"OUR bind_max line not integer-first: {lines[0]!r}"
    assert lines[1].split()[0].lstrip("-").isdigit(), \
        f"OUR readv_iov_max line not integer-first: {lines[1]!r}"


def test_qconfig_multi_key_matches_singletons(srv):
    """A multi-key request's per-key line must equal the same key queried alone
    (the loop is just per-token concatenation; no cross-key contamination)."""
    keys = ["bind_max", "tpc", "role"]
    rc_m, out_m, raw_m = qconfig(srv["our"], *keys)
    _check_test_qconfig_multi_key_matches_singletons_4(rc_m, raw_m)
    multi = [l for l in out_m.split("\n") if l != ""]
    _check_test_qconfig_multi_key_matches_singletons_5(multi, keys, out_m)
    for k, ml in zip(keys, multi):
        rc_s, out_s, _ = qconfig(srv["our"], k)
        _check_test_qconfig_multi_key_matches_singletons_6(rc_s)
        single = out_s.strip().splitlines()[0].strip()
        _check_test_qconfig_multi_key_matches_singletons_7(single, k, ml)


def test_qconfig_version_format(srv):
    """`query config version` must return a version STRING. do_Qconf emits
    XrdVSTRING (e.g. "v5.6.3" / "vX.Y.Z..."); pin OUR to a v-prefixed dotted
    form (the canonical XRootD version-string shape)."""
    rc, out, raw = qconfig(srv["our"], "version")
    assert rc == 0, f"OUR query config version failed: {raw!r}"
    ver = out.strip().splitlines()[0].strip()
    assert ver, "OUR version line empty"
    assert not ver.startswith("version="), \
        f"OUR version has key= prefix (BUG): {ver!r}"
    # Reference shape: a 'v' followed by at least major.minor digits.
    head = ver.split()[0]
    assert head[:1].lower() == "v" and any(c.isdigit() for c in head), \
        f"OUR version not a v-prefixed version string: {ver!r}"
    assert "." in head, f"OUR version not dotted (vX.Y.Z): {ver!r}"


def test_qconfig_chksum_lists_adler32(srv):
    """`query config chksum` -> bare cslist (or echoed 'chksum'); ours must list
    adler32 (the default algorithm it then answers)."""
    rc, out, raw = qconfig(srv["our"], "chksum")
    assert rc == 0, f"OUR query config chksum failed: {raw!r}"
    line = out.strip()
    assert not line.startswith("chksum="), \
        f"OUR chksum config has key= prefix (BUG): {line!r}"
    advertised = {a.strip() for a in line.replace("\n", ",").split(",")
                  if a.strip()}
    assert "adler32" in advertised, \
        f"OUR chksum config does not advertise adler32: {advertised}"


def test_qconfig_tpc_parseable(srv):
    """XrdCl reads `query config tpc` as a leading digit; pin OUR to a digit or
    the echoed 'tpc' (do_Qconf default when XRDTPC unset)."""
    rc, out, _ = qconfig(srv["our"], "tpc")
    assert rc == 0
    head = out.strip().splitlines()[0].strip() if out.strip() else ""
    assert head[:1].isdigit() or head == "tpc", \
        f"OUR query config tpc not parseable: {out!r}"


# =========================================================================== #
# 2. QUERY CHECKSUM (Qcksum) — '<algo> <hex>'; explicit ?cks.type as LAST cgi #
#    field; value pinned to an independent reference; nonexistent/dir parity. #
# =========================================================================== #

@pytest.mark.parametrize("name", ["hello.txt", "data.bin", "cksum.bin"])
def test_qcksum_shape_two_tokens(srv, name):
    """`query checksum <file>` -> exactly '<algo> <hex>' (two tokens, hex)."""
    rc, out, err = fs(srv["our"], "query", "checksum", f"/{name}")
    assert rc == 0, f"OUR query checksum /{name} failed: {out}{err}"
    toks = out.split()
    assert len(toks) == 2, f"OUR checksum not '<algo> <hex>' for /{name}: {out!r}"
    algo, hexv = toks
    assert algo and "=" not in algo, f"bad algo token: {algo!r}"
    assert all(c in "0123456789abcdefABCDEF" for c in hexv), \
        f"non-hex checksum value: {hexv!r}"


@pytest.mark.parametrize("name", ["hello.txt", "data.bin", "cksum.bin"])
def test_qcksum_default_adler32_value(srv, name):
    """Default-algorithm hex equals the independent zlib.adler32 over the bytes."""
    rc, out, err = fs(srv["our"], "query", "checksum", f"/{name}")
    assert rc == 0, f"{out}{err}"
    got = out.split()[-1].lower()
    want = ref_adler32(_data(srv, name))
    assert got == want, f"OUR adler32 /{name} wrong: server={got} ref={want}"


@pytest.mark.parametrize("algo,ref", [("adler32", ref_adler32),
                                      ("crc32", ref_crc32),
                                      ("crc32c", ref_crc32c)])
def test_qcksum_explicit_cks_type_last_cgi(srv, algo, ref):
    """`?cks.type=<algo>` as the LAST cgi field (no trailing &) selects the algo;
    the returned hex equals the independent reference over the bytes."""
    path = f"/data.bin?cks.type={algo}"
    rc, out, err = fs(srv["our"], "query", "checksum", path)
    assert rc == 0, f"OUR checksum {path} failed: {out}{err}"
    got = out.split()[-1].lower()
    want = ref(_data(srv, "data.bin")).lower()
    assert got == want, f"OUR {algo} wrong: server={got} ref={want}"


def test_qcksum_explicit_algo_echoed(srv):
    """A requested algo must be ECHOED in the algo token (no silent substitution
    to the default)."""
    rc, out, err = fs(srv["our"], "query", "checksum", "/data.bin?cks.type=crc32c")
    assert rc == 0, f"{out}{err}"
    assert out.split()[0] == "crc32c", \
        f"requested crc32c but server echoed {out.split()[0]!r}"


def test_qcksum_nonexistent_parity(srv):
    """Checksum of a missing path: OUR must reject; category is a not-found
    error (or, when stock answers/lacks a plugin, ours is the precise NotFound)."""
    rc_o, out_o, err_o = fs(srv["our"], "query", "checksum", "/missing_xyz.bin")
    assert rc_o != 0, f"OUR checksum of missing file succeeded (BUG): {out_o}"
    assert L.err_code(out_o + err_o) in ("no such file", "not found"), \
        f"OUR missing-file checksum miscategorised: {out_o}{err_o!r}"


def test_qcksum_directory_rejected(srv):
    """Checksum of a directory must be an error on OUR server."""
    rc, out, err = fs(srv["our"], "query", "checksum", "/sub")
    assert rc != 0, f"OUR checksum of a directory succeeded (BUG): {out}{err}"


def test_qcksum_determinism(srv):
    """Same checksum query twice -> identical hex (default + explicit)."""
    a1 = fs(srv["our"], "query", "checksum", "/data.bin")[1].split()[-1]
    a2 = fs(srv["our"], "query", "checksum", "/data.bin")[1].split()[-1]
    assert a1 == a2, f"non-deterministic adler32: {a1} then {a2}"
    c1 = fs(srv["our"], "query", "checksum", "/data.bin?cks.type=crc32c")[1].split()[-1]
    c2 = fs(srv["our"], "query", "checksum", "/data.bin?cks.type=crc32c")[1].split()[-1]
    assert c1 == c2, f"non-deterministic crc32c: {c1} then {c2}"


def test_qcksum_raw_reqcode_shape(srv):
    """Raw kXR_Qcksum (infotype=3) on /data.bin -> kXR_ok with an '<algo> <hex>'
    body (pins the reqcode dispatch + reply shape, not just the xrdfs surface)."""
    status, body = raw_query(srv["our"], kXR_Qcksum, "/data.bin")
    assert status == kXR_ok, f"OUR raw Qcksum status {status} (BUG): {body!r}"
    toks = body.rstrip(b"\x00").decode("latin-1").split()
    assert len(toks) >= 2, f"OUR raw Qcksum body not '<algo> <hex>': {body!r}"
    assert all(c in "0123456789abcdefABCDEF" for c in toks[-1]), \
        f"OUR raw Qcksum hex malformed: {toks[-1]!r}"


# =========================================================================== #
# 3. QUERY CKSCAN (Qckscan, infotype=6) — do_Query routes it to do_CKsum(1).  #
#    Pin OUR reqcode handling to a non-arg-invalid outcome and diff vs stock.  #
# =========================================================================== #
def test_qckscan_reqcode_not_arginvalid(srv):
    """A raw Qckscan on a real file must NOT be rejected as an invalid query
    type (do_Query dispatches kXR_Qckscan -> do_CKsum(1)). It may succeed or
    return a checksum-related status, but not kXR_error 'invalid query type'."""
    status, body = raw_query(srv["our"], kXR_Qckscan, "/data.bin")
    text = body.rstrip(b"\x00").decode("latin-1").lower()
    assert not (status == kXR_error and "invalid information query type" in text), (
        f"OUR rejected Qckscan as an invalid reqcode (BUG): {body!r}")


def test_qckscan_reference_outcome(srv):
    """Qckscan -> do_CKsum(1) (a checksum scan/recompute). The bare stock data
    server ships NO checksum plugin, so it uniformly errors here — that is a
    plugin-absence artifact, not the protocol reference. We therefore PIN OUR
    server to the reference: Qckscan on a real file must be a recognised reqcode
    and yield a non-error checksum outcome (it must NOT fall through to the
    do_Query default 'invalid query type' error)."""
    so, bo = raw_query(srv["our"], kXR_Qckscan, "/data.bin")
    text = bo.rstrip(b"\x00").decode("latin-1").lower()
    assert "invalid information query type" not in text, (
        f"OUR rejected Qckscan as an invalid reqcode (BUG): {bo!r}")
    assert so == kXR_ok, (
        f"OUR Qckscan on a real file should compute (reference do_CKsum(1)), "
        f"got status={so}: {bo!r}")
    # Record the stock plugin-absence category for completeness (not asserted as
    # parity — stock's error is the missing-plugin artifact).
    sf, _ = raw_query(srv["off"], kXR_Qckscan, "/data.bin")
    assert sf in (kXR_ok, kXR_error)


# =========================================================================== #
# 4. QUERY SPACE (Qspace, infotype=5) — rc/format parity vs stock.            #
# =========================================================================== #
def test_qspace_category_matches_stock_xrdfs(srv):
    """`xrdfs query space /` — OUR vs STOCK success/failure category must agree."""
    rc_o, out_o, err_o = fs(srv["our"], "query", "space", "/")
    rc_f, out_f, err_f = fs(srv["off"], "query", "space", "/")
    assert (rc_o == 0) == (rc_f == 0), (
        f"query space support category differs: "
        f"our_ok={rc_o == 0}({out_o}{err_o!r}) "
        f"stock_ok={rc_f == 0}({out_f}{err_f!r})")
    if rc_f != 0:
        assert L.err_code(out_o + err_o) == L.err_code(out_f + err_f), (
            f"query space failure category differs: "
            f"our={L.err_code(out_o + err_o)} stock={L.err_code(out_f + err_f)}")


def test_qspace_raw_reqcode_parity(srv):
    """Raw Qspace (infotype=5) on '/': OUR ok-category must match stock."""
    so, bo = raw_query(srv["our"], kXR_Qspace, "/")
    sf, bf = raw_query(srv["off"], kXR_Qspace, "/")
    assert (so == kXR_ok) == (sf == kXR_ok), (
        f"raw Qspace ok-category differs: our={so} ({bo!r}) "
        f"stock={sf} ({bf!r})")


# =========================================================================== #
# 5. QUERY STATS (Qstats, infotype=1) — rc==0 + non-empty XML-ish on OUR.     #
# =========================================================================== #
def test_qstats_success_nonempty(srv):
    """`xrdfs query stats a` -> success + non-empty output on OUR server."""
    rc, out, err = fs(srv["our"], "query", "stats", "a")
    assert rc == 0, f"OUR query stats failed: {out}{err}"
    assert out.strip() != "", "OUR query stats returned empty output"


def test_qstats_raw_xmlish(srv):
    """Raw Qstats (infotype=1, empty arg -> 'a') -> kXR_ok with an XML-ish body
    (XrdStats emits '<statistics ...>...'); pin the open angle bracket."""
    status, body = raw_query(srv["our"], kXR_QStats, b"")
    assert status == kXR_ok, f"OUR raw Qstats status {status} (BUG): {body!r}"
    text = body.rstrip(b"\x00").decode("latin-1")
    assert text.strip() != "", "OUR raw Qstats body empty"
    assert "<" in text, f"OUR raw Qstats body not XML-ish: {text[:120]!r}"


def test_qstats_differential_success(srv):
    """Both servers must succeed at query stats (it needs no namespace plugin)."""
    rc_o, out_o, _ = fs(srv["our"], "query", "stats", "a")
    rc_f, out_f, _ = fs(srv["off"], "query", "stats", "a")
    assert rc_o == 0, f"OUR query stats failed: {out_o!r}"
    assert (rc_o == 0) == (rc_f == 0), \
        f"query stats success category differs: our={rc_o} stock={rc_f}"


# =========================================================================== #
# 6. QUERY XATTR (Qxattr, infotype=4) — parity vs stock.                      #
# =========================================================================== #

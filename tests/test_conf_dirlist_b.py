from split_continuation import reexport as _reexport
def _expression_1(our_e):
    return (
        {n: ck for n, _s, _f, ck in our_e}
    )

def _expression_2(off_e):
    return (
        {n: (ck or "") for n, _s, _f, ck in off_e}
    )

def _expression_3(spot, off_map):
    return (
        off_map.get(spot) and ":" in off_map[spot] and \
                   off_map[spot].split(":")[-1].strip().lower() not in ("none", "")
    )

def _expression_4(text):
    return (
        [l for l in text.split("\n") if l]
    )

def _expression_5(lines):
    return (
        2 if (len(lines) >= 2 and lines[0] == ".") else 0
    )


def _check_test_wire_dcksm_tokens_and_value_1(our_e):
    assert our_e, "our dcksm dirlist returned no entries"

def _check_test_wire_dcksm_tokens_and_value_3(spot, our_map):
    assert spot in our_map, f"{spot} absent from our dcksm output"

def _check_test_wire_dcksm_tokens_and_value_4(got, want, spot, got_field):
    assert got == want, \
        f"our dcksm /many {spot} adler32={got!r} expected {want!r} (full token {got_field!r})"

def _check_test_wire_dcksm_tokens_and_value_2(ck, name):
    assert ck, f"our dcksm /many {name} missing checksum token: {ck!r}"

def _check_test_wire_dcksm_tokens_and_value_5(got, off_val, spot):
    assert got == off_val, \
        f"dcksm /many {spot} value divergence: ours={got!r} stock={off_val!r}"

def _check_test_wire_dstat_special_names_6(real, our_sz):
    assert our_sz.get("with space") == real, \
        f"our dstat /special 'with space' size={our_sz.get('with space')} real={real}"


_reexport(globals(), "_test_conf_dirlist_helpers")

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
        lines = _expression_4(text)
        # find the stat line for the first real entry after the sentinel
        # sentinel = lines[0]=="." , lines[1]=="0 0 0 0"
        idx = _expression_5(lines)
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

def test_wire_dcksm_tokens_and_value(srv):
    # OUR server: every entry must carry a checksum token, and a spot-checked
    # one must equal the independent adler32 of that file.
    try:
        _, our_e = _wire_dstat(OUR_PORT, "/many", with_cksum=True)
    except _DirlistError as e:
        pytest.fail(f"our server errored on kXR_dcksm dirlist (errnum={e.errnum})")
    _check_test_wire_dcksm_tokens_and_value_1(our_e)
    for name, _sz, _fl, ck in our_e:
        _check_test_wire_dcksm_tokens_and_value_2(ck, name)

    # spot-check one entry's value against an independent adler32
    spot = "f00.txt"
    our_map = _expression_1(our_e)
    _check_test_wire_dcksm_tokens_and_value_3(spot, our_map)
    want = _adler32_hex(os.path.join(srv["our_data"], "many", spot))
    got_field = our_map[spot]
    # token form is "algo:value"; extract the hex value
    got = got_field.split(":")[-1].strip().lower()
    _check_test_wire_dcksm_tokens_and_value_4(got, want, spot, got_field)

    # STOCK comparison if its data server supports dcksm; else just pin ours.
    try:
        _, off_e = _wire_dstat(OFF_PORT, "/many", with_cksum=True)
        off_map = _expression_2(off_e)
        if _expression_3(spot, off_map):
            off_val = off_map[spot].split(":")[-1].strip().lower()
            _check_test_wire_dcksm_tokens_and_value_5(got, off_val, spot)
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
    def _assert_test_wire_dstat_special_names_1():
        assert our_names == expected, \
            f"our dstat /special name-set wrong: missing={expected - our_names} extra={our_names - expected}"
        assert off_names == expected, f"stock dstat /special name-set wrong: {off_names ^ expected}"

    _assert_test_wire_dstat_special_names_1()
    # a spaced name carries its real size on ours
    our_sz = {n: sz for n, sz, *_ in our_e}
    real = os.path.getsize(os.path.join(srv["our_data"], "special", "with space"))
    _check_test_wire_dstat_special_names_6(real, our_sz)

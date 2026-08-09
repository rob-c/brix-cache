from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_pathedge_helpers")

def test_stat_percent_literal_resolves_both(pair):
    """'/100%ok.txt' is a LITERAL name; it must resolve (no URL-decoding). Parity."""
    _assert_stat_parity(pair, "/100%ok.txt")


def test_cat_percent_literal_content_both(pair):
    """cat '/100%ok.txt' returns its content on both (no '%' decoding)."""
    _assert_cat_parity(pair, "/100%ok.txt", "percent-literal")


def test_percent_encoded_dot_not_decoded_both(pair):
    """'/100%2eok.txt' must NOT decode to '/100.ok.txt'; it's a different literal
    that does not exist -> not-found on both (proves no URL-decoding)."""
    o_rc = _stat_size(pair["our"], "/100%2eok.txt")[0]
    f_rc = _stat_size(pair["off"], "/100%2eok.txt")[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"DIVERGENCE '/100%2eok.txt' should be not-found (no URL-decode): " \
        f"our rc={o_rc} stock rc={f_rc}"


def test_plus_name_not_space_both(pair):
    """'/a+b.txt' is a literal '+' name (NOT a space); resolves, parity vs stock."""
    _assert_cat_parity(pair, "/a+b.txt", "plus-name")
    # And the space-decoded twin '/a b.txt' does NOT exist.
    o_rc = _stat_size(pair["our"], "/a b.txt")[0]
    f_rc = _stat_size(pair["off"], "/a b.txt")[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"'/a+b.txt' must not decode to a space-name: our rc={o_rc} stock rc={f_rc}"


# =========================================================================== #
# Odd-but-valid names: leading dots are real names, NOT the '.' component.
# =========================================================================== #
def test_stat_leading_dots_name_resolves_both(pair):
    """'/...threedots.txt' is a real file, NOT a '.' traversal. Parity vs stock."""
    _assert_stat_parity(pair, "/...threedots.txt")


def test_cat_hidden_dotfile_resolves_both(pair):
    """cat '/.hidden.txt' (leading dot, a real file) returns content on both;
    '.hidden' must NOT be treated as the '.' (current-dir) component."""
    _assert_cat_parity(pair, "/.hidden.txt", "hidden")


def test_hidden_dotfile_is_not_dot_component(pair):
    """stat '/.hidden.txt' resolves to that file (Size>0), proving '.hidden' is a
    name and not the '.' component (which would resolve to '/' = a dir)."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "/.hidden.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '/.hidden.txt': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"
        # A directory would carry IsDir; a real file must not.
        assert "IsDir" not in _stat_fields(o_out).get("Flags", ""), \
            "'.hidden.txt' wrongly treated as a directory ('.' component) on our server"


# =========================================================================== #
# Mutating ops on special-name paths: on-disk effect + rc parity. Unique paths.
# =========================================================================== #
def test_mkdir_rmdir_special_name_parity(pair):
    """mkdir/rmdir '/dir (x).d' (parens+space) -> rc + on-disk effect parity."""
    d = "/dir (x).d"
    disk = "dir (x).d"
    o_rc, _, _ = fs(pair["our"], "mkdir", d)
    f_rc, _, _ = fs(pair["off"], "mkdir", d)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE mkdir {d!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc):
        assert os.path.isdir(os.path.join(pair["our_data"], disk))
    if _ok(f_rc):
        assert os.path.isdir(os.path.join(pair["off_data"], disk))
    o_rrc, _, _ = fs(pair["our"], "rmdir", d)
    f_rrc, _, _ = fs(pair["off"], "rmdir", d)
    assert _ok(o_rrc) == _ok(f_rrc), \
        f"DIVERGENCE rmdir {d!r}: our rc={o_rrc} stock rc={f_rrc}"


def test_mv_special_name_parity(pair):
    """mv '/mv+src.txt' -> '/mv dst.txt' (plus -> space name): rc + effect parity."""
    with open(os.path.join(pair["our_data"], "mv+src.txt"), "w") as f:
        f.write("m")
    with open(os.path.join(pair["off_data"], "mv+src.txt"), "w") as f:
        f.write("m")
    o_rc, _, _ = fs(pair["our"], "mv", "/mv+src.txt", "/mv dst.txt")
    f_rc, _, _ = fs(pair["off"], "mv", "/mv+src.txt", "/mv dst.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE mv special: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc):
        assert os.path.exists(os.path.join(pair["our_data"], "mv dst.txt"))
    if _ok(f_rc):
        assert os.path.exists(os.path.join(pair["off_data"], "mv dst.txt"))


def test_chmod_special_name_parity(pair):
    """chmod '/chmod[b].txt' (brackets) -> rc parity across servers."""
    our_target = os.path.join(pair["our_data"], "chmod[b].txt")
    with open(our_target, "w") as f:
        f.write("c")
    off_target = os.path.join(pair["off_data"], "chmod[b].txt")
    with open(off_target, "w") as f:
        f.write("c")
    # BOTH servers' workers drop to `nobody` under the root harness, so each can
    # only chmod a file it owns — chown both sides, not just the stock one.
    L.chown_stock(our_target)
    L.chown_stock(off_target)
    o_rc, _, _ = fs(pair["our"], "chmod", "/chmod[b].txt", "rwxr-xr-x")
    f_rc, _, _ = fs(pair["off"], "chmod", "/chmod[b].txt", "rwxr-xr-x")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE chmod special: our rc={o_rc} stock rc={f_rc}"


def test_rm_special_name_parity(pair):
    """rm '/rm%lit.txt' (percent-literal) -> rc + effect parity."""
    with open(os.path.join(pair["our_data"], "rm%lit.txt"), "w") as f:
        f.write("r")
    with open(os.path.join(pair["off_data"], "rm%lit.txt"), "w") as f:
        f.write("r")
    o_rc, _, _ = fs(pair["our"], "rm", "/rm%lit.txt")
    f_rc, _, _ = fs(pair["off"], "rm", "/rm%lit.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE rm special: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc):
        assert not os.path.exists(os.path.join(pair["our_data"], "rm%lit.txt"))
    if _ok(f_rc):
        assert not os.path.exists(os.path.join(pair["off_data"], "rm%lit.txt"))


def test_mkdir_p_deep_special_parity(pair):
    """mkdir -p '/mkp1/mk b/mk(c)' (nested special names) -> rc + effect parity."""
    d = "/mkp1/mk b/mk(c)"
    o_rc, _, _ = fs(pair["our"], "mkdir", "-p", d)
    f_rc, _, _ = fs(pair["off"], "mkdir", "-p", d)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE mkdir -p {d!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc):
        assert os.path.isdir(os.path.join(pair["our_data"], "mkp1", "mk b", "mk(c)"))
    if _ok(f_rc):
        assert os.path.isdir(os.path.join(pair["off_data"], "mkp1", "mk b", "mk(c)"))


# =========================================================================== #
# download (xrdcp) of special-name files -> byte-exact (parametrized subset).
# =========================================================================== #
@pytest.mark.parametrize("name", [
    "a.b.c.txt", "file-with-dashes", "file_underscore",
    "100%ok.txt", "a+b.txt", "name(1).txt", "[bracket].txt",
    "...threedots.txt", ".hidden.txt", "UPPER.TXT",
])
def test_xrdcp_special_name_byte_exact(pair, name, tmp_path):
    """xrdcp '/<special>' from BOTH servers -> identical bytes, equal to disk."""
    a = str(tmp_path / ("dl_our_" + name.replace("/", "_")))
    b = str(tmp_path / ("dl_off_" + name.replace("/", "_")))
    rc_a, _, ea = L.run([L.OFF_XRDCP, "-f", f"{pair['our']}//{name}", a])
    rc_b, _, eb = L.run([L.OFF_XRDCP, "-f", f"{pair['off']}//{name}", b])
    assert _ok(rc_a) == _ok(rc_b), \
        f"DIVERGENCE xrdcp {name!r}: our rc={rc_a} stock rc={rc_b} ({ea}{eb})"
    if _ok(rc_a) and _ok(rc_b):
        with open(a, "rb") as fa, open(b, "rb") as fb:
            ga, gb = fa.read(), fb.read()
        assert ga == gb, f"xrdcp {name!r} bytes differ between servers"
        with open(os.path.join(pair["our_data"], name), "rb") as f:
            assert ga == f.read(), f"xrdcp {name!r} not byte-exact vs disk"


# =========================================================================== #
# Root / empty path.
# =========================================================================== #
def test_stat_root_is_dir_both(pair):
    """stat '/' reports IsDir on both servers."""
    o = _stat_fields(fs(pair["our"], "stat", "/")[1])
    f = _stat_fields(fs(pair["off"], "stat", "/")[1])
    assert "IsDir" in o.get("Flags", ""), f"our '/' not IsDir: {o.get('Flags')}"
    assert "IsDir" in f.get("Flags", ""), f"stock '/' not IsDir: {f.get('Flags')}"


def test_stat_empty_path_parity(pair):
    """stat '' (empty path) -> same success/failure category as stock."""
    o_rc = fs(pair["our"], "stat", "")[0]
    f_rc = fs(pair["off"], "stat", "")[0]
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE stat '': our rc={o_rc} stock rc={f_rc}"

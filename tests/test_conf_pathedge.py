"""Differential conformance for PATH & NAME edge cases.

The SAME path argument is driven through the STOCK xrdfs/xrdcp client against
BOTH our nginx-xrootd server and the stock xrootd server; we then assert the
two servers agree on success/failure category, and — where applicable — on the
returned Size and content bytes.

This file is about NAME / CGI / trailing-slash / length / depth / case breadth
across MANY operations.  It deliberately does NOT re-cover the `..` / traversal
/ confinement / normalization cases — those live in test_conf_paths.py.

Philosophy (per the maintainer): a divergence is a bug in THIS implementation.
  * Resolves differently, wrong size/content, wrong success/failure   -> BUG.
  * URL-decodes a literal '%', treats ".hidden" as the '.' traversal
    component, or mishandles an opaque/CGI suffix                      -> BUG.
We pin the STOCK server's behaviour as the reference for every probe.

Self-provisioning on high ports; skips entirely without the stock toolchain.
"""

import os

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Extra named files/dirs built identically on BOTH data roots so differential
# checks are byte-exact.  Names use only safe ASCII (no real UTF-8, no actual
# traversal sequences).
# --------------------------------------------------------------------------- #
SPECIAL_FILES = {
    "a b c.txt": "spaces-name\n",            # spaces
    "a.b.c.txt": "dots-name\n",              # multiple dots
    "UPPER.TXT": "upper-name\n",             # uppercase
    "lower.txt": "lower-name\n",             # lowercase twin (distinct file)
    "file-with-dashes": "dashes\n",          # dashes, no extension
    "file_underscore": "underscore\n",       # underscores
    "100%ok.txt": "percent-literal\n",       # literal percent (NOT %2e)
    "a+b.txt": "plus-name\n",                # plus sign
    "name(1).txt": "parens\n",               # parentheses
    "[bracket].txt": "bracket\n",            # square brackets
    "...threedots.txt": "threedots\n",       # leading dots, real name
    ".hidden.txt": "hidden\n",               # leading dot, NOT '.' component
}

# A long-but-valid single component (200 chars) and a long valid path.
LONGNAME = ("L" * 196) + ".txt"              # 200 chars
LONGNAME_BODY = "longname\n"

# Deeply nested path n1..n8/leaf.txt
DEEP8 = "/n1/n2/n3/n4/n5/n6/n7/n8/leaf.txt"
DEEP8_BODY = "deep8\n"


def _build_extras(root):
    """Create the special-name files identically on a data root."""
    j = os.path.join
    for name, body in SPECIAL_FILES.items():
        with open(j(root, name), "w") as f:
            f.write(body)
    with open(j(root, LONGNAME), "w") as f:
        f.write(LONGNAME_BODY)
    deep = j(root, "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8")
    os.makedirs(deep, exist_ok=True)
    with open(j(deep, "leaf.txt"), "w") as f:
        f.write(DEEP8_BODY)


# --------------------------------------------------------------------------- #
# Fixture: launch our server + the stock server on identical rich trees, then
# decorate both data roots with the extra named files.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confpathedge"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14038), off_port=L.worker_port(14039))
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    _build_extras(ctx["our_data"])
    _build_extras(ctx["off_data"])
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def _stat_fields(out):
    d = {}
    for line in (out or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def _ls_set(out):
    return {os.path.basename(l.strip()) for l in (out or "").splitlines()
            if l.strip()}


def _ok(rc):
    return rc == 0


def _cat(url, path):
    return fs(url, "cat", path)


def _stat_size(url, path):
    rc, out, err = fs(url, "stat", path)
    return rc, _stat_fields(out).get("Size"), out, err


def _both_stat(pair, path):
    """Return (our_rc, our_size, off_rc, off_size, our_out, off_out)."""
    o_rc, o_sz, o_out, _ = _stat_size(pair["our"], path)
    f_rc, f_sz, f_out, _ = _stat_size(pair["off"], path)
    return o_rc, o_sz, f_rc, f_sz, o_out, f_out


def _assert_stat_parity(pair, path):
    """stat parity helper: same success/failure category; if both ok, same Size."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, path)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE stat {path!r}: our rc={o_rc} stock rc={f_rc} " \
        f"(our={o_out!r} stock={f_out!r})"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, \
            f"size mismatch stat {path!r}: ours={o_sz} stock={f_sz}"
    return o_rc, f_rc


def _assert_cat_parity(pair, path, needle=None):
    """cat parity helper: same category; if both ok and needle given, content matches."""
    o_rc, o_out, _ = _cat(pair["our"], path)
    f_rc, f_out, _ = _cat(pair["off"], path)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE cat {path!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc) and needle is not None:
        assert needle in o_out, f"cat {path!r}: {needle!r} not in our output {o_out!r}"
        assert needle in f_out, f"cat {path!r}: {needle!r} not in stock output {f_out!r}"
    return o_rc, f_rc


# =========================================================================== #
# Oracle: prove the test/tooling itself is sound against the stock server.
# =========================================================================== #
def test_oracle_stat_off(pair):
    rc, out, _ = fs(pair["off"], "stat", "/hello.txt")
    assert rc == 0 and "Size:" in out


def test_oracle_stat_our(pair):
    rc, out, _ = fs(pair["our"], "stat", "/hello.txt")
    assert rc == 0 and "Size:" in out


def test_oracle_special_files_exist_on_disk(pair):
    """Sanity: the extra named files were created on BOTH data roots."""
    for name in SPECIAL_FILES:
        assert os.path.exists(os.path.join(pair["our_data"], name)), name
        assert os.path.exists(os.path.join(pair["off_data"], name)), name


# =========================================================================== #
# SPECIAL-NAME files: stat resolves to the right file, Size matches stock.
# (12 parametrized)
# =========================================================================== #
@pytest.mark.parametrize("name", list(SPECIAL_FILES.keys()))
def test_stat_special_name_matches_stock(pair, name):
    """stat '/<special>' resolves to the right file; Size matches stock."""
    _assert_stat_parity(pair, "/" + name)


# SPECIAL-NAME files: cat returns the right content, parity vs stock.
# (12 parametrized)
@pytest.mark.parametrize("name,body", list(SPECIAL_FILES.items()))
def test_cat_special_name_matches_stock(pair, name, body):
    """cat '/<special>' returns that file's content on both servers."""
    needle = body.strip()
    o_rc, f_rc = _assert_cat_parity(pair, "/" + name, needle)
    assert _ok(o_rc), f"cat '/{name}' failed on our server"


# =========================================================================== #
# ls of a dir containing special-name entries -> exact names on both.
# =========================================================================== #
def test_ls_root_special_names_present_both(pair):
    """ls '/' shows every special-name file, identically on both servers."""
    o = _ls_set(fs(pair["our"], "ls", "/")[1])
    f = _ls_set(fs(pair["off"], "ls", "/")[1])
    for name in SPECIAL_FILES:
        assert name in o, f"our ls '/' missing {name!r}: {sorted(o)}"
        assert name in f, f"stock ls '/' missing {name!r}: {sorted(f)}"


def test_ls_l_special_names_present_both(pair):
    """ls -l '/' carries the special-name files on both servers."""
    o_rc, o_out, _ = fs(pair["our"], "ls", "-l", "/")
    f_rc, f_out, _ = fs(pair["off"], "ls", "-l", "/")
    assert _ok(o_rc) and _ok(f_rc)
    for name in ("a b c.txt", "100%ok.txt", "[bracket].txt", ".hidden.txt"):
        assert any(name in l for l in o_out.splitlines()), \
            f"our ls -l '/' missing {name!r}"
        assert any(name in l for l in f_out.splitlines()), \
            f"stock ls -l '/' missing {name!r}"


def test_ls_special_subset_equality(pair):
    """The set of special names exposed by '/' must be identical across servers."""
    o = _ls_set(fs(pair["our"], "ls", "/")[1]) & set(SPECIAL_FILES)
    f = _ls_set(fs(pair["off"], "ls", "/")[1]) & set(SPECIAL_FILES)
    assert o == f == set(SPECIAL_FILES), \
        f"DIVERGENCE special-name listing: ours={sorted(o)} stock={sorted(f)}"


# =========================================================================== #
# Spaces in names via xrdfs (quoted argv) and via xrdcp.
# =========================================================================== #
def test_stat_space_name_xrdfs(pair):
    """stat '/a b c.txt' (spaces) via xrdfs argv -> Size parity."""
    _assert_stat_parity(pair, "/a b c.txt")


def test_cat_space_name_xrdfs(pair):
    """cat '/a b c.txt' (spaces) via xrdfs argv -> content parity."""
    _assert_cat_parity(pair, "/a b c.txt", "spaces-name")


def test_xrdcp_space_name_download_byte_exact(pair, tmp_path):
    """xrdcp '/a b c.txt' from BOTH servers -> identical bytes, equal to disk."""
    a = str(tmp_path / "space_our.txt")
    b = str(tmp_path / "space_off.txt")
    rc_a, oa, ea = L.run([L.OFF_XRDCP, "-f", f"{pair['our']}//a b c.txt", a])
    rc_b, ob, eb = L.run([L.OFF_XRDCP, "-f", f"{pair['off']}//a b c.txt", b])
    assert _ok(rc_a) == _ok(rc_b), \
        f"DIVERGENCE xrdcp '/a b c.txt': our rc={rc_a} stock rc={rc_b} ({ea}{eb})"
    if _ok(rc_a) and _ok(rc_b):
        with open(a, "rb") as fa, open(b, "rb") as fb:
            ga, gb = fa.read(), fb.read()
        assert ga == gb, "xrdcp space-name bytes differ between servers"
        with open(os.path.join(pair["our_data"], "a b c.txt"), "rb") as f:
            assert ga == f.read(), "xrdcp space-name not byte-exact vs disk"


# =========================================================================== #
# TRAILING SLASH per op, on a dir ('/sub/'), on a file ('/hello.txt/').
# Parametrized (op, path).  Behaviour category must match stock for each.
# =========================================================================== #
@pytest.mark.parametrize("path", ["/sub/", "/sub", "/hello.txt/", "/hello.txt"])
def test_trailing_slash_stat_parity(pair, path):
    """stat parity for trailing-slash variants of a dir and a file."""
    _assert_stat_parity(pair, path)


@pytest.mark.parametrize("path", ["/sub/", "/sub", "/hello.txt/", "/hello.txt"])
def test_trailing_slash_ls_parity(pair, path):
    """ls parity for trailing-slash variants; if both ok, listings match."""
    o_rc, o_out, _ = fs(pair["our"], "ls", path)
    f_rc, f_out, _ = fs(pair["off"], "ls", path)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE ls {path!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert _ls_set(o_out) == _ls_set(f_out), \
            f"DIVERGENCE ls {path!r}: ours={_ls_set(o_out)} stock={_ls_set(f_out)}"


@pytest.mark.parametrize("path", ["/hello.txt/", "/hello.txt"])
def test_trailing_slash_cat_parity(pair, path):
    """cat parity for a file with and without a trailing slash."""
    _assert_cat_parity(pair, path, "hello world")


def test_trailing_slash_mkdir_parity(pair):
    """mkdir '/tsmk1/' (trailing slash) — rc + on-disk effect parity across servers."""
    o_rc, _, _ = fs(pair["our"], "mkdir", "/tsmk1/")
    f_rc, _, _ = fs(pair["off"], "mkdir", "/tsmk1/")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE mkdir '/tsmk1/': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc):
        assert os.path.isdir(os.path.join(pair["our_data"], "tsmk1"))
    if _ok(f_rc):
        assert os.path.isdir(os.path.join(pair["off_data"], "tsmk1"))


def test_trailing_slash_rm_on_file_parity(pair):
    """rm '/tsrm.txt/' (file + trailing slash) — rc parity; created on both."""
    with open(os.path.join(pair["our_data"], "tsrm.txt"), "w") as f:
        f.write("x")
    with open(os.path.join(pair["off_data"], "tsrm.txt"), "w") as f:
        f.write("x")
    o_rc, _, _ = fs(pair["our"], "rm", "/tsrm.txt/")
    f_rc, _, _ = fs(pair["off"], "rm", "/tsrm.txt/")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE rm '/tsrm.txt/': our rc={o_rc} stock rc={f_rc}"
    # If a server accepted it, the file must be gone there.
    if _ok(o_rc):
        assert not os.path.exists(os.path.join(pair["our_data"], "tsrm.txt"))
    if _ok(f_rc):
        assert not os.path.exists(os.path.join(pair["off_data"], "tsrm.txt"))


def test_trailing_slash_rm_dir_as_file_parity(pair):
    """rm '/tsrmdir/' (a NON-EMPTY directory via rm, with a trailing slash) — error
    category parity (rm is for files), AND no partial content deletion: if rm fails
    the directory's child file must still be present on that server.

    Uses a dedicated directory (never the shared '/sub' baseline) so this mutation
    is independent and cannot poison other tests."""
    for root in (pair["our_data"], pair["off_data"]):
        os.makedirs(os.path.join(root, "tsrmdir"), exist_ok=True)
        with open(os.path.join(root, "tsrmdir", "child.txt"), "w") as f:
            f.write("child\n")
    o_rc, _, _ = fs(pair["our"], "rm", "/tsrmdir/")
    f_rc, _, _ = fs(pair["off"], "rm", "/tsrmdir/")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE rm '/tsrmdir/': our rc={o_rc} stock rc={f_rc}"
    # If a server refused the rm, it must not have silently deleted the child.
    if not _ok(o_rc):
        assert os.path.exists(os.path.join(pair["our_data"], "tsrmdir", "child.txt")), \
            "DATA LOSS: our server failed rm '/tsrmdir/' but deleted its child file"
    if not _ok(f_rc):
        assert os.path.exists(os.path.join(pair["off_data"], "tsrmdir", "child.txt"))


# =========================================================================== #
# DOUBLE / leading slashes -> collapse; stat Size matches stock. (parametrized)
# =========================================================================== #
@pytest.mark.parametrize("path", [
    "//hello.txt",
    "///hello.txt",
    "/sub//nested.txt",
    "//sub//nested.txt",
    "/sub///nested.txt",
])
def test_double_slash_stat_size_matches_stock(pair, path):
    """Repeated slashes collapse; stat Size matches stock."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, path)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE stat {path!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch {path!r}: ours={o_sz} stock={f_sz}"


@pytest.mark.parametrize("path", ["//hello.txt", "///hello.txt", "/sub//nested.txt"])
def test_double_slash_cat_matches_stock(pair, path):
    """cat through collapsed slashes returns content on both."""
    needle = "hello world" if "hello" in path else "nested"
    _assert_cat_parity(pair, path, needle)


# =========================================================================== #
# OPAQUE / CGI suffix per op: opaque ignored, op succeeds, content correct.
# Parametrized (op, cgi-path).
# =========================================================================== #
CGI_STAT_PATHS = [
    "/hello.txt?xrd.wantprot=unix",
    "/data.bin?authz=xyz",
    "/sz_4096.bin?foo=bar&baz=1",
    "/hello.txt?a=1&b=2&c=3",
    "/data.bin?k=v;other=z",
    "/hello.txt?eq=a=b&amp=c&d",
]


@pytest.mark.parametrize("path", CGI_STAT_PATHS)
def test_opaque_stat_matches_stock(pair, path):
    """stat with an opaque/CGI suffix: opaque ignored, Size parity vs stock."""
    base = path.split("?", 1)[0]
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, path)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE stat {path!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch {path!r}: ours={o_sz} stock={f_sz}"
        # opaque must not change the resolved file: same Size as the bare path.
        bare = _stat_size(pair["our"], base)[1]
        assert o_sz == bare, \
            f"opaque changed resolution: {path!r} size {o_sz} != bare {bare}"


@pytest.mark.parametrize("path", [
    "/hello.txt?xrd.wantprot=unix",
    "/hello.txt?a=1&b=2&c=3",
    "/hello.txt?k=v;other=z",
])
def test_opaque_cat_returns_content(pair, path):
    """cat with an opaque/CGI suffix returns the file content (opaque dropped)."""
    _assert_cat_parity(pair, path, "hello world")


def test_opaque_download_byte_exact(pair, tmp_path):
    """xrdcp '/data.bin?foo=bar&baz=1' downloads the bare file, byte-exact, both."""
    a = str(tmp_path / "cgi_our.bin")
    b = str(tmp_path / "cgi_off.bin")
    rc_a, _, ea = L.run([L.OFF_XRDCP, "-f", f"{pair['our']}//data.bin?foo=bar&baz=1", a])
    rc_b, _, eb = L.run([L.OFF_XRDCP, "-f", f"{pair['off']}//data.bin?foo=bar&baz=1", b])
    assert _ok(rc_a) == _ok(rc_b), \
        f"DIVERGENCE xrdcp cgi: our rc={rc_a} stock rc={rc_b} ({ea}{eb})"
    if _ok(rc_a) and _ok(rc_b):
        with open(a, "rb") as fa, open(b, "rb") as fb:
            ga, gb = fa.read(), fb.read()
        assert ga == gb, "xrdcp cgi bytes differ between servers"
        with open(os.path.join(pair["our_data"], "data.bin"), "rb") as f:
            assert ga == f.read(), "xrdcp cgi suffix changed the bytes vs disk"


def test_opaque_embedded_equals_amp_semicolon(pair):
    """CGI with embedded '=', '&', ';' still parsed as opaque; path resolves. Parity."""
    p = "/hello.txt?token=a=b&scope=read;write&n"
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, p)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE stat {p!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        bare = _stat_size(pair["our"], "/hello.txt")[1]
        assert o_sz == f_sz == bare, \
            f"embedded-CGI changed resolution: ours={o_sz} stock={f_sz} bare={bare}"


# =========================================================================== #
# LONG name / over-long path.
# =========================================================================== #
def test_stat_long_name_matches_stock(pair):
    """stat the 200-char-name file -> Size parity vs stock."""
    _assert_stat_parity(pair, "/" + LONGNAME)


def test_cat_long_name_matches_stock(pair):
    """cat the 200-char-name file -> content parity vs stock."""
    o_rc, f_rc = _assert_cat_parity(pair, "/" + LONGNAME, "longname")
    assert _ok(o_rc), "cat long-name file failed on our server"


def test_over_long_path_rejected_both(pair):
    """A path far longer than any sane PATH_MAX is rejected on both (error parity).

    A short per-call timeout keeps a pathological client hang from poisoning the
    rest of the module; a timeout is itself a non-success and counts as rejection.
    """
    huge = "/" + ("x" * 2000) + ".txt"
    o_rc = fs(pair["our"], "stat", huge, timeout=15)[0]
    f_rc = fs(pair["off"], "stat", huge, timeout=15)[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"DIVERGENCE over-long path should fail on both: our rc={o_rc} stock rc={f_rc}"


def test_over_long_component_rejected_both(pair):
    """A single component > NAME_MAX (255) is rejected on both (error parity)."""
    huge = "/" + ("y" * 1000) + ".txt"
    o_rc = _stat_size(pair["our"], huge)[0]
    f_rc = _stat_size(pair["off"], huge)[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"DIVERGENCE over-long component should fail on both: our rc={o_rc} stock rc={f_rc}"


# =========================================================================== #
# DEEP path n1..n8/leaf.txt + over-deep path.
# =========================================================================== #
def test_stat_deep8_matches_stock(pair):
    """stat '/n1/.../n8/leaf.txt' -> Size parity vs stock."""
    _assert_stat_parity(pair, DEEP8)


def test_cat_deep8_matches_stock(pair):
    """cat '/n1/.../n8/leaf.txt' -> content parity vs stock."""
    o_rc, f_rc = _assert_cat_parity(pair, DEEP8, "deep8")
    assert _ok(o_rc), "cat deep8 leaf failed on our server"


def test_ls_deep8_parent_matches_stock(pair):
    """ls '/n1/n2/n3/n4/n5/n6/n7/n8' lists 'leaf.txt' on both servers."""
    o_rc, o_out, _ = fs(pair["our"], "ls", "/n1/n2/n3/n4/n5/n6/n7/n8")
    f_rc, f_out, _ = fs(pair["off"], "ls", "/n1/n2/n3/n4/n5/n6/n7/n8")
    assert _ok(o_rc) and _ok(f_rc)
    assert _ls_set(o_out) == _ls_set(f_out) == {"leaf.txt"}, \
        f"DIVERGENCE deep8 ls: ours={_ls_set(o_out)} stock={_ls_set(f_out)}"


def test_over_deep_nonexistent_path_not_found_both(pair):
    """A very deep but nonexistent path -> not-found on both (error parity)."""
    p = "/" + "/".join("d%d" % i for i in range(64)) + "/leaf.txt"
    o_rc = _stat_size(pair["our"], p)[0]
    f_rc = _stat_size(pair["off"], p)[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"DIVERGENCE over-deep path should be not-found: our rc={o_rc} stock rc={f_rc}"


# =========================================================================== #
# CASE sensitivity.
# =========================================================================== #
def test_stat_case_wrong_not_found_both(pair):
    """stat '/HELLO.TXT' (only '/hello.txt' exists) -> not-found on both."""
    o_rc = _stat_size(pair["our"], "/HELLO.TXT")[0]
    f_rc = _stat_size(pair["off"], "/HELLO.TXT")[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"DIVERGENCE '/HELLO.TXT' should be not-found: our rc={o_rc} stock rc={f_rc}"


def test_stat_case_exact_upper_ok_both(pair):
    """stat '/UPPER.TXT' (exists exactly) -> ok with same Size on both."""
    _assert_stat_parity(pair, "/UPPER.TXT")


def test_stat_case_distinct_twins_both(pair):
    """'/UPPER.TXT' and '/lower.txt' are DISTINCT files; both resolve, content differs."""
    _assert_cat_parity(pair, "/UPPER.TXT", "upper-name")
    _assert_cat_parity(pair, "/lower.txt", "lower-name")


def test_stat_case_lower_of_upper_not_found_both(pair):
    """stat '/upper.txt' (only '/UPPER.TXT' exists) -> not-found on both."""
    o_rc = _stat_size(pair["our"], "/upper.txt")[0]
    f_rc = _stat_size(pair["off"], "/upper.txt")[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"DIVERGENCE '/upper.txt' should be not-found: our rc={o_rc} stock rc={f_rc}"


# =========================================================================== #
# Percent-literal name: NO URL-decoding of the path.
# =========================================================================== #
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
    with open(os.path.join(pair["our_data"], "chmod[b].txt"), "w") as f:
        f.write("c")
    with open(os.path.join(pair["off_data"], "chmod[b].txt"), "w") as f:
        f.write("c")
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

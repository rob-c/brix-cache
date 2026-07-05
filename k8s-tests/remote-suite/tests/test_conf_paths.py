"""Differential conformance for PATH handling + namespace confinement.

Same path argument is driven through the STOCK xrdfs client against BOTH our
nginx-xrootd server and the stock xrootd server; we then assert the two servers
agree (same success/failure category, same returned size/content) for every
normalization probe, and — critically — that NO path traversal escapes our
exported root.

Philosophy (per the maintainer): a divergence is a bug in THIS implementation.
  * A normalization result that differs from stock  -> BUG in our server.
  * ANY confinement bypass (host file leaked, rc==0 on a "/.."-style path)
    -> HIGH-severity security BUG in our server.

For the confinement probes the assertion is simply "our server rejects
(rc != 0) and returns no host-file bytes"; we do not demand the exact same
error code as stock there, only denial.

Self-provisioning on high ports; skips entirely without the stock toolchain.
"""

import os

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Fixture: launch our server + the stock server on identical rich trees.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confpaths"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14010), off_port=L.worker_port(14011))
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
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


def _ok(rc):
    return rc == 0


# =========================================================================== #
# Oracle: prove the test/tooling itself is sound against the stock server.
# =========================================================================== #
def test_oracle_stat_hello(pair):
    rc, out, _ = fs(pair["off"], "stat", "/hello.txt")
    assert rc == 0 and "Size:" in out


def test_oracle_stat_our_hello(pair):
    rc, out, _ = fs(pair["our"], "stat", "/hello.txt")
    assert rc == 0 and "Size:" in out


# =========================================================================== #
# Trailing-slash normalization
# =========================================================================== #
def test_stat_file_trailing_slash_matches_stock(pair):
    """stat '/hello.txt/' — a file used as a dir; both must agree on category."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "/hello.txt/")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '/hello.txt/': our rc={o_rc} stock rc={f_rc} " \
        f"(our={o_out!r} stock={f_out!r})"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_stat_dir_trailing_slash_matches_stock(pair):
    """stat '/sub/' — trailing slash on a real dir; same category as stock."""
    o = _stat_fields(fs(pair["our"], "stat", "/sub/")[1])
    f = _stat_fields(fs(pair["off"], "stat", "/sub/")[1])
    o_rc = fs(pair["our"], "stat", "/sub/")[0]
    f_rc = fs(pair["off"], "stat", "/sub/")[0]
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '/sub/': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert ("IsDir" in o.get("Flags", "")) == ("IsDir" in f.get("Flags", "")), \
            f"IsDir mismatch ours={o.get('Flags')} stock={f.get('Flags')}"


def test_ls_dir_trailing_slash_matches_no_slash(pair):
    """ls '/sub/' must list exactly what ls '/sub' does, on both servers."""
    our_a = _ls_set(fs(pair["our"], "ls", "/sub")[1])
    our_b = _ls_set(fs(pair["our"], "ls", "/sub/")[1])
    off_b = _ls_set(fs(pair["off"], "ls", "/sub/")[1])
    assert our_a == our_b, f"our ls '/sub' vs '/sub/' differ: {our_a} vs {our_b}"
    assert our_b == off_b, f"DIVERGENCE ls '/sub/': ours={our_b} stock={off_b}"


# =========================================================================== #
# Double-slash normalization
# =========================================================================== #
def test_stat_leading_double_slash_matches_stock(pair):
    """stat '//hello.txt' collapses to '/hello.txt'; size matches stock."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "//hello.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '//hello.txt': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_stat_interior_double_slash_matches_stock(pair):
    """stat '/sub//nested.txt' collapses; size matches stock."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "/sub//nested.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '/sub//nested.txt': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_cat_double_slash_returns_content(pair):
    """cat '//hello.txt' yields the file content on both servers if either does."""
    o_rc, o_out, _ = _cat(pair["our"], "//hello.txt")
    f_rc, f_out, _ = _cat(pair["off"], "//hello.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE cat '//hello.txt': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert "hello world" in o_out and "hello world" in f_out


# =========================================================================== #
# '.' / '..' interior normalization (resolve to the right file)
# =========================================================================== #
def test_stat_dotdot_segment_matches_stock(pair):
    """'/sub/../hello.txt' — stock XRootD REJECTS any '..' segment outright
    (err 3010 'relative path ... is disallowed'); it does not normalize it.
    Our server must agree: same success/failure category as stock.  Silently
    resolving '..' is a divergence from the reference contract.

    If both servers DO happen to succeed, the resolved size must still match
    (and must equal /hello.txt) so a successful resolution can't point
    elsewhere."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "/sub/../hello.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '/sub/../hello.txt': our rc={o_rc} stock rc={f_rc} " \
        f"(stock rejects '..' segments; our server must too)"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"
        real = _stat_size(pair["our"], "/hello.txt")[1]
        assert o_sz == real, f"'/sub/../hello.txt' size {o_sz} != /hello.txt {real}"


def test_stat_leading_dot_resolves(pair):
    """'/./hello.txt' -> '/hello.txt'; size matches stock."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "/./hello.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '/./hello.txt': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_stat_interior_dot_resolves(pair):
    """'/sub/./nested.txt' -> '/sub/nested.txt'; size matches stock."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "/sub/./nested.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '/sub/./nested.txt': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_cat_dotdot_segment_matches_stock(pair):
    """cat '/sub/../hello.txt' — same '..' contract as stat: stock rejects the
    '..' segment, so our server must share the success/failure category."""
    o_rc, o_out, _ = _cat(pair["our"], "/sub/../hello.txt")
    f_rc, f_out, _ = _cat(pair["off"], "/sub/../hello.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE cat '/sub/../hello.txt': our rc={o_rc} stock rc={f_rc} " \
        f"(stock rejects '..'; our server must too)"
    if _ok(o_rc) and _ok(f_rc):
        assert "hello world" in o_out and "hello world" in f_out


# =========================================================================== #
# Deep nesting
# =========================================================================== #
def test_stat_deep_leaf_matches_stock(pair):
    """stat '/deep/a/b/c/leaf.txt' works on both; size matches."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "/deep/a/b/c/leaf.txt")
    assert _ok(o_rc) and _ok(f_rc), \
        f"deep leaf stat failed: our rc={o_rc} stock rc={f_rc}"
    assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_cat_deep_leaf_matches_stock(pair):
    """cat '/deep/a/b/c/leaf.txt' returns 'leaf' on both."""
    o_rc, o_out, _ = _cat(pair["our"], "/deep/a/b/c/leaf.txt")
    f_rc, f_out, _ = _cat(pair["off"], "/deep/a/b/c/leaf.txt")
    assert _ok(o_rc) and _ok(f_rc), \
        f"deep leaf cat failed: our rc={o_rc} stock rc={f_rc}"
    assert "leaf" in o_out and "leaf" in f_out


def test_stat_deep_with_dot_segments_matches_stock(pair):
    """A long valid path threaded with '.' segments under /deep matches stock."""
    p = "/deep/./a/b/./c/leaf.txt"
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, p)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE {p!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_stat_deep_dotdot_back_into_tree_matches_stock(pair):
    """'/deep/a/b/c/../../b/c/leaf.txt' — an interior '..' that rejoins the same
    subtree. Stock still rejects it outright ('..' disallowed); our server must
    share the success/failure category. If both succeed, the size must equal the
    canonical leaf so a resolution can't silently point elsewhere."""
    p = "/deep/a/b/c/../../b/c/leaf.txt"
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, p)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE {p!r}: our rc={o_rc} stock rc={f_rc} " \
        f"(stock rejects '..'; our server must too)"
    if _ok(o_rc) and _ok(f_rc):
        real = _stat_size(pair["our"], "/deep/a/b/c/leaf.txt")[1]
        assert o_sz == real == f_sz, \
            f"deep '..' rejoin size mismatch ours={o_sz} stock={f_sz} real={real}"


# =========================================================================== #
# Path with a space
# =========================================================================== #
def test_stat_space_path_matches_stock(pair):
    """stat '/with space.txt' size matches stock."""
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, "/with space.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE '/with space.txt': our rc={o_rc} stock rc={f_rc} " \
        f"(our={o_out!r} stock={f_out!r})"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_cat_space_path_matches_stock(pair):
    """cat '/with space.txt' returns content on both."""
    o_rc, o_out, _ = _cat(pair["our"], "/with space.txt")
    f_rc, f_out, _ = _cat(pair["off"], "/with space.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE cat '/with space.txt': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert "spaced" in o_out and "spaced" in f_out


# =========================================================================== #
# CONFINEMENT (HIGH severity) — traversal MUST be denied on our server.
# We require: our rc != 0 AND no host-file bytes returned.  We do not demand
# the same error code as stock, only denial + no leak.
# =========================================================================== #
HOST_SECRET_MARKERS = ("root:x:", "root:*:", "/bin/bash", "/bin/sh", "daemon:")


def _looks_like_passwd(text):
    s = text or ""
    return any(m in s for m in HOST_SECRET_MARKERS)


@pytest.mark.parametrize("evil", [
    "/../etc/passwd",
    "/../../etc/passwd",
    "/../../../../../../etc/passwd",
    "/sub/../../etc/passwd",
    "/deep/a/b/c/../../../../../etc/passwd",
])
def test_confinement_stat_traversal_denied(pair, evil):
    """stat of a traversal path MUST be denied by our server and leak nothing."""
    rc, out, err = fs(pair["our"], "stat", evil)
    assert rc != 0, \
        f"CONFINEMENT BYPASS (HIGH): our server stat {evil!r} returned rc=0: {out!r}"
    assert not _looks_like_passwd(out + err), \
        f"CONFINEMENT LEAK (HIGH): our server leaked host file via {evil!r}: {out!r}"


@pytest.mark.parametrize("evil", [
    "/../etc/passwd",
    "/../../etc/passwd",
    "/sub/../../etc/passwd",
])
def test_confinement_cat_traversal_denied(pair, evil):
    """cat of a traversal path MUST be denied and return no /etc/passwd bytes."""
    rc, out, err = _cat(pair["our"], evil)
    assert rc != 0, \
        f"CONFINEMENT BYPASS (HIGH): our server cat {evil!r} returned rc=0"
    assert not _looks_like_passwd(out + err), \
        f"CONFINEMENT LEAK (HIGH): our server leaked host file via cat {evil!r}: {out!r}"


def test_confinement_url_encoded_traversal_denied(pair):
    """A %2e%2e (percent-encoded '..') traversal MUST NOT escape the root.

    XRootD does not URL-decode paths, so this should resolve to a literal,
    nonexistent name — but it must NEVER reach /etc/passwd. We assert denial
    and no leak on OUR server (the security property is denial, not the code)."""
    evil = "/%2e%2e/%2e%2e/etc/passwd"
    rc, out, err = fs(pair["our"], "stat", evil)
    assert rc != 0, \
        f"CONFINEMENT BYPASS (HIGH): our server stat {evil!r} returned rc=0: {out!r}"
    assert not _looks_like_passwd(out + err), \
        f"CONFINEMENT LEAK (HIGH): our server leaked host file via {evil!r}: {out!r}"


def test_confinement_download_traversal_denied(pair, tmp_path):
    """xrdcp of a traversal path from OUR server must fail and write no secret."""
    dst = str(tmp_path / "stolen")
    rc, out, err = L.run([L.OFF_XRDCP, "-f",
                          f"{pair['our']}//../../etc/passwd", dst])
    assert rc != 0, \
        "CONFINEMENT BYPASS (HIGH): xrdcp of '//../../etc/passwd' from OUR server succeeded"
    if os.path.exists(dst):
        with open(dst, "rb") as f:
            body = f.read()
        assert not _looks_like_passwd(body.decode("latin-1")), \
            "CONFINEMENT LEAK (HIGH): xrdcp pulled /etc/passwd through OUR server"


# =========================================================================== #
# Opaque / CGI suffix — must be ignored (path is everything before '?').
# =========================================================================== #
def test_stat_opaque_wantprot_matches_stock(pair):
    """stat '/hello.txt?xrd.wantprot=unix' ignores opaque; size matches stock."""
    p = "/hello.txt?xrd.wantprot=unix"
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, p)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE {p!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_stat_opaque_arbitrary_cgi_matches_stock(pair):
    """stat '/data.bin?foo=bar' ignores opaque; size 4096 matches stock."""
    p = "/data.bin?foo=bar"
    o_rc, o_sz, f_rc, f_sz, o_out, f_out = _both_stat(pair, p)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE {p!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert o_sz == f_sz, f"size mismatch ours={o_sz} stock={f_sz}"


def test_cat_opaque_returns_content(pair):
    """cat '/hello.txt?foo=bar' returns content (opaque dropped) on both."""
    p = "/hello.txt?foo=bar"
    o_rc, o_out, _ = _cat(pair["our"], p)
    f_rc, f_out, _ = _cat(pair["off"], p)
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE cat {p!r}: our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert "hello world" in o_out and "hello world" in f_out


# =========================================================================== #
# File-as-directory / dir-as-file category checks
# =========================================================================== #
def test_ls_on_file_category_matches_stock(pair):
    """ls '/hello.txt' (a file) — error category must match stock."""
    o_rc, o_out, o_err = fs(pair["our"], "ls", "/hello.txt")
    f_rc, f_out, f_err = fs(pair["off"], "ls", "/hello.txt")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE ls '/hello.txt': our rc={o_rc} stock rc={f_rc} " \
        f"(our={o_out + o_err!r} stock={f_out + f_err!r})"


def test_stat_dir_as_file_open_category_matches_stock(pair):
    """cat '/sub' (a directory) — category must match stock."""
    o_rc, o_out, o_err = _cat(pair["our"], "/sub")
    f_rc, f_out, f_err = _cat(pair["off"], "/sub")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE cat '/sub': our rc={o_rc} stock rc={f_rc}"


# =========================================================================== #
# Root / empty path
# =========================================================================== #
def test_stat_root_is_dir_both(pair):
    """stat '/' must report IsDir on both servers."""
    o = _stat_fields(fs(pair["our"], "stat", "/")[1])
    f = _stat_fields(fs(pair["off"], "stat", "/")[1])
    assert "IsDir" in o.get("Flags", ""), f"our '/' not IsDir: {o.get('Flags')}"
    assert "IsDir" in f.get("Flags", ""), f"stock '/' not IsDir: {f.get('Flags')}"


def test_ls_empty_dir_matches_stock(pair):
    """ls '/empty_dir' yields the same (empty) listing on both servers."""
    o_rc, o_out, _ = fs(pair["our"], "ls", "/empty_dir")
    f_rc, f_out, _ = fs(pair["off"], "ls", "/empty_dir")
    assert _ok(o_rc) == _ok(f_rc), \
        f"DIVERGENCE ls '/empty_dir': our rc={o_rc} stock rc={f_rc}"
    if _ok(o_rc) and _ok(f_rc):
        assert _ls_set(o_out) == _ls_set(f_out), \
            f"empty_dir listing differs ours={_ls_set(o_out)} stock={_ls_set(f_out)}"


# =========================================================================== #
# Case sensitivity & nonexistent paths
# =========================================================================== #
def test_stat_case_sensitive_not_found_both(pair):
    """stat '/HELLO.TXT' must be not-found on both (case-sensitive namespace)."""
    o_rc = _stat_size(pair["our"], "/HELLO.TXT")[0]
    f_rc = _stat_size(pair["off"], "/HELLO.TXT")[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"DIVERGENCE '/HELLO.TXT' should be not-found: our rc={o_rc} stock rc={f_rc}"


def test_stat_nonexistent_deep_not_found_both(pair):
    """stat a nonexistent deep path -> not found on both."""
    p = "/deep/a/b/c/nope.txt"
    o_rc = _stat_size(pair["our"], p)[0]
    f_rc = _stat_size(pair["off"], p)[0]
    assert (not _ok(o_rc)) and (not _ok(f_rc)), \
        f"DIVERGENCE {p!r} should be not-found: our rc={o_rc} stock rc={f_rc}"


def test_ls_many_dir_matches_stock(pair):
    """ls '/many' enumerates the same 12 files on both servers."""
    o_rc, o_out, _ = fs(pair["our"], "ls", "/many")
    f_rc, f_out, _ = fs(pair["off"], "ls", "/many")
    assert _ok(o_rc) and _ok(f_rc), \
        f"ls '/many' failed: our rc={o_rc} stock rc={f_rc}"
    assert _ls_set(o_out) == _ls_set(f_out), \
        f"DIVERGENCE ls '/many': ours={_ls_set(o_out)} stock={_ls_set(f_out)}"

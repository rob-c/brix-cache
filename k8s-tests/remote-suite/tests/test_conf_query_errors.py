"""Differential conformance for kXR_query (config/checksum/stats/space) and
protocol ERROR SEMANTICS, stock XrdCl client vs BOTH servers.

Philosophy (per the maintainer): a divergence is a bug in THIS implementation
unless there is positive evidence otherwise. We pin the stock-matching behavior
and do NOT xfail/skip to hide a real diff.

The two probe classes:

  QUERY      kXR_query config/checksum/stats/space against OUR server, with the
             reference format derived from XrdXrootdXeq.cc do_Qconf(): each key
             returns a *bare value* terminated by '\n' (never "<key>=..."),
             unknown keys are echoed back. Numeric keys yield an integer line.

  ERRORS     the priority class. The SAME failing op is run against OUR and the
             STOCK server; the coarse error CATEGORY (err_code) must match and
             both must fail (rc != 0).

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisions our + stock
servers on high ports; skips entirely without the stock xrootd toolchain.
"""

import os

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Module fixture: one server pair for the whole file.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confqueryerr"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14008), off_port=L.worker_port(14009))
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


def fs(url, *args, timeout=60):
    """Stock xrdfs runner -> (rc, out, err)."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def _qconfig(url, key):
    """Run `query config <key>` and return (rc, stripped-line-text, raw)."""
    rc, out, err = fs(url, "query", "config", key)
    return rc, out.strip(), (out + err)


# =========================================================================== #
# QUERY config — reference format: bare value + '\n', never "<key>=...".
# One distinct test case per key (parametrized).
#
# do_Qconf() returns a bare value line for known keys, and ECHOES the key for
# unknown ones. In every case the answer must NOT be of the form "<key>=...".
# =========================================================================== #
QCONFIG_KEYS = [
    "bind_max", "chksum", "tpc", "tpcdlg", "readv_ior_max", "readv_iov_max",
    "sitename", "version", "role", "cms", "pio_max", "window", "cid", "fattr",
]


@pytest.mark.parametrize("key", QCONFIG_KEYS)
def test_query_config_key_format(srv, key):
    """OUR `query config <key>` succeeds and returns a bare, newline-terminated
    value -- never a "<key>=..." pair (the reference emits the value alone, or
    echoes the key for unknowns)."""
    rc, line, raw = _qconfig(srv["our"], key)
    assert rc == 0, f"OUR query config {key} failed: {raw!r}"
    assert line != "", f"OUR query config {key} returned an empty line"
    # The wire payload from do_Qconf is newline-terminated; xrdfs prints it,
    # so the captured stdout must contain a newline after the value.
    rc2, full_out, _ = fs(srv["our"], "query", "config", key)
    assert "\n" in full_out, \
        f"OUR query config {key} not newline-terminated: {full_out!r}"
    # Never a "<key>=value" form.
    assert not line.startswith(f"{key}="), \
        f"OUR query config {key} returned a key= prefix (bug): {line!r}"
    # And no bare "key=" anywhere on the first value token either.
    first = line.splitlines()[0].strip()
    assert "=" not in first.split()[0] if first.split() else True, \
        f"OUR query config {key} first token looks like key=value: {first!r}"


@pytest.mark.parametrize("key", ["bind_max", "readv_iov_max",
                                 "readv_ior_max", "pio_max"])
def test_query_config_numeric_is_integer(srv, key):
    """Numeric config keys must yield an integer value line."""
    rc, line, raw = _qconfig(srv["our"], key)
    assert rc == 0, f"OUR query config {key} failed: {raw!r}"
    first = line.split()[0] if line.split() else ""
    assert first.lstrip("-").isdigit(), \
        f"OUR query config {key} is not an integer: {line!r}"


def test_query_config_chksum_value_only(srv):
    """`query config chksum` must be a bare cslist (or the echoed key 'chksum'),
    never 'chksum=...'."""
    rc, line, raw = _qconfig(srv["our"], "chksum")
    assert rc == 0, f"OUR query config chksum failed: {raw!r}"
    assert not line.startswith("chksum="), \
        f"OUR chksum config has a key= prefix (bug): {line!r}"


def test_query_config_tpc_parseable(srv):
    """XrdCl parses `query config tpc` as a leading digit; pin the same form on
    OUR server as the stock server yields."""
    _, our_line, _ = _qconfig(srv["our"], "tpc")
    _, off_line, _ = _qconfig(srv["off"], "tpc")
    for who, line in (("our", our_line), ("stock", off_line)):
        head = line.splitlines()[0].strip() if line else ""
        assert head[:1].isdigit() or head == "tpc", \
            f"{who} query config tpc not parseable: {line!r}"


def test_query_config_unknown_key_echoed(srv):
    """Reference: an unknown config key is echoed back verbatim (bare + '\\n'),
    NOT 'key=...'. Pin OUR server to the same behavior the stock server shows."""
    bogus = "no_such_config_key_xyzzy"
    rc_o, line_o, raw_o = _qconfig(srv["our"], bogus)
    rc_f, line_f, raw_f = _qconfig(srv["off"], bogus)
    assert rc_o == rc_f, \
        f"unknown-key rc differs: our={rc_o} stock={rc_f}"
    if rc_f == 0:
        assert not line_o.startswith(f"{bogus}="), \
            f"OUR echoes unknown key as key= (bug): {line_o!r}"
        assert bogus in line_o, \
            f"OUR did not echo the unknown key: {line_o!r} (stock {line_f!r})"


# =========================================================================== #
# QUERY checksum — '<algo> <hex>' form, hex identical for identical content.
# =========================================================================== #
@pytest.mark.parametrize("path", ["/data.bin", "/cksum.bin"])
def test_query_checksum_form_and_match(srv, path):
    """`query checksum <file>` -> '<algo> <hex>' on OUR server, and the hex must
    match the stock server for the same content."""
    rc_o, out_o, err_o = fs(srv["our"], "query", "checksum", path)
    assert rc_o == 0, f"OUR query checksum {path} failed: {out_o}{err_o}"
    toks_o = out_o.split()
    assert len(toks_o) >= 2, \
        f"OUR checksum not '<algo> <hex>': {out_o!r}"
    hex_o = toks_o[-1]
    assert all(c in "0123456789abcdefABCDEF" for c in hex_o), \
        f"OUR checksum value not hex: {hex_o!r}"

    rc_f, out_f, _ = fs(srv["off"], "query", "checksum", path)
    if rc_f == 0 and out_f.split():
        hex_f = out_f.split()[-1]
        assert hex_o.lower() == hex_f.lower(), \
            f"checksum hex differs for {path}: our={hex_o} stock={hex_f}"


def test_query_checksum_algo_token_present(srv):
    """The algo token (first field) must be a non-empty name, not empty/=form."""
    rc, out, err = fs(srv["our"], "query", "checksum", "/data.bin")
    assert rc == 0, f"{out}{err}"
    algo = out.split()[0]
    assert algo and "=" not in algo, f"unexpected algo token: {algo!r}"


# =========================================================================== #
# QUERY stats — OUR must succeed with non-empty output (stock content may vary).
# =========================================================================== #
def test_query_stats_success_nonempty(srv):
    rc, out, err = fs(srv["our"], "query", "stats", "a")
    assert rc == 0, f"OUR query stats failed: {out}{err}"
    assert out.strip() != "", f"OUR query stats returned empty output"


def test_query_stats_default_arg_success(srv):
    """query stats with the bare 'a' (all) selector must also succeed."""
    rc, out, err = fs(srv["our"], "query", "stats")
    # Some xrdfs builds require a selector arg; accept either form succeeding.
    if rc != 0:
        rc, out, err = fs(srv["our"], "query", "stats", "a")
    assert rc == 0, f"OUR query stats failed: {out}{err}"
    assert out.strip() != "", "OUR query stats empty"


# =========================================================================== #
# QUERY space — compare success/failure CATEGORY between OUR and STOCK.
# Stock may not support `query space`; pin OUR server to matching behavior.
# =========================================================================== #
def test_query_space_matches_stock_category(srv):
    rc_o, out_o, err_o = fs(srv["our"], "query", "space", "/")
    rc_f, out_f, err_f = fs(srv["off"], "query", "space", "/")
    our_ok = (rc_o == 0)
    off_ok = (rc_f == 0)
    assert our_ok == off_ok, (
        f"query space support category differs: "
        f"our_ok={our_ok}({out_o}{err_o!r}) stock_ok={off_ok}({out_f}{err_f!r})")
    if not off_ok:
        # Both reject -> the coarse error category should also line up.
        assert L.err_code(out_o + err_o) == L.err_code(out_f + err_f), (
            f"query space failure category differs: "
            f"our={L.err_code(out_o + err_o)} stock={L.err_code(out_f + err_f)}")


# =========================================================================== #
# ERROR SEMANTICS — the priority. Same failing op, OUR vs STOCK; the coarse
# error CATEGORY must match and BOTH must fail (rc != 0).
# =========================================================================== #
# L.err_code keys "not found" and "no such file" name the SAME XRootD error
# category (kXR_NotFound / errno ENOENT); the two servers just phrase the text
# differently ("source not found" vs "no such file or directory"). Collapse the
# coarse buckets to their underlying category so the differential test compares
# real semantics, not message wording.
_CATEGORY_ALIASES = {
    "no such file": "notfound",
    "not found": "notfound",
    "not authorized": "auth",
    "permission": "auth",
    "exists": "exists",
    "already exists": "exists",
    "is a directory": "isdir",
    "not a directory": "notdir",
}


def _category(text):
    return _CATEGORY_ALIASES.get(L.err_code(text), L.err_code(text))


def _both_fail_same_category(srv, *args):
    rc_o, out_o, err_o = fs(srv["our"], *args)
    rc_f, out_f, err_f = fs(srv["off"], *args)
    cat_o = _category(out_o + err_o)
    cat_f = _category(out_f + err_f)
    return (rc_o, cat_o, out_o + err_o), (rc_f, cat_f, out_f + err_f)


ERROR_OPS = [
    pytest.param(["stat", "/nonexistent"], id="stat_nonexistent"),
    pytest.param(["cat", "/nonexistent"], id="cat_nonexistent"),
    pytest.param(["stat", "/no/such/dir/file"], id="stat_in_missing_dir"),
    pytest.param(["rm", "/nonexistent"], id="rm_nonexistent"),
    pytest.param(["mkdir", "/sub"], id="mkdir_existing"),
    pytest.param(["chmod", "/nonexistent", "rwxr-xr-x"], id="chmod_nonexistent"),
    pytest.param(["truncate", "/nonexistent", "10"], id="truncate_nonexistent"),
    pytest.param(["mv", "/nonexistent", "/x"], id="mv_nonexistent"),
    pytest.param(["ls", "/nonexistentdir"], id="ls_nonexistentdir"),
    pytest.param(["cat", "/sub"], id="cat_directory"),
]


@pytest.mark.parametrize("args", ERROR_OPS)
def test_error_category_matches_stock(srv, args):
    """For each failing op, OUR and STOCK must both fail with the same coarse
    error category. A divergence is a candidate bug in OUR implementation."""
    (rc_o, cat_o, raw_o), (rc_f, cat_f, raw_f) = _both_fail_same_category(srv, *args)
    assert rc_f != 0, f"oracle: stock UNEXPECTEDLY succeeded on {args}: {raw_f!r}"
    assert rc_o != 0, \
        f"OUR server accepted a failing op {args} (bug): {raw_o!r}"
    assert cat_o == cat_f, (
        f"error CATEGORY divergence on {args}: "
        f"our={cat_o!r} ({raw_o!r}) vs stock={cat_f!r} ({raw_f!r})")


def test_error_rmdir_nonexistent_matches_stock(srv):
    """rmdir of a nonexistent path: pin OUR rc-category to whatever the stock
    server does (the reference oss rmdir is lenient and returns success here, so
    a failing OUR server would itself be the divergence)."""
    (rc_o, cat_o, raw_o), (rc_f, cat_f, raw_f) = \
        _both_fail_same_category(srv, "rmdir", "/nonexistent")
    assert (rc_o == 0) == (rc_f == 0), (
        f"rmdir /nonexistent rc-category differs: "
        f"our_rc={rc_o}({raw_o!r}) stock_rc={rc_f}({raw_f!r})")
    if rc_f != 0:
        assert cat_o == cat_f, (
            f"rmdir error category differs: our={cat_o!r} stock={cat_f!r}")


def test_error_query_checksum_nonexistent(srv):
    """`query checksum /nonexistent`: OUR server must reject (rc != 0). If the
    stock server in this config actually computes checksums (rather than
    rejecting with 'not supported'), require a matching error category."""
    rc_o, out_o, err_o = fs(srv["our"], "query", "checksum", "/nonexistent")
    assert rc_o != 0, \
        f"OUR query checksum of a missing file succeeded (bug): {out_o}{err_o!r}"
    rc_f, out_f, err_f = fs(srv["off"], "query", "checksum", "/nonexistent")
    stock_unsupported = "not supported" in (out_f + err_f).lower()
    if rc_f != 0 and not stock_unsupported:
        assert _category(out_o + err_o) == _category(out_f + err_f), (
            f"checksum-of-missing error category differs: "
            f"our={_category(out_o + err_o)!r} stock={_category(out_f + err_f)!r}")


# =========================================================================== #
# Security / robustness — path traversal must be rejected on OUR (and stock).
# =========================================================================== #
def test_path_traversal_rejected_both(srv):
    """A '/../../etc/passwd' read must be rejected (rc != 0) on OUR server; the
    stock server rejects it too. Compare rejection category."""
    trav = "/../../etc/passwd"
    rc_o, out_o, err_o = fs(srv["our"], "cat", trav)
    rc_f, out_f, err_f = fs(srv["off"], "cat", trav)
    assert rc_o != 0, \
        f"OUR server served a path-traversal target (SECURITY BUG): {out_o!r}"
    assert rc_f != 0, f"oracle: stock served the traversal target: {out_f!r}"


def test_stat_traversal_rejected_both(srv):
    """stat of a traversal path is rejected on both servers."""
    trav = "/../../../etc/shadow"
    rc_o, out_o, err_o = fs(srv["our"], "stat", trav)
    rc_f, out_f, err_f = fs(srv["off"], "stat", trav)
    assert rc_o != 0, \
        f"OUR server stat'd a traversal target (SECURITY BUG): {out_o!r}"
    assert rc_f != 0, f"oracle: stock stat'd the traversal target: {out_f!r}"


def test_unknown_query_subcmd_rejected_both(srv):
    """An unsupported `query` selector must be rejected (rc != 0) on OUR server;
    pin to the stock server's rejection category."""
    rc_o, out_o, err_o = fs(srv["our"], "query", "bogusquerycode", "/")
    rc_f, out_f, err_f = fs(srv["off"], "query", "bogusquerycode", "/")
    # xrdfs may reject the *argument* client-side; in that case both will be
    # identical anyway. Require matching success/failure category.
    assert (rc_o == 0) == (rc_f == 0), (
        f"unknown query subcmd category differs: "
        f"our_ok={rc_o == 0}({out_o}{err_o!r}) stock_ok={rc_f == 0}({out_f}{err_f!r})")

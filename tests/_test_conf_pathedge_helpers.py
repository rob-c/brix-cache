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

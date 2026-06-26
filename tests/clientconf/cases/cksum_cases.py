"""
cksum_cases — differential conformance for ``xrdadler32`` and ``xrdcrc32c``.

Both tools print ``<checksum> <path>``.  Two wrinkles drive the design:

  * stock echoes the full URL while ours echoes the resolved path — so parity is
    on the checksum VALUE (leading hex token), not the whole line; and
  * the cksum tools exit 0 even on "unable to open", and stock ``xrdcrc32c`` in
    particular cannot operate against this server at all — so rc parity is
    useless and stock is only a *bonus* oracle.

Therefore the post validates OUR client first (it must produce a checksum for a
real file, and none for a missing one); stock is compared only when it actually
produced a value.  This keeps the suite honest — our client's correctness is
always asserted — without going red when stock can't serve as the oracle.
"""

import pytest

from .. import corpus
from ..diffcore import OURS, STOCK
from ..model import Case

# The reference xrootd here is NOT configured to compute checksums (it answers
# "query chksum is not supported"), so a checksum differential is impossible
# against it for EITHER client.  cksum conformance therefore targets the nginx
# tiers, whose checksum support is the feature under test.
CKS_EPS = frozenset({"anon", "gsi", "tls", "token"})


def _unreachable(result):
    """True when a run failed because the server was not reachable (infra)."""
    blob = (result.stdout + result.stderr).lower()
    return "connect" in blob and "fail" in blob


def _server_declined_cksum(result):
    """True when the SERVER refused to produce a checksum (capability/edge),
    e.g. checksums unconfigured, or a path the server won't checksum.  Not a
    client divergence — both clients see the same server answer."""
    blob = (result.stdout + result.stderr).lower()
    return any(s in blob for s in (
        "not supported", "unsupported", "unknown checksum algorithm",
        "arginvalid", "no checksum"))


def _hex_token(text):
    for line in text.splitlines():
        for w in line.split():
            if len(w) >= 8 and all(c in "0123456789abcdefABCDEF" for c in w):
                return w.lower()
    return None


def _post_cksum_value(ep, ctx, results):
    if _unreachable(results[OURS]) or _unreachable(results[STOCK]):
        pytest.skip("server unreachable during checksum (infra)")
    if _server_declined_cksum(results[OURS]) or \
            _server_declined_cksum(results[STOCK]):
        pytest.skip("server did not compute a checksum for this path (capability)")
    o = _hex_token(results[OURS].stdout)
    assert o is not None, (
        "our client produced no checksum for a real file (rc=%s): %s"
        % (results[OURS].rc, results[OURS].stderr.strip()))
    s = _hex_token(results[STOCK].stdout)
    if s is None:
        # Stock could not checksum this file against our server (known for
        # xrdcrc32c) — our client's value still stands on its own.
        return
    assert s == o, "checksum value differs: stock=%r ours=%r" % (s, o)


# Per-tool process exit code on a missing file, matching stock byte-for-byte:
#   xrdadler32 → 1  (stock speaks root://; Stat/Open of the missing file fails)
#   xrdcrc32c  → 3  (stock is local-only: a plain open() of the URL fails)
#   xrdcrc64   → 1  (no stock counterpart; remote-capable, follows xrdadler32)
_MISSING_RC = {"xrdadler32": 1, "xrdcrc32c": 3, "xrdcrc64": 1}


def _make_post_no_cksum(tool):
    want = _MISSING_RC[tool]

    def _post(ep, ctx, results):
        # A missing file must yield NO checksum from either tool.
        assert _hex_token(results[OURS].stdout) is None, \
            "our client emitted a checksum for a missing file"
        assert _hex_token(results[STOCK].stdout) is None, \
            "stock emitted a checksum for a missing file"
        # Exit code must match stock's per-tool convention exactly.
        assert results[OURS].rc == want, \
            "%s missing-file rc=%s, want %s (stock parity)" % (
                tool, results[OURS].rc, want)
        # Bonus oracle: when stock produced a code, it must agree.
        assert results[STOCK].rc == want, \
            "%s stock missing-file rc=%s, expected %s" % (
                tool, results[STOCK].rc, want)

    return _post


def cases_for(tool):
    out = []
    for name in corpus.NONEMPTY_NAMES:
        e = corpus.BY_REL[name]
        out.append(Case(
            id="%s-%s" % (tool, e.rel.replace("/", "_").replace(" ", "_")),
            argv=lambda ep, ctx, which, p=e.remote: [ep.url(p)],
            endpoints=CKS_EPS, parity=frozenset(), post=_post_cksum_value,
            timeout=60))
    out.append(Case(
        id="%s-missing" % tool,
        argv=lambda ep, ctx, which:
            [ep.url("/%s/missing.bin" % corpus.PREFIX)],
        endpoints=CKS_EPS, parity=frozenset(), post=_make_post_no_cksum(tool),
        timeout=60))
    return out

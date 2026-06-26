"""
xrdfs_cases — differential conformance for the ``xrdfs`` metadata tool.

Read-only operations fan out over the deterministic corpus (stat/ls/locate/cat/
query) against every healthy endpoint; a small set of write operations (mkdir/
rmdir/touch/rm/mv/truncate) use per-test-unique paths so they never collide
under xdist or perturb the shared corpus.

Parity dimensions are chosen per operation:
  * stat/cat/query    → {rc, stdout}  (server truth, identical across clients)
  * ls/locate         → {rc} + a post that compares the basename SET
                         (listing ORDER and the echoed authority differ
                          cosmetically between clients)
  * errors            → {rc}
  * writes            → {rc} + a read-back post where useful
"""

from .. import corpus
from ..diffcore import OURS, STOCK
from ..endpoints import WRITABLE
from ..model import Case

TOOL = "xrdfs"

# All endpoints can serve read-only metadata.
READ_EPS = frozenset({"anon", "gsi", "tls", "token", "ref"})


def _u(ep, *parts):
    return [ep.url(), *parts]


# --------------------------------------------------------------------------- #
# Post comparators                                                            #
# --------------------------------------------------------------------------- #
def _basename_set(text):
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # plain `ls` prints one path per line; take the trailing component.
        tok = line.split()[-1]
        names.add(tok.rstrip("/").rsplit("/", 1)[-1])
    return names


def _post_same_listing(ep, ctx, results):
    s = _basename_set(results[STOCK].norm_stdout)
    o = _basename_set(results[OURS].norm_stdout)
    assert s == o, "ls listing differs: stock=%r ours=%r" % (
        sorted(s), sorted(o))


def _post_readback_equal(remote_getter, want_bytes):
    """Build a post that downloads the just-written remote file and checks bytes.

    Used by write cases that should leave identical server state regardless of
    client.  We read back with the STOCK client to a scratch file and compare.
    """
    def _post(ep, ctx, results):
        import os
        import subprocess
        from .. import diffcore
        stock = diffcore.binary(STOCK, "xrdfs")
        if stock is None:
            return
        # nothing to verify if both writes failed identically
        if results[STOCK].rc != 0 or results[OURS].rc != 0:
            return
        for which in (STOCK, OURS):
            remote = remote_getter(ctx, which)
            local = ctx.local("readback_%s" % which, "rb")
            r = subprocess.run([stock, ep.url(), "cat", remote],
                               env=ep.auth_env(), capture_output=True,
                               timeout=60)
            if r.returncode == 0:
                with open(local, "wb") as fh:
                    fh.write(r.stdout)
                assert os.path.getsize(local) == len(want_bytes), \
                    "read-back size mismatch for %s via %s" % (remote, which)
    return _post


# --------------------------------------------------------------------------- #
# Case builders                                                               #
# --------------------------------------------------------------------------- #
def _stat_cases():
    out = []
    for e in corpus.FILES:
        out.append(Case(
            id="stat-%s" % e.rel.replace("/", "_").replace(" ", "_"),
            argv=lambda ep, ctx, which, p=e.remote: _u(ep, "stat", p),
            endpoints=READ_EPS, parity={"rc", "stdout"}))
    for d in corpus.DIRS:
        out.append(Case(
            id="stat-dir-%s" % d.replace("/", "_"),
            argv=lambda ep, ctx, which, p="/%s/%s" % (corpus.PREFIX, d):
                _u(ep, "stat", p),
            endpoints=READ_EPS, parity={"rc", "stdout"}))
    return out


def _stat_error_cases():
    return [Case(
        id="stat-missing",
        argv=lambda ep, ctx, which:
            _u(ep, "stat", "/%s/does-not-exist.bin" % corpus.PREFIX),
        endpoints=READ_EPS, parity={"rc"})]


def _ls_cases():
    out = []
    targets = [corpus.ROOT, "%s/d1" % corpus.ROOT, "%s/d1/d2" % corpus.ROOT,
               "%s/emptydir" % corpus.ROOT]
    for t in targets:
        out.append(Case(
            id="ls-%s" % t.strip("/").replace("/", "_"),
            argv=lambda ep, ctx, which, p=t: _u(ep, "ls", p),
            endpoints=READ_EPS, parity={"rc"}, post=_post_same_listing))
        out.append(Case(
            id="ls-l-%s" % t.strip("/").replace("/", "_"),
            argv=lambda ep, ctx, which, p=t: _u(ep, "ls", "-l", p),
            endpoints=READ_EPS, parity={"rc"}))
    out.append(Case(
        id="ls-missing",
        argv=lambda ep, ctx, which:
            _u(ep, "ls", "%s/nope" % corpus.ROOT),
        endpoints=READ_EPS, parity={"rc"}))
    return out


def _locate_cases():
    out = []
    for e in corpus.SMALL_NAMES:
        ent = corpus.BY_REL[e]
        out.append(Case(
            id="locate-%s" % ent.rel.replace("/", "_").replace(" ", "_"),
            argv=lambda ep, ctx, which, p=ent.remote: _u(ep, "locate", p),
            endpoints=READ_EPS, parity={"rc"}))
    return out


def _post_same_stdout_bytes(ep, ctx, results):
    """Exact raw-byte equality of stdout (cat streams binary file content)."""
    a, b = results[STOCK].stdout_bytes, results[OURS].stdout_bytes
    assert a == b, "cat stdout bytes differ (stock=%dB ours=%dB)" % (
        len(a), len(b))


def _cat_cases():
    # cat streams raw file bytes to stdout; compare exact bytes + rc.
    out = []
    for e in corpus.TEXTISH_NAMES:
        ent = corpus.BY_REL[e]
        out.append(Case(
            id="cat-%s" % ent.rel.replace("/", "_"),
            argv=lambda ep, ctx, which, p=ent.remote: _u(ep, "cat", p),
            endpoints=READ_EPS, parity={"rc"}, post=_post_same_stdout_bytes))
    return out


# Stock `xrdfs query config <var>` variables (XrdXrootd qconfig surface).
_CONFIG_VARS = ["bind_max", "chksum", "pio_max", "readv_ior_max",
                "readv_iov_max", "tpc", "version", "wan_port"]


def _query_cases():
    out = []
    # query checksum <file> — server-truth checksum string.
    for e in corpus.NONEMPTY_NAMES[:6]:
        ent = corpus.BY_REL[e]
        out.append(Case(
            id="query-cksum-%s" % ent.rel.replace("/", "_").replace(" ", "_"),
            argv=lambda ep, ctx, which, p=ent.remote:
                _u(ep, "query", "checksum", p),
            endpoints=READ_EPS, parity={"rc"}, post=_post_cksum_token))
    # query config <var> — both clients must agree on acceptance (rc class);
    # the values themselves are server-specific and not byte-compared.
    for var in _CONFIG_VARS:
        out.append(Case(
            id="query-config-%s" % var,
            argv=lambda ep, ctx, which, v=var: _u(ep, "query", "config", v),
            endpoints=READ_EPS, parity={"rc"}))
    return out


def _post_cksum_token(ep, ctx, results):
    """Compare the checksum VALUE (first hex token), ignoring echoed path/URL."""
    def tok(text):
        for line in text.splitlines():
            for w in line.split():
                if all(c in "0123456789abcdefABCDEF" for c in w) and len(w) >= 8:
                    return w.lower()
        return None
    s, o = tok(results[STOCK].stdout), tok(results[OURS].stdout)
    if s is None and o is None:
        return
    assert s == o, "checksum value differs: stock=%r ours=%r" % (s, o)


def _write_cases():
    """Mkdir/touch/rm/mv/truncate on per-test-unique paths (writable tiers)."""
    out = []

    def mkrm(ep, ctx, which):
        d = ctx.remote("md", which)
        return _u(ep, "mkdir", d)

    out.append(Case(
        id="mkdir", argv=mkrm, endpoints=WRITABLE, parity={"rc"},
        needs_write=True))

    out.append(Case(
        id="mkdir-p-nested",
        argv=lambda ep, ctx, which:
            _u(ep, "mkdir", "-p", ctx.remote("a/b/c", which)),
        endpoints=WRITABLE, parity={"rc"}, needs_write=True))

    out.append(Case(
        id="rmdir-missing",
        argv=lambda ep, ctx, which:
            _u(ep, "rmdir", ctx.remote("nodir", which)),
        endpoints=WRITABLE, parity={"rc"}, needs_write=True))

    out.append(Case(
        id="truncate-missing",
        argv=lambda ep, ctx, which:
            _u(ep, "truncate", ctx.remote("notrunc", which), "10"),
        endpoints=WRITABLE, parity={"rc"}, needs_write=True))

    return out


CASES = (
    _stat_cases()
    + _stat_error_cases()
    + _ls_cases()
    + _locate_cases()
    + _cat_cases()
    + _query_cases()
    + _write_cases()
)

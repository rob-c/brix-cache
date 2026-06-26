"""
xrdcp_cases — differential conformance for the ``xrdcp`` transfer tool.

The heaviest table.  Downloads fan out over the corpus with byte-exact parity;
uploads round-trip through a per-binary-unique remote path and read back; a set
of project-only knobs ride on representative downloads with the
*knob-off ⇒ parity, knob-on ⇒ behavioural + bytes-invariant* contract.

Parity dimensions:
  * download        → {rc, bytes}
  * download error  → {rc}
  * upload          → {rc} + read-back-size post
"""

import os
import subprocess

from .. import corpus, diffcore
from ..diffcore import OURS, STOCK
from ..model import Case, KnobSpec

TOOL = "xrdcp"

DL_EPS = frozenset({"anon", "gsi", "tls", "token", "ref"})
UP_EPS = frozenset({"anon", "gsi", "tls", "token", "ref"})
KNOB_EPS = frozenset({"anon", "gsi", "tls", "token", "ref"})   # knobs across all tiers


# --------------------------------------------------------------------------- #
# argv / produces helpers                                                     #
# --------------------------------------------------------------------------- #
def _dl_argv(entry, *opts):
    def build(ep, ctx, which):
        dst = ctx.local("dl_%s" % entry.rel, which)
        return [*opts, ep.url(entry.remote), dst]
    return build


def _dl_produces(entry):
    return lambda ctx, which: ctx.local("dl_%s" % entry.rel, which)


def _local_source(ctx, which, entry):
    """Materialize the corpus entry as a local upload source (idempotent)."""
    path = ctx.local("src_%s" % entry.rel, which)
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(corpus.local_bytes(entry))
    return path


def _up_argv(entry, *opts):
    def build(ep, ctx, which):
        src = _local_source(ctx, which, entry)
        return ["-f", *opts, src, ep.url(ctx.remote(entry.rel, which))]
    return build


def _post_upload_readback(entry):
    """Download each binary's uploaded copy with stock; verify size == source."""
    def _post(ep, ctx, results):
        if results[STOCK].rc != 0 or results[OURS].rc != 0:
            return
        stock = diffcore.binary(STOCK, "xrdcp")
        if stock is None:
            return
        for which in (STOCK, OURS):
            remote = ctx.remote(entry.rel, which)
            back = ctx.local("upback_%s" % entry.rel, which)
            r = subprocess.run([stock, "-f", ep.url(remote), back],
                               env=ep.auth_env(), capture_output=True,
                               text=True, timeout=120)
            assert r.returncode == 0, \
                "read-back of %s (%s) failed: %s" % (remote, which, r.stderr)
            assert os.path.getsize(back) == entry.size, \
                "uploaded size mismatch %s via %s" % (entry.rel, which)
    return _post


# --------------------------------------------------------------------------- #
# Knob behavioural assertions                                                 #
# --------------------------------------------------------------------------- #
def _b_rc0(on, base, ctx):
    assert on.rc == 0, "knob run failed rc=%s: %s" % (on.rc, on.stderr)


def _b_more_output(on, base, ctx):
    """The knob must EMIT additional diagnostics (timing/wire-trace)."""
    assert on.rc == 0, "knob run failed rc=%s: %s" % (on.rc, on.stderr)
    extra = len(on.stdout) + len(on.stderr)
    basel = len(base.stdout) + len(base.stderr)
    assert extra > basel, \
        "knob produced no extra output (on=%d base=%d)" % (extra, basel)


# --------------------------------------------------------------------------- #
# Case builders                                                               #
# --------------------------------------------------------------------------- #
def _download_cases():
    out = []
    for e in corpus.FILES:
        out.append(Case(
            id="dl-%s" % e.rel.replace("/", "_").replace(" ", "_"),
            argv=_dl_argv(e), produces=_dl_produces(e),
            endpoints=DL_EPS, parity={"rc", "bytes"},
            timeout=120 if e.size >= (1 << 20) else 90))
    return out


def _download_force_cases():
    out = []
    for name in corpus.SMALL_NAMES[:4]:
        e = corpus.BY_REL[name]

        def build(ep, ctx, which, e=e):
            dst = ctx.local("dlf_%s" % e.rel, which)
            with open(dst, "wb") as fh:        # pre-existing stale content
                fh.write(b"STALE-MUST-BE-REPLACED")
            return ["-f", ep.url(e.remote), dst]

        out.append(Case(
            id="dl-force-%s" % e.rel.replace("/", "_"),
            argv=build,
            produces=lambda ctx, which, e=e: ctx.local("dlf_%s" % e.rel, which),
            endpoints=DL_EPS, parity={"rc", "bytes"}))
    return out


def _download_error_cases():
    return [Case(
        id="dl-missing",
        argv=lambda ep, ctx, which:
            [ep.url("/%s/missing.bin" % corpus.PREFIX),
             ctx.local("dl_missing", which)],
        endpoints=DL_EPS, parity={"rc"})]


def _streams_cases():
    out = []
    for name in ["k64.bin", "mib1.bin", "odd_99991.bin"]:
        e = corpus.BY_REL[name]
        out.append(Case(
            id="dl-S2-%s" % e.rel,
            argv=_dl_argv(e, "-S", "2"), produces=_dl_produces(e),
            endpoints=DL_EPS, parity={"rc", "bytes"}, timeout=120))
    return out


def _upload_cases():
    out = []
    for name in (corpus.SMALL_NAMES + ["mib1.bin"]):
        e = corpus.BY_REL[name]
        out.append(Case(
            id="up-%s" % e.rel.replace("/", "_").replace(" ", "_"),
            argv=_up_argv(e), endpoints=UP_EPS, parity={"rc"},
            post=_post_upload_readback(e), needs_write=True,
            timeout=120 if e.size >= (1 << 20) else 90))
    return out


def _knobs():
    return [
        KnobSpec("--verify", _b_rc0, endpoints=KNOB_EPS),
        KnobSpec("--pgrw", _b_rc0, endpoints=KNOB_EPS),
        KnobSpec("--compress", _b_rc0, extra_args=["gzip"], endpoints=KNOB_EPS),
        KnobSpec("--no-retry", _b_rc0, endpoints=KNOB_EPS),
        KnobSpec("--timing", _b_more_output, endpoints=KNOB_EPS),
        KnobSpec("--wire-trace", _b_more_output, endpoints=KNOB_EPS),
    ]


def _knob_cases():
    """Knobs ride on two representative downloads (a mid-size and a 1 MiB),
    each across all auth tiers, so every knob is exercised over GSI/TLS/token
    as well as anon/ref."""
    out = []
    for base_name in ("k64.bin", "mib1.bin"):
        base = corpus.BY_REL[base_name]
        for k in _knobs():
            out.append(Case(
                id="dl-%s-knob%s" % (base_name.split(".")[0],
                                     k.flag.replace("-", "")),
                argv=_dl_argv(base), produces=_dl_produces(base),
                endpoints=KNOB_EPS, parity={"rc", "bytes"}, knob=k,
                timeout=120))
    return out


CASES = (
    _download_cases()
    + _download_force_cases()
    + _download_error_cases()
    + _streams_cases()
    + _upload_cases()
    + _knob_cases()
)

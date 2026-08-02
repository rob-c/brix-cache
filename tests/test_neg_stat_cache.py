"""
test_neg_stat_cache.py — phase-56 C-2: per-worker negative-stat cache, live.

(The phase-56 doc sketch named this suite ``test_metadata_stress.py``; that
filename was already taken by the rate-limiter metadata storm suite, so the
C-2 coverage lives here instead.)

The cache (src/fs/vfs/vfs_stat.c) is a per-worker 256-slot table of
recently-observed ENOENT results, keyed separately for the follow and
nofollow stat arms, TTL 1s, enabled ONLY by ``BRIX_NEG_STAT_CACHE=1`` in the
worker environment and disabled outright under impersonation.  Every
same-worker namespace mutator (open-create, mkdir, rename, staged commit)
calls ``brix_vfs_neg_stat_forget()`` so a create issued after a cached
negative is visible immediately — the doc's mandatory
create-after-negative-probe race.

Observability note that shapes this suite: on the root wire the DEFAULT
kXR_stat is the FOLLOW arm, and every follow-arm ENOENT runs
``stat_symlink_follow_fallback`` (an uncached realpath + probe that rescues
host-absolute in-root symlinks — and, incidentally, any file that appeared
since the negative was cached).  A cached follow negative is therefore never
externally visible through plain ``xrdfs stat``.  The NOFOLLOW arm
(kXR_statNoFollow, raw wire — the stock client cannot send it) has no such
fallback, so it is the arm where a cache hit, the TTL, and the forget hooks
are all genuinely observable; the raw-wire legs below use it.

Live coverage against a dedicated single-worker anon export with the knob ON
(lifecycle instance ``lc-negstat``, tests/configs/nginx_lc_negstat.conf):

  * success — repeated stats of a missing path stay ENOENT and never leak
    onto other paths;
  * race (mandatory, doc §13) — prime a cached nofollow negative, upload the
    same path with xrdcp, and the very next nofollow stat MUST succeed: only
    the create-side forget can make that true (no fallback on this arm);
  * race — same for mkdir (mkdir-side forget);
  * cache-hit + TTL — an EXTERNAL on-disk create (no wire mutator, so no
    forget hook) stays masked by the cached nofollow negative immediately
    after (the proof the cache is actually operating), then becomes visible
    within the 1s TTL horizon;
  * security-negative — on the main fleet (knob absent → default OFF) an
    external create is visible on the FIRST nofollow stat after negative
    probes, with no TTL window.
"""

import os
import socket
import struct
import time

import pytest

from metrics_helpers import xrdcp, xrdfs
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, DATA_ROOT, HOST, NGINX_ANON_PORT

# Serialised onto one worker: the knob-on tests share the single fixed ledger
# port (lc-negstat); each test closes its harness at teardown so the port is
# free for the next.
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-negstat")]

# ---- minimal raw kXR client (mirrors _test_conf_stattypes_helpers framing) --
kXR_login, kXR_stat = 3007, 3017
kXR_ok = 0
kXR_statNoFollow = 0x40   # vendor stat option (src/protocols/root/protocol/flags.h)


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed mid-frame")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    return status, (_recv_exact(s, dlen) if dlen else b"")


def _session(port):
    s = socket.create_connection((HOST, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))  # handshake
    st, _ = _resp(s)
    assert st == kXR_ok, "handshake reply not kXR_ok"
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0x7fffffff, b"ctyp\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"
    return s


def _stat_nofollow(port, path):
    """One kXR_stat with kXR_statNoFollow on a fresh session -> wire status.

    The nofollow arm has no symlink-follow fallback, so this is the probe that
    actually observes the cache (hit, TTL expiry, forget)."""
    s = _session(port)
    try:
        p = path.encode()
        s.sendall(struct.pack("!2sHB7sI4sI", b"\x00\x02", kXR_stat,
                              kXR_statNoFollow, b"\x00" * 7, 0, b"\x00" * 4,
                              len(p)) + p)
        return _resp(s)[0]
    finally:
        s.close()


def _start(lifecycle, tmp_path):
    """Start the knob-ON single-worker anon export; returns (endpoint, data dir)."""
    data = tmp_path / "export"
    data.mkdir()
    if os.geteuid() == 0:
        from cmdscripts import open_tree_for_worker
        open_tree_for_worker(tmp_path)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-negstat",
        template="nginx_lc_negstat.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        env={"BRIX_NEG_STAT_CACHE": "1"},
        reason="phase-56 C-2 negative-stat cache subject"))
    return ep, data


def _prime_negative(port, path, n=3):
    """Probe a missing path repeatedly (nofollow) so the worker caches the
    negative on the arm the assertions observe."""
    for _ in range(n):
        assert _stat_nofollow(port, path) != kXR_ok, \
            f"expected ENOENT priming {path}"


def test_repeat_negative_probes_stay_enoent(lifecycle, tmp_path):
    """Success: a missing path keeps reporting ENOENT across repeated probes
    (cache hit after the first miss) and the cached negative never bleeds onto
    a different, genuinely-present path."""
    ep, data = _start(lifecycle, tmp_path)
    _prime_negative(ep.port, "/absent.dat", n=5)
    # A path never probed negative is statable on the first try: the cache
    # captures only observed ENOENTs, never whole-namespace state.
    (data / "present.dat").write_bytes(b"p" * 64)
    assert _stat_nofollow(ep.port, "/present.dat") == kXR_ok
    # ...and the primed path is still (correctly) absent, on both stat arms.
    assert _stat_nofollow(ep.port, "/absent.dat") != kXR_ok
    r = xrdfs(f"root://{HOST}:{ep.port}", "stat", "/absent.dat")
    assert r.returncode != 0, r.stdout


def test_create_after_negative_probe_race(lifecycle, tmp_path):
    """MANDATORY race (doc §13): prime a cached negative, create the same path
    through the wire, and the immediately-following stat MUST succeed.  On the
    fallback-less nofollow arm only the create-side forget hook can make this
    pass — riding out the 1s TTL would fail the assertion."""
    ep, data = _start(lifecycle, tmp_path)
    src = tmp_path / "payload.bin"
    src.write_bytes(os.urandom(8192))
    _prime_negative(ep.port, "/race.dat")
    r = xrdcp("-f", str(src), f"root://{HOST}:{ep.port}//race.dat")
    assert r.returncode == 0, r.stderr
    assert _stat_nofollow(ep.port, "/race.dat") == kXR_ok, (
        "false ENOENT immediately after a same-worker create — the "
        "upload-path neg-stat forget hook failed")


def test_mkdir_after_negative_probe(lifecycle, tmp_path):
    """Race, mkdir flavour: a cached negative on a directory path is cleared by
    the mkdir-side forget hook, so the next nofollow stat sees the new
    directory instead of the stale negative."""
    ep, _data = _start(lifecycle, tmp_path)
    _prime_negative(ep.port, "/newdir")
    r = xrdfs(f"root://{HOST}:{ep.port}", "mkdir", "/newdir")
    assert r.returncode == 0, r.stderr
    assert _stat_nofollow(ep.port, "/newdir") == kXR_ok, (
        "false ENOENT immediately after mkdir — forget hook failed")


def test_external_create_masked_then_visible_within_ttl(lifecycle, tmp_path):
    """Cache-hit + TTL bound: a create that bypasses the wire (direct on-disk
    write — no mutator, no forget hook) stays masked by the cached nofollow
    negative immediately after (the positive proof the cache is operating; the
    suite would otherwise pass vacuously with the knob dead), and becomes
    visible once the 1s TTL lapses (5s polling deadline)."""
    ep, data = _start(lifecycle, tmp_path)
    _prime_negative(ep.port, "/ext.dat")
    (data / "ext.dat").write_bytes(b"e" * 32)
    assert _stat_nofollow(ep.port, "/ext.dat") != kXR_ok, (
        "external create visible instantly after negative priming — the "
        "cache is not operating (knob not reaching the worker?)")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if _stat_nofollow(ep.port, "/ext.dat") == kXR_ok:
            return
        time.sleep(0.25)
    pytest.fail("external create still invisible after 5s — cached negative "
                "outlived the 1s TTL")


@pytest.mark.registry_server("main")
def test_default_off_no_stale_negative_on_main_fleet(tmp_path):
    """Security-negative: the main fleet does not set BRIX_NEG_STAT_CACHE, so
    the cache must be OFF by default — an external create is visible on the
    very FIRST nofollow stat after repeated negative probes, with no TTL
    window."""
    name = f"negstat_off_{os.getpid()}.dat"
    target = os.path.join(DATA_ROOT, name)
    try:
        for _ in range(3):
            assert _stat_nofollow(NGINX_ANON_PORT, "/" + name) != kXR_ok
        with open(target, "wb") as fh:
            fh.write(b"off" * 16)
        assert _stat_nofollow(NGINX_ANON_PORT, "/" + name) == kXR_ok, (
            "default-off violated: a stale cached negative was served on the "
            "main fleet")
    finally:
        if os.path.exists(target):
            os.unlink(target)

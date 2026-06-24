"""GSI interoperability guards — keep nginx-xrootd talking GSI to real XRootD.

These tests defend the GSI handshake fixes that make the native client and the
nginx server interoperate with stock XRootD, EOS, and dCache, so a refactor
cannot silently drop back to a GSI dialect those servers reject. See
docs/10-reference/comparison/xrootd-implementations.md (§5) for the full rationale.

Four tiers, from always-on to opt-in:

  1. test_gsi_core_invariants_unit   — CI-safe C unit test of the shared gsi_core
       wire invariants (IV is load-bearing, cipher allowlist, kXRS_none terminator).
  2. test_gsi_loopback_authenticates — client <-> our own nginx GSI server end to
       end (our server is suffix-driven on the IV, so this catches IV / dh_pad /
       cipher-negotiation regressions behaviorally). Skips if the fleet isn't up.
  3. test_gsi_live_interop           — OPT-IN: forces GSI against real endpoints
       named in TEST_GSI_ENDPOINTS / TEST_EOS_ENDPOINT (e.g. EOS, dCache) with the
       caller's proxy. Adding a server is one env entry. Skips otherwise.
  4. test_wire_contract_tripwires    — source-level tripwires for the wire facts
       that ONLY a strict peer (dCache) would reject and that have no other CI
       signal: the kXRS_md_alg bucket, the "#ivlen" suffix, the inner terminator,
       the CA-dir grid fallback, and the server's suffix-driven use_iv.
  5. xcache + TPC origin guards      — this module fronting EOS/dCache: source
       tripwires that the xcache origin fill execs the native client and the
       in-process TPC outbound GSI reuses the shared gsi_core, plus a live xcache
       origin-fetch (with integrity) and a (dest-gated) live TPC pull, both
       parameterized over the same endpoints.

Run:
    PYTHONPATH=tests pytest tests/test_gsi_interop_guards.py -v
    TEST_GSI_ENDPOINTS="root://eoslhcb.cern.ch=/eos/lhcb/,root://lhcbdcache-kit.gridka.de:1094=/pnfs/gridka.de/lhcb/LHCb-Disk/" \\
        X509_USER_PROXY=/tmp/x509up_u$(id -u) \\
        PYTHONPATH=tests pytest tests/test_gsi_interop_guards.py -k live -v
"""

import os
import re
import shutil
import socket
import subprocess

import pytest

from settings import CA_DIR, NGINX_GSI_PORT, PROXY_STD, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC = os.environ.get("CC", "cc")
XRDGSITEST = os.path.join(REPO, "client", "bin", "xrdgsitest")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")

pytestmark = pytest.mark.timeout(120)


# --------------------------------------------------------------------------- #
# Tier 1 — shared gsi_core wire invariants (no server, always runs in CI)
# --------------------------------------------------------------------------- #
def test_gsi_core_invariants_unit():
    """Compile + run tests/c/gsi_interop_test.c against the shared gsi_core."""
    if not shutil.which(CC):
        pytest.skip("no C compiler")

    out_bin = os.path.join(os.environ.get("TMPDIR", "/tmp"), "gsi_interop_unit.bin")
    cmd = [
        CC, "-O2", "-D_GNU_SOURCE", f"-I{os.path.join(REPO, 'src')}",
        "-o", out_bin,
        os.path.join(REPO, "tests/c/gsi_interop_test.c"),
        os.path.join(REPO, "src/gsi/gsi_core.c"),
        os.path.join(REPO, "src/compat/crypto.c"),
        "-lcrypto",
    ]
    build = subprocess.run(cmd, capture_output=True, text=True)
    if build.returncode != 0 and "lcrypto" in build.stderr:
        pytest.skip("libcrypto/dev headers unavailable")
    assert build.returncode == 0, f"compile failed:\n{build.stderr}"

    run = subprocess.run([out_bin], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, f"gsi_core invariants failed:\n{run.stdout}\n{run.stderr}"
    assert "ALL PASSED" in run.stdout, run.stdout


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _reachable(host, port, timeout=5.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _split_endpoint(ep):
    """root://host[:port] -> (host, port)."""
    rest = ep.split("://", 1)[1].split("/", 1)[0]
    if rest.startswith("["):                       # IPv6 literal
        host, _, tail = rest[1:].partition("]")
        port = int(tail.lstrip(":")) if tail.lstrip(":") else 1094
        return host, port
    if ":" in rest:
        host, port = rest.rsplit(":", 1)
        return host, int(port)
    return rest, 1094


def _gsi_env(proxy, ca_dir):
    env = dict(os.environ)
    env["X509_USER_PROXY"] = proxy
    # Intentionally set X509_CERT_DIR for the harness CA; the live tier leaves it
    # unset to also exercise the /etc/grid-security/certificates fallback.
    if ca_dir is not None:
        env["X509_CERT_DIR"] = ca_dir
    return env


# --------------------------------------------------------------------------- #
# Tier 2 — client <-> our own nginx GSI server (behavioral, CI-safe)
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not os.path.exists(XRDGSITEST), reason="xrdgsitest not built")
def test_gsi_loopback_authenticates():
    """Force GSI against our own server; exit 0 only if GSI authenticated.

    Our server now derives use_iv from the client's kXRS_cipher_alg '#ivlen'
    suffix, so a client that reverts to bare-name-with-IV (or wrong dh_pad, or an
    unsupported cipher) fails this test rather than silently downgrading.
    """
    if not os.path.exists(PROXY_STD):
        pytest.skip("test proxy not provisioned (run the GSI fixture)")
    if not _reachable(SERVER_HOST, NGINX_GSI_PORT):
        pytest.skip(f"nginx GSI server {SERVER_HOST}:{NGINX_GSI_PORT} not running")

    endpoint = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
    r = subprocess.run([XRDGSITEST, endpoint],
                       capture_output=True, text=True, timeout=60,
                       env=_gsi_env(PROXY_STD, CA_DIR))
    assert r.returncode == 0, (
        f"GSI handshake against our own server failed (regression in the GSI "
        f"dialect?):\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}")


@pytest.mark.skipif(not os.path.exists(XRDFS), reason="xrdfs not built")
def test_gsi_loopback_read():
    """A read over GSI against our own server (data plane after GSI auth)."""
    if not os.path.exists(PROXY_STD):
        pytest.skip("test proxy not provisioned")
    if not _reachable(SERVER_HOST, NGINX_GSI_PORT):
        pytest.skip("nginx GSI server not running")
    endpoint = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
    r = subprocess.run([XRDFS, endpoint, "ls", "/"],
                       capture_output=True, text=True, timeout=60,
                       env=_gsi_env(PROXY_STD, CA_DIR))
    assert r.returncode == 0, f"GSI ls failed:\n{r.stdout}\n{r.stderr}"


# --------------------------------------------------------------------------- #
# Tier 3 — live external interop (opt-in; the gold-standard guard)
# --------------------------------------------------------------------------- #
def _live_endpoints():
    """Parse TEST_GSI_ENDPOINTS ('ep=dir,ep=dir') + the TEST_EOS_ENDPOINT shim."""
    specs = []
    raw = os.environ.get("TEST_GSI_ENDPOINTS", "").strip()
    if raw:
        for item in raw.split(","):
            ep, _, d = item.partition("=")
            ep = ep.strip()
            if ep:
                specs.append((ep, d.strip() or "/"))
    eos = os.environ.get("TEST_EOS_ENDPOINT", "").strip()
    if eos:
        specs.append((eos, os.environ.get("TEST_EOS_DIR", "/eos/lhcb/")))
    return specs


_LIVE = _live_endpoints()


@pytest.mark.skipif(not _LIVE, reason="no TEST_GSI_ENDPOINTS / TEST_EOS_ENDPOINT")
@pytest.mark.skipif(not os.path.exists(XRDGSITEST), reason="xrdgsitest not built")
@pytest.mark.parametrize("endpoint,listdir", _LIVE,
                         ids=[e[0] for e in _LIVE] or ["none"])
def test_gsi_live_interop(endpoint, listdir):
    """Force GSI against each real endpoint; then list a dir over it.

    Uses the caller's proxy ($X509_USER_PROXY or /tmp/x509up_u<uid>) and leaves
    X509_CERT_DIR unset so the client's CA-dir fallback to
    /etc/grid-security/certificates is exercised too.
    """
    proxy = os.environ.get("X509_USER_PROXY", f"/tmp/x509up_u{os.getuid()}")
    if not os.path.exists(proxy):
        pytest.skip(f"no proxy at {proxy} (voms-proxy-init first)")
    host, port = _split_endpoint(endpoint)
    if not _reachable(host, port):
        pytest.skip(f"{endpoint} ({host}:{port}) not reachable")

    env = _gsi_env(proxy, None)  # ca_dir=None -> exercise grid CA fallback

    # Stage A — GSI handshake must authenticate (exit 0 only on GSI success).
    g = subprocess.run([XRDGSITEST, endpoint],
                       capture_output=True, text=True, timeout=90, env=env)
    assert g.returncode == 0, (
        f"GSI handshake against {endpoint} failed — framework dropped GSI support "
        f"for this server:\nstdout:\n{g.stdout}\nstderr:\n{g.stderr}")

    # Stage B — a metadata op over the authenticated session.
    ls = subprocess.run([XRDFS, endpoint, "ls", listdir],
                        capture_output=True, text=True, timeout=90, env=env)
    assert ls.returncode == 0, (
        f"GSI ls {listdir} on {endpoint} failed:\n{ls.stdout}\n{ls.stderr}")
    assert ls.stdout.strip(), f"empty listing from {endpoint}:{listdir}"


# --------------------------------------------------------------------------- #
# Tier 4 — wire-contract tripwires (CI-safe; no behavioral signal without dCache)
# --------------------------------------------------------------------------- #
def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()


def test_wire_contract_tripwires():
    """Fail loudly if a known interop-critical wire fact is removed from source.

    These guard requirements that ONLY a strict peer (notably dCache) rejects and
    that no CI-reachable server would catch — see the interop landmines in
    docs/10-reference/comparison/xrootd-implementations.md (§5.4).
    """
    client_gsi = _read("client/lib/sec/sec_gsi.c")
    conn = _read("client/lib/conn.c")
    server_parse = _read("src/gsi/parse_x509.c")

    # (a) client must emit the kXRS_md_alg digest bucket (dCache NPEs without it).
    assert "kXRS_md_alg" in client_gsi, (
        "client no longer emits kXRS_md_alg — dCache will NPE (digestBucket null)")

    # (b) when an IV is prepended, the cipher_alg sent to the server MUST carry a
    #     "#ivlen" suffix. dCache reads the suffix to learn the IV is present; a
    #     bare cipher name + prepended IV makes dCache read ivlen=0 and mis-decrypt
    #     ("Could not decrypt encrypted client message") while EOS still passes —
    #     the exact EOS-ok/dCache-broken split. Match any cipher_field format that
    #     embeds '#', tolerant of formatting.
    assert re.search(r"snprintf\(\s*cipher_field[^;]*#", client_gsi), (
        "client builds the kXRS_cipher_alg field WITHOUT a '#ivlen' suffix while "
        "still prepending an IV (use_iv) — dCache/stock XRootD will fail to decrypt "
        "the client message. Restore the '%s#%d' (cipher#ivlen) form when use_iv.")

    # (c) client must terminate the inner encrypted bucket list with kXRS_none.
    assert "xrootd_gbuf_end(&x.inner)" in client_gsi, (
        "client no longer appends the kXRS_none terminator to the inner buffer — "
        "dCache will overrun (readerIndex exceeds writerIndex)")

    # (d) client CA-dir resolution must fall back to the grid trust dir.
    assert "/etc/grid-security/certificates" in conn, (
        "client lost the /etc/grid-security/certificates CA fallback — grid (IGTF) "
        "server certs will fail TLS verification when X509_CERT_DIR is unset")

    # (e) server must keep handling the IV for IV-advertising (stock/EOS) clients.
    #     Two valid implementations: hardcode use_iv=1 in the signed-DH path (sound
    #     because signed-DH ⟹ version≥10400 ⟹ stock useIV=true), or derive it from
    #     the client's '#ivlen' suffix. Either way the signed-DH decrypt must NOT
    #     pass use_iv=0, and the cipher-name parser must strip a stock client's
    #     '#ivlen' suffix so the cipher still resolves.
    helpers = _read("src/gsi/parse_crypto_helpers.c")
    assert "'#'" in helpers, (
        "server cipher-name parser no longer strips the '#ivlen' suffix — a stock "
        "IV-advertising client's cipher_alg ('aes-128-cbc#16') will fail to resolve")
    assert not re.search(r"xrootd_gsi_cipher_decrypt\([^;]*,\s*0\s*,\s*&plain_len",
                         server_parse), (
        "server signed-DH path decrypts with use_iv=0 — it will mis-handle the "
        "IV-prepended main that stock XRootD/EOS clients always send at v>=10400")


# --------------------------------------------------------------------------- #
# Tier 5 — xcache + TPC origin GSI (this module fronting EOS/dCache)
#
# Two distinct OUTBOUND GSI codepaths must keep working against real XRootD or
# the xcache / TPC use case silently breaks:
#   * xcache origin fill  -> fork/execs the native client (cache/fetch.c,
#       cache_origin_client default "xrdcp"); rides the guarded sec_gsi.c path.
#   * native TPC pull     -> in-process src/tpc/gsi_outbound_*.c (separate
#       implementation that can regress independently of the client).
# --------------------------------------------------------------------------- #
def test_xcache_origin_uses_native_client():
    """xcache must fetch GSI origins via the native client, not the anon built-in.

    The built-in origin client only does an anonymous kXR_login, which EOS/dCache
    reject; cache/fetch.c (and writethrough_flush.c) therefore fork/exec the
    native client. If that exec path is removed, GSI origins silently stop working.
    """
    fetch = _read("src/cache/fetch.c")
    assert "cache_origin_client" in fetch and "posix_spawn" in fetch, (
        "xcache no longer fork/execs the native client for GSI origins — GSI "
        "origins (EOS/dCache) will fall back to anon login and be rejected")


def test_tpc_outbound_uses_shared_core():
    """The in-process TPC outbound GSI must reuse the shared, proven gsi_core.

    src/tpc/gsi_outbound_*.c is a second GSI implementation; pinning it to the
    shared cipher/DH kernel (xrootd_gsi_cipher_encrypt / _public) and the kXRS_none
    terminator stops its crypto drifting from the client that is proven against
    EOS/stock XRootD.
    """
    ex = _read("src/tpc/gsi_outbound_exchange.c")
    assert "xrootd_gsi_cipher_encrypt" in ex and "xrootd_gsi_cipher_public" in ex, (
        "TPC outbound GSI no longer uses the shared gsi_core cipher kernel — its "
        "DH/cipher math can drift from the EOS-proven client")
    assert "kXRS_none" in ex, (
        "TPC outbound GSI no longer emits the kXRS_none terminator")
    # dCache-correctness: the outbound round-2 must echo cipher_alg + md_alg, or
    # dCache NPEs (digestBucket null) on a TPC pull with dCache as the origin.
    assert "kXRS_md_alg" in ex and "kXRS_cipher_alg" in ex, (
        "TPC outbound GSI no longer emits kXRS_cipher_alg/kXRS_md_alg — TPC with "
        "dCache as the origin will fail (server-side StringBucket NPE)")


def _pick_remote_file(endpoint, listdir, env):
    """ls -l <listdir> and return the path of the first regular file, or None."""
    r = subprocess.run([XRDFS, endpoint, "ls", "-l", listdir],
                       capture_output=True, text=True, timeout=90, env=env)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        # xrdfs ls -l: "-rw   <size> /path" — leading '-' marks a regular file.
        parts = line.split()
        if parts and parts[0].startswith("-") and parts[-1].startswith("/"):
            return parts[-1]
    return None


@pytest.mark.skipif(not _LIVE, reason="no TEST_GSI_ENDPOINTS / TEST_EOS_ENDPOINT")
@pytest.mark.skipif(not os.path.exists(XRDFS), reason="xrdfs not built")
@pytest.mark.parametrize("endpoint,listdir", _LIVE,
                         ids=[e[0] for e in _LIVE] or ["none"])
def test_xcache_origin_fetch_live(endpoint, listdir, tmp_path):
    """Faithful xcache origin-fill: the exact `xrdcp -f <origin> <part>` the cache
    runs, with integrity checked against the origin's own checksum.

    This is the xcache GSI path end to end (cache/fetch.c just execs this), so it
    guards "use this module as an xcache in front of EOS/dCache".
    """
    import zlib
    XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp not built")
    proxy = os.environ.get("X509_USER_PROXY", f"/tmp/x509up_u{os.getuid()}")
    if not os.path.exists(proxy):
        pytest.skip(f"no proxy at {proxy}")
    host, port = _split_endpoint(endpoint)
    if not _reachable(host, port):
        pytest.skip(f"{endpoint} not reachable")

    env = _gsi_env(proxy, None)               # grid-CA fallback exercised too
    rfile = _pick_remote_file(endpoint, listdir, env)
    if rfile is None:
        pytest.skip(f"no regular file found under {listdir} on {endpoint}")

    # Stage A — the cache's literal fetch command.
    dst = str(tmp_path / "fill.part")
    cp = subprocess.run([XRDCP, "-f", f"{endpoint}/{rfile}", dst],
                        capture_output=True, text=True, timeout=120, env=env)
    assert cp.returncode == 0, (
        f"xcache origin fill (xrdcp) from {endpoint}{rfile} failed — GSI to the "
        f"origin broke:\n{cp.stdout}\n{cp.stderr}")
    assert os.path.getsize(dst) > 0, "fetched part file is empty"

    # Stage B — integrity vs the origin's reported adler32.
    ck = subprocess.run([XRDFS, endpoint, "cksum", rfile],
                        capture_output=True, text=True, timeout=90, env=env)
    if ck.returncode == 0 and "adler32" in ck.stdout:
        want = ck.stdout.split()[1].lower()
        with open(dst, "rb") as f:
            got = format(zlib.adler32(f.read()) & 0xffffffff, "08x")
        assert got == want, (
            f"xcache fill integrity mismatch for {endpoint}{rfile}: "
            f"origin adler32={want} local={got}")


# TPC pull from a live origin (this module as the TPC destination). Gated on a
# running native-TPC nginx-xrootd destination (TEST_TPC_DEST_ENDPOINT) because it
# needs a server instance whose xrootd_certificate is authorized at the origin.
# NOTE: the in-process outbound path (src/tpc/gsi_outbound_*.c) is the legacy
# unsigned-DH dialect (no kXRS_md_alg); it is proven against EOS but UNVERIFIED
# against dCache — this test is the gold guard once a dest is available.
_TPC_DEST = os.environ.get("TEST_TPC_DEST_ENDPOINT", "").strip()


@pytest.mark.skipif(not (_TPC_DEST and _LIVE),
                    reason="set TEST_TPC_DEST_ENDPOINT + TEST_GSI_ENDPOINTS to run")
@pytest.mark.skipif(not os.path.exists(XRDFS), reason="xrdfs not built")
@pytest.mark.parametrize("endpoint,listdir", _LIVE,
                         ids=[e[0] for e in _LIVE] or ["none"])
def test_tpc_pull_from_origin_live(endpoint, listdir):
    """Native TPC pull with a real origin (EOS/dCache) as the source.

    Drives `xrdcp --tpc <origin>/<file> <dest>/<file>` so the nginx destination
    performs the server-outbound GSI handshake (src/tpc/gsi_outbound_*.c) against
    the live origin. Validates the module can TPC with EOS/dCache as origins.
    """
    XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
    proxy = os.environ.get("X509_USER_PROXY", f"/tmp/x509up_u{os.getuid()}")
    if not (os.path.exists(XRDCP) and os.path.exists(proxy)):
        pytest.skip("xrdcp / proxy unavailable")
    host, port = _split_endpoint(endpoint)
    dhost, dport = _split_endpoint(_TPC_DEST)
    if not (_reachable(host, port) and _reachable(dhost, dport)):
        pytest.skip("origin or TPC dest not reachable")

    env = _gsi_env(proxy, None)
    rfile = _pick_remote_file(endpoint, listdir, env)
    if rfile is None:
        pytest.skip(f"no regular file under {listdir} on {endpoint}")

    dst_url = f"{_TPC_DEST}/tmp/tpc_{abs(hash(endpoint)) % 100000}.bin"
    cp = subprocess.run([XRDCP, "--tpc", "first", f"{endpoint}/{rfile}", dst_url],
                        capture_output=True, text=True, timeout=180, env=env)
    assert cp.returncode == 0, (
        f"TPC pull from {endpoint}{rfile} via dest {_TPC_DEST} failed — the module's "
        f"server-outbound GSI (src/tpc/gsi_outbound_*.c) does not interoperate with "
        f"this origin:\n{cp.stdout}\n{cp.stderr}")

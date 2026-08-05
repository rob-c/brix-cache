"""
test_server_leg_faults.py — faults on the legs the CLIENT cannot see.

THE GAP: every other module in tests/resilience/ splices the fault proxy between
the client and the server, so all of it measures one leg — client<->server. Two
legs that carry real grid traffic had never had a single fault injected:

  * the **origin leg**: a root:// front whose `brix_storage_backend` is a remote
    origin fetches every byte over a second connection the client knows nothing
    about — covered here for both drivers, `http://` (sd_http) and `s3://`
    (sd_s3), because they share no fetch code and do not behave the same;
  * the **TPC pull leg**: in a native third-party copy the *destination* dials
    the *source*, so the bytes cross a connection with no client on it at all.

docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §6 listed all
of it as open ("no TPC leg through the fault proxy; no fault injection against an
`s3://` or `http://` origin").

WHY IT MATTERS, stated as the failure being excluded: these are the legs where a
truncated fetch is most likely to be **committed as a complete file**. The client
sees a clean 0 either way; the only evidence a byte went missing is what the
server does with a short upstream read. A grid transfer that silently commits
3 MiB of a 4 MiB file is worse than one that fails.

MEASURED CONTRACT (scratch probes, 2026-08-05; `brix-fault-proxy` in path,
`xrdcp` from client/bin, 4 MiB object):

    fault (server-side leg)      http:// origin        s3:// origin        native TPC pull
    none                         rc 0, byte-exact      rc 0, byte-exact    rc 0, byte-exact
    truncate-at mid-transfer     rc 54, no output      rc 54, no output    rc 54, nothing committed
    truncate-at early            n/a                   n/a                 rc 54, nothing committed
    corrupt (length-preserving)  rc 0, FULL, WRONG     rc 0, FULL, WRONG   rc 0, FULL, WRONG
      + `--verify`               rc 51, no output      rc 51 19x/20 *      rc 0, still committed
      + `--cksum <alg>` (bare)   rc 0, still delivered rc 0, delivered     rc 0, still committed
      + `--pgrw`                 stalls ~180 s (below) rc 0, FULL, WRONG   n/a

    * the twentieth run kept the corrupted file under rc 0 with an explicit
      "checksum NOT verified" warning — see the fail-open note below.

Four results are worth stating out loud:

  * **The asymmetry with the client leg.** On a direct client connection the same
    mid-transfer sever is *transparently recovered* — `test_tls_token_leg_sweep.py`
    measures rc 0 and a byte-exact file, because the client reconnects and
    re-reads. Neither server-side puller does that: it fails the operation
    instead. Read the two modules together and the contract is "the client
    retries, the server refuses" — the safe division of labour, since only the
    client knows whether a retry is still wanted.
  * **Truncation and corruption are not the same problem here.** A short upstream
    read is visible to the front, and it refuses. A length-preserving flip is
    not visible to anything in the path, so it is relayed under a clean rc 0.
    Only an explicit end-to-end checksum closes that, and only `--verify` is
    one — `--cksum <alg>` with no `:source` suffix merely prints a digest.
  * **`--pgrw` does not protect the origin leg**, by construction: the per-page
    CRC32c is computed by the FRONT over the bytes it already read from the
    origin, so a flip upstream of the front is faithfully CRC'd and delivered.
    Asserted on the s3:// leg, where it returns in ~0.1 s; on the http:// leg it
    cannot be asserted because it hits the stall in the KNOWN ISSUE below.
  * **`--verify` is fail-open when the checksum QUERY fails**, and the query
    crosses the same damaged leg. Once in 20 runs against the s3:// origin the
    server's re-read died, the client printed "checksum NOT verified" and
    exited 0 *keeping the corrupted file*. The policy is deliberate
    (`download_reconcile_cksum`, client/lib/xfer/copy_local.c) and defensible in
    isolation; what makes it worth writing down is that the two events are
    correlated — the damage `--verify` catches is the damage that disables it.

KNOWN ISSUE (2026-08-05, deliberately NOT asserted by this module — two
robustness defects, neither of them an integrity defect):

  1. `xrdcp --pgrw` against a CORRUPTED http:// origin leg *stalls for ~180 s*
     before failing, with the front->origin socket ESTABLISHED and idle after
     ~1.6 MB and nothing logged. 180 s is 3x `BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS`
     (`src/fs/backend/http/sd_http.h`), so the per-request timeout does fire —
     it is retried, and the client waits out every attempt. It then fails with
     `invalid file handle (FileNotOpen)`, which describes the front's cleanup
     rather than the actual fault. `--pgrw` on a CLEAN origin leg is fine (rc 0,
     byte-exact), and `--pgrw` against an equally corrupted **s3://** leg returns
     in 0.1 s (asserted below) — so it is specific to sd_http under corruption,
     not to pgread, not to remote backends, and not to corruption in general.
  2. After that stall, the SAME object then fails instantly with
     `No such file or directory (NotFound)` on every subsequent attempt. The
     origin is unreachable, not empty — and NotFound is the one errno a grid
     client may act on destructively (re-upload, "file lost" alarm), so the
     mapping matters beyond tidiness.

Neither is asserted here. A test that waits out a 180 s stall is a test that
hangs CI, and pinning defect 2 would pin a bug as a contract. Both need a fix in
the sd_http retry/health path, which is a change to the driver rather than to
this suite; reproducer above, `--pgrw` through `servers.FaultProxy` at
`set_corrupt(0.01, "down")`.

Trio per CLAUDE.md:
  * success   — a clean transfer through the proxy is byte-exact on both legs,
                proving the fault proxy itself is transparent and the assertions
                below are not passing vacuously.
  * error     — a severed upstream fetch fails the operation on both legs, and
                nothing partial is committed or delivered.
  * security  — the corruption cases: what is silently relayed by default, and
                which client option actually refuses it.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_server_leg_faults.py -v
"""
import hashlib
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402
from settings import HOST  # noqa: E402

pytestmark = pytest.mark.timeout(300)

SIZE = 4 * 1024 * 1024
NAME = "leg.bin"
MID_CUT = 1 << 20             # bytes: well past any handshake, inside the payload
EARLY_CUT = 300               # bytes: inside the destination's login to the source

# The proxy flips at `pct * 10000` ppm per byte, so 0.0005% is 5 ppm: ~21
# expected flips across a 4 MiB object — the payload is hit with certainty —
# but only a ~0.15% chance of touching a ~300-byte handshake. Measured at the
# 100x higher rate first used here, the handshake was damaged often enough that
# the same test alternated between "corruption delivered" and "connection
# refused" run to run; the rate has to be chosen to pick out one regime.
CORRUPT_PCT = 0.0005


def _why_skip():
    for label, path in (("nginx", servers.NGINX_BIN),
                        ("brix-fault-proxy", servers.FAULT_PROXY),
                        ("xrdcp", servers.XRDCP)):
        if not os.path.isfile(path):
            return f"{label} not built: {path}"
    return None


_skip_reason = _why_skip()
if _skip_reason:
    pytest.skip(_skip_reason, allow_module_level=True)


def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _env():
    env = dict(os.environ)
    for key in ("LD_LIBRARY_PATH", "X509_USER_PROXY", "BEARER_TOKEN",
                "BEARER_TOKEN_FILE", "XrdSecSSSKT"):
        env.pop(key, None)
    return env


# --------------------------------------------------------------------------- #
# The origin leg: root:// front -> fault proxy -> http:// origin.              #
# --------------------------------------------------------------------------- #
class OriginLeg:
    """Front, its remote origin, the proxy between them, and a download runner.

    `download()` returns (returncode, exact, delivered_bytes) and always removes
    the output, so "was anything delivered" is judged per call and cannot leak
    into the next test.
    """

    def __init__(self, front, origin, fp, dst_dir, want):
        self.front, self.origin, self.fp = front, origin, fp
        self.dst_dir, self.want = dst_dir, want
        self._n = 0

    def download(self, extra=()):
        return self.run(extra)[:3]

    def run(self, extra=()):
        """As `download()`, plus the client's stderr — needed only where the
        contract is about what the client SAYS, not just what it returns."""
        self._n += 1
        dst = os.path.join(self.dst_dir, f"origin-{self._n}.bin")
        url = f"root://{HOST}:{self.front.port}//{NAME}"
        try:
            proc = subprocess.run([servers.XRDCP, "-f", *extra, url, dst],
                                  env=_env(), capture_output=True, timeout=180)
            got = os.path.getsize(dst) if os.path.exists(dst) else 0
            exact = (proc.returncode == 0 and got == SIZE
                     and _md5(dst) == self.want)
            return proc.returncode, exact, got, proc.stderr.decode(errors="replace")
        finally:
            if os.path.exists(dst):
                os.unlink(dst)


@pytest.fixture(scope="module")
def origin_leg(tmp_path_factory):
    """A front backed by an http:// origin that is only reachable through the
    proxy — so the CLIENT connection is pristine in every test below and the
    only damaged leg is the one the client cannot observe."""
    dst = tmp_path_factory.mktemp("origin-dst")
    with servers.NginxWebdavAnon() as origin:
        want = _md5(servers.seed_file(origin.data, NAME, SIZE))
        with servers.FaultProxy(origin.port) as fp, \
                servers.NginxHttpOriginFront(fp.listen) as front:
            leg = OriginLeg(front, origin, fp, str(dst), want)
            yield leg
            fp.clear()


@pytest.fixture(scope="module")
def s3_origin_leg(tmp_path_factory):
    """The same topology one driver over: the front's backend is `s3://` rather
    than `http://`, so every fetch goes through sd_s3 — a signed request, an S3
    error document, its own ranged-GET pattern and its own idea of a short body.
    None of that is shared with sd_http, which is why the coverage audit listed
    the two origins separately rather than as one 'remote backend' case."""
    dst = tmp_path_factory.mktemp("s3-origin-dst")
    with servers.NginxS3Anon() as origin:
        want = _md5(servers.seed_file(origin.data, NAME, SIZE))
        with servers.FaultProxy(origin.port) as fp, \
                servers.NginxS3OriginFront(fp.listen) as front:
            leg = OriginLeg(front, origin, fp, str(dst), want)
            yield leg
            fp.clear()


# --------------------------------------------------------------------------- #
# The TPC pull leg: destination -> fault proxy -> source.                      #
# --------------------------------------------------------------------------- #
class TpcLeg:
    """Source, destination, and the proxy the destination pulls through.

    `copy()` returns (returncode, exact, committed_bytes) where the byte count is
    read from the DESTINATION's export — a committed short file is the failure
    this whole module exists to exclude, and it is invisible from the client.
    """

    def __init__(self, src, dst, fp, want):
        self.src, self.dst, self.fp, self.want = src, dst, fp, want
        self._n = 0

    def copy(self):
        self._n += 1
        name = f"tpc-{self._n}.bin"
        landed = os.path.join(self.dst.data, name)
        src_url = f"root://{HOST}:{self.fp.listen}//{NAME}"
        dst_url = f"root://{HOST}:{self.dst.port}//{name}"
        try:
            proc = subprocess.run(
                [servers.XRDCP, "-f", "-s", "--tpc", "only", src_url, dst_url],
                env=_env(), capture_output=True, timeout=180)
            got = os.path.getsize(landed) if os.path.exists(landed) else 0
            exact = (proc.returncode == 0 and got == SIZE
                     and _md5(landed) == self.want)
            return proc.returncode, exact, got
        finally:
            if os.path.exists(landed):
                os.unlink(landed)


@pytest.fixture(scope="module")
def tpc_leg(tmp_path_factory):
    """A TPC destination whose source is reachable only through the proxy."""
    with servers.NginxAnon() as src:
        want = _md5(servers.seed_file(src.data, NAME, SIZE))
        with servers.FaultProxy(src.port) as fp, servers.NginxTpcDest() as dst:
            leg = TpcLeg(src, dst, fp, want)
            yield leg
            fp.clear()


@pytest.fixture(autouse=True)
def _clean_proxies(request):
    """No test inherits the previous one's faults."""
    legs = [request.getfixturevalue(n)
            for n in ("origin_leg", "s3_origin_leg", "tpc_leg")
            if n in request.fixturenames]
    for leg in legs:
        leg.fp.clear()
    yield
    for leg in legs:
        leg.fp.clear()


# --------------------------------------------------------------------------- #
# Success — the proxy is transparent, so nothing below passes vacuously.       #
# --------------------------------------------------------------------------- #
def test_clean_fetch_through_the_origin_leg_is_byte_exact(origin_leg):
    rc, exact, got = origin_leg.download()
    assert rc == 0 and exact, f"rc={rc} bytes={got}"


def test_clean_tpc_pull_through_the_proxy_commits_byte_exact(tpc_leg):
    rc, exact, got = tpc_leg.copy()
    assert rc == 0 and exact, f"rc={rc} committed={got}"


def test_the_front_serves_from_the_origin_not_from_a_local_copy(origin_leg):
    """Non-vacuity: with `brix_stage off` the front holds no copy of the object,
    so every byte the client got really crossed the proxied origin leg. Without
    this the whole module could be measuring a local read."""
    local = [n for n in os.listdir(origin_leg.front.data)
             if not n.startswith(".")]
    assert NAME not in local, f"front export is not empty of the object: {local}"


# --------------------------------------------------------------------------- #
# Error — a severed upstream fetch fails the operation.                        #
# --------------------------------------------------------------------------- #
def test_origin_leg_sever_fails_the_read(origin_leg):
    origin_leg.fp.set_truncate(MID_CUT, "down")
    rc, exact, got = origin_leg.download()
    assert rc != 0 and not exact, f"rc={rc} bytes={got}"


def test_tpc_pull_leg_sever_fails_the_copy(tpc_leg):
    tpc_leg.fp.set_truncate(MID_CUT, "down")
    rc, exact, got = tpc_leg.copy()
    assert rc != 0 and not exact, f"rc={rc} committed={got}"


def test_tpc_pull_leg_cut_during_the_source_login_fails_the_copy(tpc_leg):
    """The early cut lands in the destination's own login to the source, before
    a single payload byte — the destination must fail rather than commit an
    empty object for a file it never opened."""
    tpc_leg.fp.set_truncate(EARLY_CUT, "down")
    rc, exact, got = tpc_leg.copy()
    assert rc != 0 and not exact, f"rc={rc} committed={got}"


# --------------------------------------------------------------------------- #
# Security — nothing partial is ever committed or delivered.                   #
# --------------------------------------------------------------------------- #
def test_origin_leg_sever_delivers_no_partial_file(origin_leg):
    """The failure this module exists to exclude: a short upstream fetch turned
    into a successful short read. The client cannot tell the difference, so the
    only defence is the front refusing to finish."""
    origin_leg.fp.set_truncate(MID_CUT, "down")
    rc, _exact, got = origin_leg.download()
    assert got == 0, f"delivered {got} bytes of a severed fetch (rc={rc})"


def test_tpc_pull_leg_sever_commits_nothing_at_the_destination(tpc_leg):
    """Same failure on the copy plane, and the more dangerous one: a committed
    short object is indistinguishable from a complete transfer forever after."""
    tpc_leg.fp.set_truncate(MID_CUT, "down")
    rc, _exact, got = tpc_leg.copy()
    assert got == 0, f"committed {got} bytes of a severed pull (rc={rc})"


# --------------------------------------------------------------------------- #
# Security — corruption on a leg the client cannot see.                        #
#                                                                              #
# Truncation and corruption behave completely differently here, and it is the   #
# reason this section is separate. A SEVERED origin fetch fails the read (see   #
# above): the front notices the short upstream and refuses. A CORRUPTED one is  #
# length-preserving, so there is nothing for the front to notice — the bytes    #
# are relayed and the client is told 0. The defence has to be an explicit       #
# checksum, and the tests below pin which options actually provide one.         #
# --------------------------------------------------------------------------- #
def test_a_corrupted_origin_leg_is_delivered_to_the_client_silently(origin_leg):
    """THE EXPOSURE, measured rather than assumed: bytes flipped between the
    front and its http:// origin reach the client as a full-length file with a
    clean rc 0. Nothing in the path checks them — the origin leg carries no
    integrity envelope of its own, and the client's own transport was pristine
    throughout, so there is nothing for the client to detect either.

    Pinned as a test because it is the shape of the failure operators care about
    and the justification for the next test. If this ever starts failing because
    the read was refused, that is an improvement — but it is a behaviour change
    on a documented default and should be a deliberate one."""
    origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = origin_leg.download()
    assert rc == 0, f"expected the corrupted fetch to be relayed, got rc={rc}"
    assert got == SIZE, f"expected a full-length file, got {got} bytes"
    assert not exact, ("nothing was corrupted — CORRUPT_PCT is too low for this "
                       "object size and the assertions here are vacuous")


def test_verify_catches_corruption_on_the_origin_leg(origin_leg):
    """The defence that works: `--verify` asks the server for the object's
    checksum after the transfer. The server computes it from the origin, the
    client from what landed, and the two disagree — so the corrupted download is
    refused and nothing is left behind.

    Note what this does NOT rely on: the client-to-front leg is clean in this
    test, so the mismatch can only have come from the leg the client cannot
    see. That is precisely the leg an end-to-end checksum exists to cover."""
    origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = origin_leg.download(extra=("--verify",))
    assert rc != 0, "the post-transfer checksum comparison passed on bad data"
    assert not exact and got == 0, f"left {got} bytes behind (rc={rc})"


def test_bare_cksum_prints_a_digest_and_does_not_verify_anything(origin_leg):
    """The security-negative, and a genuine footgun: `--cksum adler32` with no
    mode suffix is a PRINT, not a comparison (`copy_cksum_verify.c` — only
    `:source`/`:end2end` query the server, and `:<value>` compares a literal).
    So it returns 0 on the same corrupted download that `--verify` refuses.

    That is documented behaviour, not a defect — it is pinned here because the
    option reads like a check, and an operator who reaches for it expecting one
    would be silently unprotected on exactly the leg this module is about."""
    origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = origin_leg.download(extra=("--cksum", "adler32"))
    assert rc == 0 and got == SIZE, f"rc={rc} bytes={got}"
    assert not exact, "vacuous: nothing was corrupted"


def test_tpc_pull_leg_commits_corruption_with_the_verify_knob_off(tpc_leg):
    """The TPC destination here runs the DEFAULT config, with
    `brix_tpc_verify_checksum` off — and a corrupted pull is therefore committed
    as a complete object. That is deliberate stock-parity behaviour, not a gap:
    the knob and its fail-closed path are covered by
    `tests/test_tpc_pull_integrity.py` (history-storage-and-caching.md #13),
    which drives a kXR-response-aware proxy able to corrupt a single frame while
    leaving the `kXR_stat` and `kXR_Qcksum` replies truthful.

    What this test adds is the RAW-transport path that the surgical proxy
    cannot produce: flips sprayed across the whole stream, framing included. The
    contract to pin is that the outcome is the same either way — the default
    commits, and no client-side option compensates (`--verify` and
    `--cksum:source` are both no-ops on a copy where the client moves no bytes,
    measured)."""
    tpc_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = tpc_leg.copy()
    assert rc == 0 and got == SIZE, f"rc={rc} committed={got}"
    assert not exact, "vacuous: nothing was corrupted"


# --------------------------------------------------------------------------- #
# The same origin leg one driver over: s3:// instead of http://.               #
#                                                                              #
# Not a duplicate of the section above. sd_s3 and sd_http share no fetch code,  #
# and the measurements differ in two ways that matter:                         #
#                                                                              #
#   * `--pgrw` returns IMMEDIATELY here (0.1 s) instead of stalling ~180 s, so  #
#     the architectural claim the http section could only assert in prose is    #
#     assertable — and the stall is pinned as an sd_http defect rather than a   #
#     property of pgread over any remote backend.                              #
#   * `--verify` refuses 19 times in 20 rather than 20 in 20; the twentieth is  #
#     the fail-open below, which is the most interesting result in the module.  #
# --------------------------------------------------------------------------- #
def test_clean_fetch_through_the_s3_origin_leg_is_byte_exact(s3_origin_leg):
    rc, exact, got = s3_origin_leg.download()
    assert rc == 0 and exact, f"rc={rc} bytes={got}"


def test_the_front_serves_from_the_s3_origin_not_from_a_local_copy(s3_origin_leg):
    """Non-vacuity, as for the http front: with `brix_stage off` the object is
    not in the front's export, so every byte really crossed the proxied leg."""
    local = [n for n in os.listdir(s3_origin_leg.front.data)
             if not n.startswith(".")]
    assert NAME not in local, f"front export is not empty of the object: {local}"


def test_s3_origin_leg_sever_delivers_no_partial_file(s3_origin_leg):
    """A short upstream S3 body fails the read rather than becoming a successful
    short one — the same refusal sd_http makes, reached through entirely
    different code (an S3 GET whose declared length is not met)."""
    s3_origin_leg.fp.set_truncate(MID_CUT, "down")
    rc, exact, got = s3_origin_leg.download()
    assert rc != 0 and not exact, f"rc={rc} bytes={got}"
    assert got == 0, f"delivered {got} bytes of a severed fetch (rc={rc})"


def test_a_corrupted_s3_origin_leg_is_delivered_to_the_client_silently(s3_origin_leg):
    """The exposure, measured on the S3 driver too: flipped bytes between the
    front and its s3:// origin reach the client as a full-length file under a
    clean rc 0. Nothing in the S3 fetch path notices — the object's stored ETag
    is not consulted on read, and the client's own transport was pristine."""
    s3_origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = s3_origin_leg.download()
    assert rc == 0, f"expected the corrupted fetch to be relayed, got rc={rc}"
    assert got == SIZE, f"expected a full-length file, got {got} bytes"
    assert not exact, "vacuous: nothing was corrupted"


def test_pgrw_does_not_protect_the_s3_origin_leg(s3_origin_leg):
    """`--pgrw` is the strongest per-block integrity the protocol has, and it is
    structurally unable to cover this leg: the per-page CRC32c is computed by the
    FRONT over bytes it has ALREADY read from the origin, so an upstream flip is
    faithfully CRC'd and delivered. The client verifies a true statement about
    corrupt data.

    This is the assertion the http section cannot make — there `--pgrw` hits the
    sd_http stall (see KNOWN ISSUE) and never returns a usable verdict. Here it
    returns in ~0.1 s, which is also what proves the stall is an sd_http defect
    and not how pgread behaves over a remote backend."""
    s3_origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = s3_origin_leg.download(extra=("--pgrw",))
    assert rc == 0 and got == SIZE, f"rc={rc} bytes={got}"
    assert not exact, "vacuous: nothing was corrupted"


def test_verify_on_the_s3_origin_leg_refuses_or_states_it_could_not_check(s3_origin_leg):
    """THE FAIL-OPEN, and the reason this is a union rather than `rc != 0`.

    `--verify` asks the server for the object's checksum after the transfer, and
    the server computes that by RE-READING the object — over the same damaged
    leg. Measured over 20 runs: 19 mismatched and were refused, and once the
    re-read itself died and the client reported `checksum computation failed`,
    then *kept the corrupted file and exited 0*. That is deliberate policy
    (`download_reconcile_cksum`, copy_local.c: UNVERIFIED warns and clears the
    status, because a query hiccup is not a transfer failure) — but the two
    events are correlated, not independent: the damage `--verify` exists to catch
    is the same damage that disables it. sd_s3 issues many ranged GETs per read,
    so there are ~30x more response headers to hit than on the single-GET http
    path, which is why the http leg refused 20 times out of 20 and this one 19.

    Asserting `rc != 0` here would be a 5%-flaky test. Asserting the union is
    still strong, because the escape hatch is narrow: a clean rc 0 is allowed
    ONLY if the client said out loud that it could not check. A silent pass on
    corrupt data fails this test, which is the regression worth catching."""
    s3_origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got, err = s3_origin_leg.run(extra=("--verify",))
    assert not exact, "vacuous: nothing was corrupted"
    if rc != 0:
        assert got == 0, f"refused but left {got} bytes behind (rc={rc})"
        return
    assert "NOT verified" in err, (
        "corrupt data passed --verify with rc 0 and no warning: " + repr(err))

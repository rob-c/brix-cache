"""
test_tls_token_leg_sweep.py — the TLS and token legs of the fault sweep.

THE GAP: `tests/resilience/` was root:// + GSI + CLEARTEXT only — the sweep
harness hard-coded GSI (`servers.py`), so neither the TLS record layer nor a
WLCG-token login had ever met loss, truncation or corruption. Two things went
untested as a result: whether TLS actually converts an in-flight bit flip into a
hard failure (the whole reason to pay for it), and whether a login damaged
mid-handshake fails CLOSED rather than leaving a session that reads data.
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §6 + item 16.

MEASURED CONTRACT (scratch probes, 2026-08-05; `brix-fault-proxy` in path,
`xrdcp` from client/bin, 4 MiB object):

    fault                     roots:// (TLS)        root:// + token
    none                      rc 0, byte-exact      rc 0, byte-exact
    truncate-at mid-transfer  rc 0, byte-exact      rc 0, byte-exact
    truncate-at in handshake  rc 51, no data        rc 51, no data
    corrupt (length-preserving) rc != 0, no data    rc 54, no data
    no credential             n/a (auth none)       rc 53, no data
    expired token             n/a                   rc 54, no data

    corrupt at the LOW rate — cleartext root://, payload rather than handshake
      plain                   n/a                   rc 0, FULL SIZE, WRONG
      + `--pgrw`              n/a                   rc 51, no data
      + `--verify`            n/a                   rc 51, no data

Three results are worth stating out loud:

  * **A mid-transfer sever is transparently recovered.** The client reconnects
    and the output is byte-exact — on the token leg that means it re-ran the ztn
    login on the new connection. A partial or silently-short output file would
    be the failure; there is none.
  * **TLS makes corruption fatal.** The same length-preserving bit flip that a
    cleartext HTTP download delivers with a clean 200
    (`test_download_loss_sweep.py`) is a hard failure here — nothing is written.
    That contrast is the point of the two modules together.
  * **Cleartext root:// has no integrity check of its own**, so the same flip
    arrives as a full-length file under rc 0. `--pgrw` and `--verify` each catch
    it; neither is on by default. The last three tests are that measurement read
    three ways — the exposure, then the two defences.

A NOTE ON THE TWO CORRUPTION RATES. The proxy flips at `pct * 10000` ppm per
byte, so one flat rate cannot address both questions: a rate high enough to
mangle a few-hundred-byte handshake with certainty destroys the payload tests'
premise, and a rate low enough to spare the handshake leaves the credential
intact most of the time. Hence `CORRUPT_PCT` (handshake regime) and
`CORRUPT_PAYLOAD_PCT` (payload regime) — 1000x apart, each chosen so its own
tests are deterministic. Picking one rate for both is how these tests were first
written, and it produced a suite that failed on a coin toss.

Trio per CLAUDE.md:
  * success   — clean transfers on both legs are byte-exact through the proxy,
                and a mid-transfer sever is recovered rather than truncated.
  * error     — damage during the handshake fails closed on both legs, leaving
                no output file behind.
  * security  — TLS never delivers altered bytes; the token leg refuses a
                missing, an expired and a corrupted-in-flight credential,
                writing nothing in every case; and over cleartext, where the
                transport offers no such guarantee, `--pgrw` and `--verify` do.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_tls_token_leg_sweep.py -v
"""
import hashlib
import os
import subprocess
import sys

import pytest

def _expression_1(token, self):
    return (
        self.token if token is ... else token
    )

def _expression_2(scheme, self):
    return (
        scheme or ("roots" if self.kind == "tls" else "root")
    )

def _expression_3(dst):
    return (
        os.path.getsize(dst) if os.path.exists(dst) else 0
    )

def _expression_4(size, proc, dst, self):
    return (
        proc.returncode == 0 and size > 0
                             and _md5(dst) == self.want
    )


def _guard_run_1(tok, env):
    if tok:
        env["BEARER_TOKEN"] = tok
    else:
        env.pop("BEARER_TOKEN", None)

def _guard_run_2(dst):
    if os.path.exists(dst):
        os.unlink(dst)


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402
from settings import HOST  # noqa: E402

sys.path.insert(0, servers.REPO)
from utils.make_token import TokenIssuer  # noqa: E402

pytestmark = pytest.mark.timeout(300)

SIZE = 4 * 1024 * 1024
NAME = "leg.bin"
HANDSHAKE_CUT = 300           # bytes: lands inside the login/TLS exchange
CORRUPT_PCT = 0.5             # per-byte flip probability, in percent

# The PAYLOAD-corruption rate, chosen to separate two regimes that a single rate
# conflates. The proxy flips at `pct * 10000` ppm per byte, so 0.0005% is 5 ppm:
# ~21 expected flips across a 4 MiB object (the payload is hit with certainty)
# but only a ~0.15% chance of touching a ~300-byte handshake. At CORRUPT_PCT
# above, the handshake is damaged ~3% of the time and these tests would fail on
# a coin toss for the wrong reason.
CORRUPT_PAYLOAD_PCT = 0.0005


def _why_skip():
    if not os.path.isfile(servers.NGINX_BIN):
        return f"nginx not built: {servers.NGINX_BIN}"
    if not os.path.isfile(servers.FAULT_PROXY):
        return f"brix-fault-proxy not built: {servers.FAULT_PROXY}"
    if not os.path.isfile(servers.XRDCP):
        return f"xrdcp not built: {servers.XRDCP}"
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


class Leg:
    """A server, its fault proxy, the seeded object, and a copy runner.

    `copy()` returns (returncode, exact, delivered) and always removes the
    destination, so "was anything delivered" is judged per call and never leaks
    between tests. `run()` is the same call with the exact byte count, for the
    tests that must distinguish "nothing arrived" from "a full-length file
    arrived with the wrong contents".
    """

    def __init__(self, kind, dst_dir, token=None):
        self.kind = kind
        self.dst_dir = dst_dir
        self.token = token
        self._n = 0

    def copy(self, token=..., scheme=None, extra=()):
        rc, exact, size = self.run(token=token, scheme=scheme, extra=extra)
        return rc, exact, size > 0

    def run(self, token=..., scheme=None, extra=()):
        self._n += 1
        dst = os.path.join(self.dst_dir, f"out-{self._n}.bin")
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        env.pop("X509_USER_PROXY", None)
        env["X509_CERT_DIR"] = servers.CA_DIR
        tok = _expression_1(token, self)
        _guard_run_1(tok, env)
        scheme = _expression_2(scheme, self)
        url = f"{scheme}://{HOST}:{self.fp.listen}/{NAME}"
        try:
            proc = subprocess.run([servers.XRDCP, "-f", *extra, url, dst],
                                  env=env, capture_output=True, timeout=120)
            size = _expression_3(dst)
            exact = (_expression_4(size, proc, dst, self))
            return proc.returncode, exact, size
        finally:
            _guard_run_2(dst)


@pytest.fixture(scope="module")
def issuer(tmp_path_factory):
    """A signing authority the server can validate against.

    The jwks and its directory must be world-readable: nginx validates from an
    unprivileged worker, and a 0700 pytest tmp dir would fail the load with a
    permission error that reads like a bad key.
    """
    token_dir = tmp_path_factory.mktemp("resil-tokens")
    ti = TokenIssuer(str(token_dir))
    ti.init_keys()
    os.chmod(str(token_dir), 0o755)
    os.chmod(ti.jwks_path, 0o644)
    return ti


@pytest.fixture(scope="module")
def tls_leg(tmp_path_factory):
    dst = tmp_path_factory.mktemp("tls-dst")
    with servers.NginxTlsAnon() as ng, servers.FaultProxy(ng.port) as fp:
        leg = Leg("tls", str(dst))
        leg.ng, leg.fp = ng, fp
        leg.want = _md5(servers.seed_file(ng.data, NAME, SIZE))
        yield leg
        fp.clear()


@pytest.fixture(scope="module")
def token_leg(tmp_path_factory, issuer):
    dst = tmp_path_factory.mktemp("token-dst")
    with servers.NginxTokenRoot(issuer.jwks_path, issuer.issuer,
                                issuer.audience) as ng, \
            servers.FaultProxy(ng.port) as fp:
        leg = Leg("token", str(dst), token=issuer.generate(scope="storage.read:/"))
        leg.ng, leg.fp = ng, fp
        leg.want = _md5(servers.seed_file(ng.data, NAME, SIZE))
        yield leg
        fp.clear()


@pytest.fixture(autouse=True)
def _clean_proxies(request):
    """No test inherits the previous one's faults."""
    legs = [request.getfixturevalue(n) for n in ("tls_leg", "token_leg")
            if n in request.fixturenames]
    for leg in legs:
        leg.fp.clear()
    yield
    for leg in legs:
        leg.fp.clear()


# --------------------------------------------------------------------------- #
# Success.                                                                     #
# --------------------------------------------------------------------------- #
def test_clean_tls_transfer_is_byte_exact(tls_leg):
    rc, exact, _ = tls_leg.copy()
    assert (rc, exact) == (0, True)


def test_clean_token_transfer_is_byte_exact(token_leg):
    rc, exact, _ = token_leg.copy()
    assert (rc, exact) == (0, True)


def test_tls_recovers_from_a_mid_transfer_sever(tls_leg):
    """The stream is cut halfway; the client reconnects and finishes exactly."""
    tls_leg.fp.set_truncate(SIZE // 2, "down")
    rc, exact, _ = tls_leg.copy()
    assert (rc, exact) == (0, True), "a severed transfer must not truncate output"


def test_token_login_is_replayed_after_a_mid_transfer_sever(token_leg):
    """Same cut on the token leg: the reconnect re-runs the ztn login, so a
    byte-exact result also proves the second login succeeded."""
    token_leg.fp.set_truncate(SIZE // 2, "down")
    rc, exact, _ = token_leg.copy()
    assert (rc, exact) == (0, True)


# --------------------------------------------------------------------------- #
# Error — damage during the handshake fails closed.                            #
# --------------------------------------------------------------------------- #
def test_tls_handshake_cut_fails_closed(tls_leg):
    tls_leg.fp.set_truncate(HANDSHAKE_CUT, "down")
    rc, exact, delivered = tls_leg.copy()
    assert rc != 0 and not exact and not delivered


def test_token_login_cut_fails_closed(token_leg):
    token_leg.fp.set_truncate(HANDSHAKE_CUT, "down")
    rc, exact, delivered = token_leg.copy()
    assert rc != 0 and not exact and not delivered


# --------------------------------------------------------------------------- #
# Security.                                                                    #
# --------------------------------------------------------------------------- #
def test_tls_never_delivers_corrupted_bytes(tls_leg):
    """The defining property of the TLS leg: a length-preserving bit flip is a
    hard failure, where the cleartext HTTP planes deliver it with a 200
    (test_download_loss_sweep.py::test_corruption_is_invisible_to_http...)."""
    tls_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, delivered = tls_leg.copy()
    assert rc != 0, "TLS accepted a corrupted record stream"
    assert not exact and not delivered


def test_token_login_corrupted_in_flight_is_refused(token_leg):
    """The credential itself is mangled on the way up: refuse, deliver nothing."""
    token_leg.fp.set_corrupt(CORRUPT_PCT, "up")
    rc, exact, delivered = token_leg.copy()
    assert rc != 0 and not exact and not delivered


def test_missing_token_is_refused(token_leg):
    rc, _, delivered = token_leg.copy(token=None)
    assert rc != 0 and not delivered


def test_expired_token_is_refused(token_leg, issuer):
    rc, _, delivered = token_leg.copy(token=issuer.generate_expired())
    assert rc != 0 and not delivered


# --------------------------------------------------------------------------- #
# Payload integrity on the CLEARTEXT root:// leg — what the transport does not  #
# do for you, and which client option does.                                     #
#                                                                              #
# The three tests below are one measurement read three ways. The first is the   #
# exposure; the other two are the two defences against it. Separating them      #
# matters because the first is the case an operator is most likely to be in     #
# (neither option is on by default) and least likely to notice.                 #
# --------------------------------------------------------------------------- #
def test_a_plain_cleartext_read_delivers_corruption_silently(token_leg):
    """THE EXPOSURE, stated as a measurement rather than a worry: over cleartext
    root:// a length-preserving bit flip arrives as a full-length file with a
    clean rc 0. The client is given no signal at all — the size is right, the
    return is success, only the contents are wrong.

    This is not a defect in the server; the root protocol carries no integrity
    check over a plain read, which is exactly why the next two tests exist. It
    is asserted here so the two defences below cannot be mistaken for belt-and-
    braces on top of a transport that was already safe. Contrast
    `test_tls_never_delivers_corrupted_bytes` above: TLS turns this same fault
    into a hard failure."""
    token_leg.fp.set_corrupt(CORRUPT_PAYLOAD_PCT, "down")
    rc, exact, size = token_leg.run()
    assert rc == 0, f"expected a clean return over cleartext, got rc={rc}"
    assert size == SIZE, f"expected a full-length file, got {size} bytes"
    assert not exact, ("the proxy did not corrupt anything — the rate is too "
                       "low for this object size, so the tests below would be "
                       "passing vacuously")


def test_pgrw_catches_corruption_that_a_plain_read_delivers(token_leg):
    """First defence: `--pgrw` (kXR_pgread, per-page CRC32c, INVARIANT 1). The
    CRC is computed at the server over the page it read and checked by the
    client after the wire, so a flip anywhere in between is caught — and caught
    at the page it landed on, not at the end of a 4 MiB transfer. Nothing is
    left behind."""
    token_leg.fp.set_corrupt(CORRUPT_PAYLOAD_PCT, "down")
    rc, exact, size = token_leg.run(extra=("--pgrw",))
    assert rc != 0, "pgread accepted a page whose CRC32c could not match"
    assert not exact and size == 0, f"left {size} bytes behind (rc={rc})"


def test_verify_catches_corruption_that_a_plain_read_delivers(token_leg):
    """Second defence: `--verify` asks the server for the object's checksum
    after the transfer and compares it against what actually landed. Weaker than
    `--pgrw` — it spends a whole transfer before saying no, and it is a
    whole-file digest rather than a per-page one — but it needs no protocol
    support beyond a checksum query, so it is the option that also covers the
    planes where pgread is not in play."""
    token_leg.fp.set_corrupt(CORRUPT_PAYLOAD_PCT, "down")
    rc, exact, size = token_leg.run(extra=("--verify",))
    assert rc != 0, "the post-transfer checksum comparison passed on bad data"
    assert not exact and size == 0, f"left {size} bytes behind (rc={rc})"

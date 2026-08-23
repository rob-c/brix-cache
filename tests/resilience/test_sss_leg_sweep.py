"""
test_sss_leg_sweep.py — the SSS (shared-secret) leg of the fault sweep.

THE GAP: `tests/resilience/` swept GSI first, then TLS and WLCG tokens
(`test_tls_token_leg_sweep.py`). SSS was the last login mechanism with no fault
coverage at all — listed as still open in
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §6.

WHY SSS IS THE INTERESTING ONE TO DAMAGE: every other mechanism here presents a
credential the server can verify without holding it — a certificate chain, a
signed token. SSS presents a **shared secret**. If a handshake mangled in flight
could be talked into succeeding, or could fall back to an unauthenticated session
that still reads data, the secret's entire value is gone. So the question this
module answers is not "does a damaged login fail" but "does a damaged login fail
*closed*, with nothing served".

MEASURED CONTRACT (scratch probes, 2026-08-05; `brix-fault-proxy` in path,
`xrdcp --auth sss` from client/bin, 4 MiB object):

    fault                          result
    none                           rc 0, byte-exact
    no keytab                      rc 53, nothing served
    truncate-at 64 B (up or down)  rc 51, nothing served
    truncate-at 300 B down         rc 51, nothing served
    truncate-at 1 MiB down         rc 0, byte-exact  (mid-transfer, recovered)
    corrupt up (client->server)    rc 54, nothing served — "SSS auth failed
                                   (NotAuthorized)", then the fallback is refused
    corrupt down (server->client)  rc 54, nothing served

Two results are worth stating out loud:

  * **A tampered credential is rejected, not merely misparsed.** Flipping bits on
    the client->server direction produces `SSS auth failed (NotAuthorized)` — the
    server evaluates the mangled secret and says no. The client then tries to
    fall back to another protocol and there is none, so the session ends with
    nothing served. Fail-closed on both halves.
  * **A mid-transfer sever is recovered byte-exact**, the same as the TLS and
    token legs: the client reconnects and re-runs the SSS login on the new
    connection. Contrast `test_server_leg_faults.py`, where the identical sever
    on a *server-side* leg is a hard failure — the client retries, the server
    refuses.

Trio per CLAUDE.md:
  * success   — a clean SSS transfer through the proxy is byte-exact, and a
                mid-transfer sever is recovered rather than truncated.
  * error     — a handshake severed in either direction fails closed with no
                output file.
  * security  — a credential corrupted in flight is refused; a client with no
                keytab is refused; and in neither case does the server fall back
                to serving the object unauthenticated.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_sss_leg_sweep.py -v
"""
import hashlib
import os
import subprocess
import sys

import pytest

def _expression_1(keytab, self):
    return (
        self.keytab if keytab is ... else keytab
    )

def _expression_2(dst):
    return (
        os.path.getsize(dst) if os.path.exists(dst) else 0
    )

def _expression_3(got, proc, dst, self):
    return (
        proc.returncode == 0 and got == SIZE
                             and _md5(dst) == self.want
    )


def _guard_download_1(kt, env):
    if kt:
        env["XrdSecSSSKT"] = kt

def _guard_download_2(dst):
    if os.path.exists(dst):
        os.unlink(dst)


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402
from settings import HOST  # noqa: E402

pytestmark = pytest.mark.timeout(300)

SIZE = 4 * 1024 * 1024
NAME = "leg.bin"
HANDSHAKE_CUT = 64            # bytes: lands inside the SSS login exchange
MID_CUT = 1 << 20             # bytes: well past the login, inside the payload

# Per-byte flip probability, in percent. Deliberately HIGH: the login exchange is
# a few hundred bytes, so a low rate leaves it intact most of the time and the
# transfer succeeds — the test would fail on a coin toss. At 20%/byte the login
# is mangled with certainty, which is what these tests are actually about. (The
# low-rate regime, where the handshake survives and only the payload is hit, is
# the payload-integrity question and lives in test_tls_token_leg_sweep.py.)
CORRUPT_PCT = 20.0

SSSADMIN = os.path.join(servers.REPO, "client", "bin", "xrdsssadmin-brix")


def _why_skip():
    for label, path in (("nginx", servers.NGINX_BIN),
                        ("brix-fault-proxy", servers.FAULT_PROXY),
                        ("xrdcp", servers.XRDCP),
                        ("xrdsssadmin-brix", SSSADMIN)):
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


class SssLeg:
    """The SSS server, its fault proxy, the keytab, and a download runner.

    `download(keytab=...)` returns (returncode, exact, delivered_bytes) and
    always removes the output, so "was anything served" is judged per call.
    Pass `keytab=None` to drive the no-credential case.
    """

    def __init__(self, ng, fp, keytab, dst_dir, want):
        self.ng, self.fp, self.keytab = ng, fp, keytab
        self.dst_dir, self.want = dst_dir, want
        self._n = 0

    def download(self, keytab=...):
        self._n += 1
        dst = os.path.join(self.dst_dir, f"sss-{self._n}.bin")
        env = dict(os.environ)
        for key in ("LD_LIBRARY_PATH", "X509_USER_PROXY", "BEARER_TOKEN",
                    "BEARER_TOKEN_FILE", "XrdSecSSSKT", "XrdSecsssKT"):
            env.pop(key, None)
        kt = _expression_1(keytab, self)
        _guard_download_1(kt, env)
        url = f"root://{HOST}:{self.fp.listen}//{NAME}"
        try:
            proc = subprocess.run(
                [servers.XRDCP, "-f", "--auth", "sss", url, dst],
                env=env, capture_output=True, timeout=180)
            got = _expression_2(dst)
            exact = (_expression_3(got, proc, dst, self))
            return proc.returncode, exact, got
        finally:
            _guard_download_2(dst)


@pytest.fixture(scope="module")
def sss_leg(tmp_path_factory):
    """One keytab authenticates both ends. `anybody`/`anygroup` keeps the
    client's local login name acceptable, so a rejection in any test below is a
    real cryptographic rejection and not a name mismatch."""
    work = tmp_path_factory.mktemp("resil-sss")
    keytab = str(work / "resil.keytab")
    proc = subprocess.run([SSSADMIN, "-k", keytab, "add", "--id", "1",
                           "--user", "anybody", "--group", "anygroup",
                           "--name", "testhost"],
                          capture_output=True, text=True)
    if proc.returncode != 0 or not os.path.exists(keytab):
        pytest.skip(f"xrdsssadmin-brix could not mint a keytab: "
                    f"{proc.stdout}{proc.stderr}")
    os.chmod(keytab, 0o600)

    dst = tmp_path_factory.mktemp("sss-dst")
    with servers.NginxSssRoot(keytab) as ng, servers.FaultProxy(ng.port) as fp:
        want = _md5(servers.seed_file(ng.data, NAME, SIZE))
        leg = SssLeg(ng, fp, keytab, str(dst), want)
        yield leg
        fp.clear()


@pytest.fixture(autouse=True)
def _clean_proxy(sss_leg):
    """No test inherits the previous one's faults."""
    sss_leg.fp.clear()
    yield
    sss_leg.fp.clear()


# --------------------------------------------------------------------------- #
# Success.                                                                     #
# --------------------------------------------------------------------------- #
def test_clean_sss_transfer_is_byte_exact(sss_leg):
    rc, exact, got = sss_leg.download()
    assert rc == 0 and exact, f"rc={rc} bytes={got}"


def test_sss_login_is_replayed_after_a_mid_transfer_sever(sss_leg):
    """The cut lands deep in the payload, so the client reconnects — which means
    it re-ran the SSS login on the new connection. A short output file would be
    the failure; the assertion is byte-exactness, not merely rc 0."""
    sss_leg.fp.set_truncate(MID_CUT, "down")
    rc, exact, got = sss_leg.download()
    assert rc == 0 and exact, f"rc={rc} bytes={got}"


# --------------------------------------------------------------------------- #
# Error — a login damaged in flight fails closed.                              #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("direction", ["down", "up"])
def test_sss_handshake_cut_fails_closed(sss_leg, direction):
    """Severed in either direction while the login is still in flight: the
    transfer must fail and leave nothing behind, on both halves of the
    exchange."""
    sss_leg.fp.set_truncate(HANDSHAKE_CUT, direction)
    rc, exact, got = sss_leg.download()
    assert rc != 0 and not exact and got == 0, f"rc={rc} bytes={got}"


# --------------------------------------------------------------------------- #
# Security — a bad credential never yields data, by any route.                 #
# --------------------------------------------------------------------------- #
def test_a_credential_corrupted_in_flight_is_refused(sss_leg):
    """The core property: the server evaluates the mangled shared secret and
    refuses it. Nothing is served, and the client's fallback to another protocol
    finds none — so the session ends with no data by either path.

    Observed at a lower rate, where the credential is damaged but still parses,
    the refusal is explicit: `SSS auth failed (NotAuthorized)`. The secret is
    checked, not merely read."""
    sss_leg.fp.set_corrupt(CORRUPT_PCT, "up")
    rc, exact, got = sss_leg.download()
    assert rc != 0 and not exact and got == 0, f"rc={rc} bytes={got}"


def test_a_server_challenge_corrupted_in_flight_is_refused(sss_leg):
    """The mirror direction — a mangled server challenge must not be accepted
    into a usable session either."""
    sss_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = sss_leg.download()
    assert rc != 0 and not exact and got == 0, f"rc={rc} bytes={got}"


def test_a_client_with_no_keytab_is_refused(sss_leg):
    """The control: with the wire clean and only the credential missing, the
    object is still not served. Without this the corruption cases above could be
    passing because of a broken pipe rather than a refused login."""
    rc, exact, got = sss_leg.download(keytab=None)
    assert rc != 0 and not exact and got == 0, f"rc={rc} bytes={got}"

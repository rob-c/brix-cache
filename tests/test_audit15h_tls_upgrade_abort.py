"""
test_audit15h_tls_upgrade_abort.py — DEFECT CANDIDATE #23 (FIXED): abandoning
an armed in-protocol TLS upgrade crashed the worker.

Found while wiring the audit's §B1.8 row (krb5 x TLS, test_audit15h_krb5_tls.py)
— a probe that read the kXR_protocol reply off a `brix_tls on` listener and then
closed the socket left the next connection to that worker with ECONNRESET, and
the error log with `worker process NNNN exited on signal 11`.  It is not
krb5-specific and it is not `brix_tls_require`-specific: it reproduces on any
root:// listener with `brix_tls on`, including an anonymous one.

THE SEQUENCE, IN FULL.  Three frames, no credential, no login:

    1. the 20-byte client hello
    2. kXR_protocol with kXR_ableTLS set
    3. close the socket

The server answers (2) with kXR_haveTLS | kXR_gotoTLS — "send your ClientHello
now" — and arms the upgrade.  Step (3) means the ClientHello never comes.

THE PATH.  ``brix_recv_process_frame`` sees ``ctx->tls_pending`` and calls
``brix_start_tls`` (recv_process.c:286).  With the peer already gone,
``ngx_ssl_handshake`` returns NGX_ERROR, so ``brix_start_tls`` logs
"kXR_ableTLS ngx_ssl_handshake error" and finalizes the session
(tls.c:75-78) — which destroys the session pool and with it ``ctx``.  Control
returns to the recv loop, which dereferences the freed context on the very next
statement:

    step = brix_recv_process_frame(s, c, conf, ctx, rev, &rx_pending);
    brix_shutdown_hold_sync(c, ctx, ctx->state != XRD_ST_REQ_HEADER);   <-- UAF
    if (step == BRIX_RECV_STEP_RETURN) { return; }

``brix_recv_process_frame`` does return BRIX_RECV_STEP_RETURN here, so the guard
that would have prevented this is present and correct — it is simply one line
too late.  Under gdb (single-process nginx, no krb5, `brix_auth none`) the
faulting frame is exactly ``ngx_stream_brix_recv (recv.c:262)``, first attempt,
every time.

WHY IT MATTERS.  The trigger is three frames from an unauthenticated peer, on a
listener that may be configured to serve nobody without a proxy — the
AUTHED_PORT plane here is `brix_auth gsi` and dies just the same.  A dead worker
takes every other connection it was serving with it, so this is a remote
pre-auth denial of service against every session sharing that worker, not just
against the connection that sent it.

Under a daemonized multi-worker nginx the crash is racy rather than certain (the
close has to land before the handshake is attempted; measured ~5 in 6), so the
pin below retries and stops at the first observed death.

STATUS: FIXED, AND THIS FILE IS NOW THE REGRESSION GUARD.  The one-line
reordering the analysis above prescribed is in the tree — ``recv.c:261-265``
returns on ``BRIX_RECV_STEP_RETURN`` BEFORE touching ``ctx`` again:

    step = brix_recv_process_frame(s, c, conf, ctx, rev, &rx_pending);
    if (step == BRIX_RECV_STEP_RETURN) {
        return;
    }
    brix_shutdown_hold_sync(c, ctx, ctx->state != XRD_ST_REQ_HEADER);

so the freed context is never dereferenced and every assertion below is the
post-fix shape (`deaths == 0`, the victim session intact).  The narrative above
is kept in full because it is the reproduction: if any of these go red, the UAF
is back and the sequence that finds it is written out frame by frame.

Cases:
  * success       — a client that follows through with its ClientHello upgrades,
                    logs in and reads, and the worker is untouched
  * regression    — the same client that walks away instead leaves the worker
                    alive: the abandoned upgrade finalizes only its own session
  * control       — the identical byte sequence against a plane with no TLS
                    configured is harmless, so the opcode is not the cause
  * sec-negative  — the same three frames on a `brix_auth gsi` listener, sent
                    with no credential whatsoever, still cost nothing: the
                    pre-auth reachability that made this a DoS is closed
  * sec-negative  — an unrelated, healthy, authenticated-transport session on
                    the same worker keeps serving across the abandonment
  * recovery      — the listener is still answering afterwards, which is what
                    tells a red run apart from a hung one
"""

import os
import shutil
import socket
import ssl
import struct
import subprocess
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN
from test_min_sec_level import _send_initial
from _test_audit15g_helpers import wait_until
from _test_phase25_ratelimit_helpers import _xrd_recv_status, _xrd_stat

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-tlsabort")]

NAME = "lc-audit15h-tlsabort"
CONNECT_HOST = "localhost"  # net-literal-allow: TLS certificate test identity

READ_FILE = "/hello.txt"
READ_BODY = b"tls upgrade abort\n"

KXR_OK = 0
kXR_haveTLS = 0x80000000
kXR_gotoTLS = 0x40000000

# How many times to arm-and-abandon before giving up on seeing the crash.  The
# race is won roughly five times in six, so twelve attempts miss by chance about
# once in three hundred million; the loop stops at the first death.
ATTEMPTS = 12


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    assert shutil.which("openssl"), "openssl is required to build the TLS plane"
    base = tmp_path_factory.mktemp("a15htlsabort")
    ca_key, ca_pem = str(base / "ca.key"), str(base / "ca.pem")
    key, csr, cert = (str(base / "hostkey.pem"), str(base / "host.csr"),
                      str(base / "hostcert.pem"))

    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True,
                       timeout=60)

    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/O=brix-test/CN=audit15h tlsabort CA",
            "-keyout", ca_key, "-out", ca_pem)
    openssl("req", "-nodes", "-newkey", "rsa:2048",
            "-subj", f"/O=brix-test/CN={CONNECT_HOST}",
            "-keyout", key, "-out", csr)
    ext = base / "host.ext"
    ext.write_text(f"subjectAltName=DNS:{CONNECT_HOST},IP:127.0.0.1\n"  # net-literal-allow: TLS SAN test identity
                   "extendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key,
            "-CAcreateserial", "-days", "2", "-out", cert,
            "-extfile", str(ext))
    os.chmod(key, 0o600)
    return {"ca": ca_pem, "cert": cert, "key": key}


@pytest.fixture
def abort(lifecycle, tmp_path, pki):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    data.mkdir()
    (data / os.path.basename(READ_FILE)).write_bytes(READ_BODY)

    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15h_tlsabort.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CERT": pki["cert"], "KEY": pki["key"],
                         "CA": pki["ca"]},
        reason="audit-15h abandoned TLS upgrade (defect #23)"))


# --------------------------------------------------------------------------- #
# wire
# --------------------------------------------------------------------------- #

def _connect(port):
    sock = socket.create_connection((CONNECT_HOST, port), timeout=10)
    sock.settimeout(10)
    _send_initial(sock)
    return sock


def _healthy_connect(port, timeout=15):
    """`_connect` plus the kXR_protocol exchange, retried across a respawn.

    Every test in this file runs after something that deliberately killed a
    worker, and the listen socket outlives the worker that was accepting on it:
    a connect in that window is accepted by the kernel and then reset.  That is
    the defect's own noise, not a second failure, so the tests that need a
    working session wait it out instead of reporting it."""
    deadline = time.monotonic() + timeout
    while True:
        sock = None
        try:
            sock = _connect(port)
            return sock, _protocol_flags(sock)
        except OSError:
            if sock is not None:
                sock.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def _protocol_flags(sock):
    """kXR_protocol advertising kXR_ableTLS; return the reply's flags word."""
    sock.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006,
                             0x00000520, 0x02, 0x03, 0))
    status, body = _xrd_recv_status(sock)
    assert status == KXR_OK, (status, body)
    return struct.unpack(">I", body[4:8])[0]


def _upgrade(raw):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=CONNECT_HOST)


def _login(sock):
    sock.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                             b"pytest\x00\x00", 0, 0, 5, 0, 0))
    return _xrd_recv_status(sock)


def _arm_and_abandon(port):
    """The trigger: hello, ableTLS kXR_protocol, close before the ClientHello.

    Returns the advertised flags, or None when the connection could not be
    established at all — which is itself a symptom, not an error: a worker
    killed by an earlier round leaves the *next* connect to be reset while the
    master is still respawning."""
    try:
        sock = _connect(port)
    except OSError:
        return None
    try:
        return _protocol_flags(sock)
    except OSError:
        return None
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# worker bookkeeping
# --------------------------------------------------------------------------- #

def _workers(endpoint):
    """The master's live children, by ppid.  The template pins
    worker_processes to 1, so any change to this set is a death."""
    try:
        with open(endpoint.pidfile) as handle:
            master = int(handle.read().strip())
    except (FileNotFoundError, ValueError):
        # nginx briefly rewrites/removes the pidfile while a daemonized
        # lifecycle instance is settling.  The caller treats an empty set as
        # "not observable yet" and retries; it is not a worker death.
        return set()
    found = set()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as handle:
                stat = handle.read()
        except OSError:
            continue                      # exited between listdir and open
        # comm can contain spaces and parens; the fields start after the last ')'
        if int(stat[stat.rindex(")") + 2:].split()[1]) == master:
            found.add(int(entry))
    return found


def _count_deaths(endpoint, port, attempts=ATTEMPTS):
    """Arm-and-abandon until the worker set changes; return how many died.

    The worker set is re-read at the top of every round rather than carried
    across, so a respawn this loop already counted cannot be counted twice, and
    the closure below always compares against the pids from *this* round."""
    deaths = 0
    for _ in range(attempts):
        alive = _workers(endpoint)
        if not alive:
            # Under the complete fleet the master can be CPU-starved while
            # respawning after the preceding deliberate-abort test.  The
            # listener may already accept connections before its child is
            # visible in /proc, so give the worker a bounded readiness window
            # instead of turning scheduler pressure into a false failure.
            wait_until(lambda: _workers(endpoint) or None,
                       timeout=20.0, tick=0.1, what="the initial worker")
            alive = _workers(endpoint)
        _arm_and_abandon(port)
        try:
            wait_until(lambda: (_workers(endpoint) - alive) or None,
                       timeout=2.0, tick=0.1, what="a worker respawn")
            deaths += 1
            break
        except AssertionError:
            pass                          # survived this round; try again
    return deaths


# --------------------------------------------------------------------------- #
# success — the same plane, the same first two frames, followed through
# --------------------------------------------------------------------------- #

def test_the_upgrade_completes_when_the_client_follows_through(abort):
    """The control that makes the pin below about abandonment and nothing else.

    Identical listener, identical hello and kXR_protocol; the only difference is
    that this client sends its ClientHello.  It upgrades, logs in, reads the
    file, and the worker that served it is the same worker afterwards."""
    raw, flags = _healthy_connect(abort.port)
    before = _workers(abort)
    assert len(before) == 1, f"the template promises one worker: {before}"

    try:
        assert flags & kXR_haveTLS and flags & kXR_gotoTLS, \
            f"the plane did not arm an upgrade at all: {flags:#x}"
        sock = _upgrade(raw)
        status, body = _login(sock)
        assert status == KXR_OK, (status, body)
        status, body = _xrd_stat(sock, READ_FILE)
        assert status == KXR_OK, ("a completed upgrade could not stat",
                                  status, body)
    finally:
        raw.close()

    assert _workers(abort) == before, \
        "a well-behaved TLS client killed the worker"


# --------------------------------------------------------------------------- #
# regression guard — abandoning an upgrade must not kill the worker
# --------------------------------------------------------------------------- #

def test_abandoning_an_armed_upgrade_keeps_the_worker_alive(abort):
    """Abandoning an armed TLS upgrade must finalize only that session.

    Three frames from an unauthenticated peer, the last of which is a close,
    and the worker dereferences a session context that ``brix_start_tls``
    already handed to ``ngx_stream_finalize_session``.

    The recv loop must honor the return from the TLS failure path before
    touching the session context again.
    """
    deaths = _count_deaths(abort, abort.port)
    assert deaths == 0, f"abandoned TLS upgrade killed {deaths} worker(s)"


def test_a_plane_without_tls_is_untouched_by_the_same_bytes(abort):
    """The attribution control.  Byte for byte the same client behaviour
    against a listener with no `brix_tls` block: the kXR_protocol reply arms
    nothing, so there is no half-built upgrade to abandon and no session to
    finalize out from under the recv loop."""
    clear = abort.extra_ports["CLEAR_PORT"]

    sock, flags = _healthy_connect(clear)
    sock.close()
    assert not (flags & kXR_gotoTLS), \
        f"the cleartext plane armed an upgrade: {flags:#x}"

    deaths = _count_deaths(abort, clear)
    assert deaths == 0, \
        "a plane with no TLS configured died to the abandoned-upgrade sequence"


# --------------------------------------------------------------------------- #
# security-negative
# --------------------------------------------------------------------------- #

def test_the_crash_lands_before_any_authentication(abort):
    """The severity argument.  AUTHED_PORT is `brix_auth gsi`: without an x509
    proxy nobody gets past kXR_auth, and this client never even sends
    kXR_login.  A peer that the listener would refuse to serve can still take
    its worker down, so no authentication policy limits the exposure."""
    deaths = _count_deaths(abort, abort.extra_ports["AUTHED_PORT"])
    assert deaths == 0, f"unauthenticated abandoned upgrade killed {deaths} worker(s)"


def test_an_unrelated_session_on_the_worker_survives(abort):
    """An unrelated healthy session must survive the abandoned upgrade.

    The victim below is a separate connection that has completed the TLS
    upgrade and logged in, and is doing nothing wrong.  The one worker serves
    everything, so this also guards against collateral session loss."""
    raw, _ = _healthy_connect(abort.port)
    try:
        victim = _upgrade(raw)
        assert _login(victim)[0] == KXR_OK
        assert _xrd_stat(victim, READ_FILE)[0] == KXR_OK, \
            "the victim session was not healthy to begin with"

        deaths = _count_deaths(abort, abort.port)
        assert deaths == 0, f"abandoned upgrade killed {deaths} worker(s)"
        assert _xrd_stat(victim, READ_FILE)[0] == KXR_OK, \
            "the healthy session was disrupted by the abandoned upgrade"
    finally:
        raw.close()


# --------------------------------------------------------------------------- #
# recovery — green whichever way the defect goes
# --------------------------------------------------------------------------- #

def test_the_listener_remains_available_after_abandonment(abort):
    """The listener remains available after an abandoned upgrade."""
    deaths = _count_deaths(abort, abort.port)
    assert deaths == 0, f"abandoned upgrade killed {deaths} worker(s)"

    def serves():
        sock = None
        try:
            sock = _connect(abort.port)
            armed = bool(_protocol_flags(sock) & kXR_haveTLS)
            _upgrade(sock).close()        # never leave another armed upgrade
            return armed
        except OSError:
            return False
        finally:
            if sock is not None:
                sock.close()

    assert wait_until(serves, timeout=15, tick=0.25,
                      what="the listener to serve again"), \
        "the daemon stopped serving after the abandoned upgrade"

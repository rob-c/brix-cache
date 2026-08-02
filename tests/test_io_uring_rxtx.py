"""tests/test_io_uring_rxtx.py — phase-44 P44-C client cleartext RECV/SEND tier.

Subject: the native client's io_uring cleartext socket engine
(``client/lib/core/aio/aio_engine.c`` + ``aio_io.c``, §13.4 sub-option ii-b) —
for a non-TLS connection (``ac->ssl == NULL``) the loop drives reads with a
multishot ``IORING_OP_RECV`` over a provided-buffer ring (``BGID_RX``) and
writes with a staged one-shot ``IORING_OP_SEND``, so a cleartext link does true
zero-readiness-syscall I/O.  Selected by ``XRDC_IO_URING_LOOP=rxtx`` (the ii-a
``on``/``1`` value stays POLL_ADD-only; ``epoll`` — the default — keeps the
readiness loop).

The engine is a client-side construct, so the subject here is the C harness
``client/bin/aio_smoke`` (async demux + 256-ping flood + read fanout + 400
concurrent MT calls, all checked byte-exact) driven against a plain anon
root:// data plane.  ``tests/configs/nginx_lc_uring_rxtx.conf`` exposes two
listeners over one data dir — a cleartext ``root://`` port and a TLS
``roots://`` port — from the ``lc-uring-rxtx`` ledger entry
(tests/fleet_lifecycle_ports.py).  The server carries no io_uring itself.

Coverage (success / error / security-negative):

  * success — under ``rxtx`` the cleartext run passes byte-exact AND the ring is
    genuinely engaged: ``strace`` shows ``io_uring_enter`` with **no**
    ``epoll_wait`` (a silent auto-fallback to epoll could otherwise pass the
    byte checks while never exercising the new path).
  * security-negative — a TLS (``roots://``) connection under ``rxtx`` still
    passes byte-exact: ``ac->ssl != NULL`` forces the ``SSL_*`` path, so the raw
    ``RECV``/``SEND`` ops never touch the encrypted socket.  Were the guard
    wrong, raw ``RECV`` would read ciphertext and corrupt the stream (the run
    would fail or hang) — passing proves the encrypted byte stream is never fed
    to a raw socket read.
  * error / fail-safe — an unknown ``XRDC_IO_URING_LOOP`` value must NOT engage
    the ring (``strace`` shows ``epoll_wait`` and **no** ``io_uring_enter``) yet
    still transfer byte-exact: a malformed/hostile engine selector can never
    silently break I/O or mis-select an unintended transport; it degrades to the
    epoll default.

Run:
    PYTHONPATH=tests pytest tests/test_io_uring_rxtx.py -v
"""

import os
import shutil
import subprocess

import pytest

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, SERVER_CERT, SERVER_KEY, CA_CERT, CA_DIR

# One C driver on one fixed exclusive port; serialise the whole file onto it so
# the fixed listen never has two concurrent drivers (mirrors test_io_uring_runtime).
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-uring-rxtx"),
              pytest.mark.timeout(180)]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
SMOKE = os.path.join(CLIENT_DIR, "bin", "aio_smoke")

# io_uring syscalls whose presence/absence proves which engine actually ran.
_TRACE_SYSCALLS = "io_uring_enter,io_uring_setup,epoll_wait"


# --------------------------------------------------------------------------- #
# Harness                                                                      #
# --------------------------------------------------------------------------- #

def _ensure_smoke():
    """Build aio_smoke on demand; skip (never fail) if the toolchain is absent."""
    if os.path.exists(SMOKE):
        return
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler / aio_smoke not built")
    subprocess.run(["make", "-C", CLIENT_DIR, "aio-smoke"],
                   capture_output=True, text=True, timeout=300)
    if not os.path.exists(SMOKE):
        pytest.skip("aio_smoke build failed (liburing headers?)")


def _start(lifecycle, tmp_path):
    """Boot the two-listener (cleartext + TLS) anon instance; return the endpoint.

    The host cert/key + trusted CA are the fleet PKI mints (settings); skip if a
    session has not provisioned them."""
    for pem in (SERVER_CERT, SERVER_KEY, CA_CERT):
        if not os.path.exists(pem):
            pytest.skip(f"fleet PKI not provisioned ({pem} missing)")

    data = tmp_path / "export"
    data.mkdir()
    # aio_smoke reads/writes random.bin; give it a non-trivial file to checksum.
    (data / "random.bin").write_bytes(os.urandom(200000))
    if os.geteuid() == 0:
        from cmdscripts import open_tree_for_worker
        open_tree_for_worker(tmp_path)

    return lifecycle.start(NginxInstanceSpec(
        name="lc-uring-rxtx",
        template="nginx_lc_uring_rxtx.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST,
                         "DATA_DIR": str(data),
                         "CERT": SERVER_CERT,
                         "KEY": SERVER_KEY,
                         "CA": CA_CERT},
        reason="phase-44 P44-C client rxtx subject"))


def _run_smoke(url, loop_value, tls=False, trace=None):
    """Run aio_smoke against `url` with XRDC_IO_URING_LOOP=`loop_value`.

    tls=True adds X509_CERT_DIR so a roots:// handshake validates the host cert.
    `trace` (a path) wraps the run in strace over the io_uring/epoll syscalls.
    Returns (passed, syscall_counts | None) where passed == ("M1 PASS" in out)."""
    env = dict(os.environ, XRDC_IO_URING_LOOP=loop_value)
    if tls:
        env["X509_CERT_DIR"] = CA_DIR

    argv = [SMOKE, url]
    counts = None
    if trace is not None and shutil.which("strace") is not None:
        argv = ["strace", "-f", "-e", f"trace={_TRACE_SYSCALLS}",
                "-o", trace] + argv

    proc = subprocess.run(argv, capture_output=True, text=True,
                          env=env, timeout=120)
    passed = "M1 PASS" in proc.stdout
    if not passed:
        # Surface the harness output so a failure is diagnosable.
        print("aio_smoke STDOUT:\n" + proc.stdout[-2000:])
        print("aio_smoke STDERR:\n" + proc.stderr[-2000:])

    if trace is not None and os.path.exists(trace):
        counts = {s: 0 for s in _TRACE_SYSCALLS.split(",")}
        with open(trace) as f:
            for line in f:
                for s in counts:
                    if s + "(" in line:
                        counts[s] += 1
    return passed, counts


# --------------------------------------------------------------------------- #
# P44-C — cleartext RECV/SEND multishot tier                                  #
# --------------------------------------------------------------------------- #

def test_rxtx_cleartext_byte_exact_ring_engaged(lifecycle, tmp_path):
    """Success: a cleartext run under rxtx is byte-exact AND the ring is truly
    engaged (io_uring_enter present, no epoll_wait) — a silent epoll fallback
    can never masquerade as a pass."""
    ep = _start(lifecycle, tmp_path)
    _ensure_smoke()
    trace = str(tmp_path / "rxtx.strace")
    passed, counts = _run_smoke(f"root://{HOST}:{ep.port}", "rxtx", trace=trace)
    assert passed, "aio_smoke did not report M1 PASS under rxtx (cleartext)"
    if counts is not None:                       # strace present
        assert counts["io_uring_enter"] > 0, \
            "rxtx did not engage the io_uring engine (no io_uring_enter)"
        assert counts["epoll_wait"] == 0, \
            "rxtx unexpectedly fell back to the epoll loop"


def test_rxtx_tls_falls_back_to_ssl(lifecycle, tmp_path):
    """Security-negative: a TLS (roots://) connection under rxtx still passes
    byte-exact — ac->ssl != NULL forces SSL_*, so raw RECV/SEND never consume the
    encrypted socket.  A wrong guard would raw-read ciphertext and corrupt the
    stream, failing/hanging this run."""
    ep = _start(lifecycle, tmp_path)
    _ensure_smoke()
    tls_port = ep.extra_ports["TLS_PORT"]
    passed, _ = _run_smoke(f"roots://{HOST}:{tls_port}", "rxtx", tls=True)
    assert passed, \
        "TLS run under rxtx failed — the rxtx path must decline ac->ssl != NULL"


def test_unknown_loop_value_fails_safe_to_epoll(lifecycle, tmp_path):
    """Error / fail-safe: an unknown XRDC_IO_URING_LOOP value must not engage the
    ring (epoll_wait present, no io_uring_enter) yet still transfer byte-exact —
    a malformed engine selector degrades to the epoll default, never a crash or a
    mis-selected transport."""
    ep = _start(lifecycle, tmp_path)
    _ensure_smoke()
    trace = str(tmp_path / "bogus.strace")
    passed, counts = _run_smoke(f"root://{HOST}:{ep.port}",
                                "definitely-not-a-mode", trace=trace)
    assert passed, "an unknown loop selector must still transfer byte-exact"
    if counts is not None:
        assert counts["epoll_wait"] > 0, \
            "the unknown selector did not fall back to the epoll loop"
        assert counts["io_uring_enter"] == 0, \
            "an unknown selector must never engage the io_uring engine"

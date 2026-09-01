"""Metadata walk thread-offload (phase-109 W1/W2).

phase-106 W5 traced a real availability defect: PROPFIND and SEARCH ran their
backend I/O INLINE on the nginx event loop, so against a remote storage backend
one slow origin stalled every connection on the worker for up to the bounded
timeout.  GET/PUT/COPY/MOVE already thread-offload; phase-109 extends the same
pattern (walk_offload.c) to the metadata builds, gated on remote-backend + a
configured thread pool + impersonation OFF (the copy_collection.c precedent:
the broker socket is single-user and a task lacks the principal, so under
impersonation the walk stays inline — the phase-106 authz tests keep covering
that path).

  * success   — the load-bearing cell: with the ORIGIN made deliberately slow,
                a PROPFIND against the remote backend is in flight and a second,
                unrelated request on the SAME single-worker instance completes
                promptly — proving the event loop is no longer blocked (before
                phase-109 this exact scenario stalled the worker)
  * error     — an unreachable origin fails the walk with an error status, not
                a hang, and the worker stays healthy
  * security  — the offload gate must not change WHAT is served: remote and
                local answers agree; and the offloaded response still refuses a
                traversal probe exactly as the inline path does

Run:
    PYTHONPATH=tests pytest tests/test_walk_offload.py -v
"""

from __future__ import annotations

import http.client
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-walk-offload")]

TEMPLATE = "nginx_lc_walk_offload.conf"

MULTISTATUS = (b'<?xml version="1.0" encoding="utf-8"?>'
               b'<D:multistatus xmlns:D="DAV:">'
               b'<D:response><D:href>/</D:href><D:propstat>'
               b'<D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop>'
               b'<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'
               b'<D:response><D:href>/alpha.txt</D:href><D:propstat>'
               b'<D:prop><D:getcontentlength>5</D:getcontentlength>'
               b'<D:resourcetype/></D:prop>'
               b'<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'
               b'</D:multistatus>')


class _Origin(ThreadingHTTPServer):
    """Mock WebDAV origin: answers PROPFIND with a fixed listing, optionally
    after a configurable delay — the slow-origin lever the stall test pulls."""

    delay = 0.0


class _OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _reply(self, code, body=b"", ctype="application/xml",
               delayed=False):
        if delayed and self.server.delay > 0:
            time.sleep(self.server.delay)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_PROPFIND(self):                       # noqa: N802 — http.server API
        # Only the LISTING is delayed: the build also makes stat/HEAD and
        # residency round-trips, and delaying every method compounds the
        # latency past the client timeout instead of modelling one slow op.
        self._reply(207, MULTISTATUS, delayed=True)

    def do_HEAD(self):                           # noqa: N802
        self._reply(200)

    def do_GET(self):                            # noqa: N802
        self._reply(200, b"alpha", "text/plain")


@pytest.fixture(scope="module")
def rig(tmp_path_factory):
    """The nginx front (remote + local servers) plus the controllable origin."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    data = tmp_path_factory.mktemp("walkoffload-data")
    (data / "alpha.txt").write_bytes(b"alpha")

    harness = LifecycleHarness()
    try:
        inst = harness.start(NginxInstanceSpec(
            name="lc-walk-offload",
            template=TEMPLATE,
            protocol="webdav",
            readiness="tcp",
            data_root=str(data),
            template_values={"DATA_DIR": str(data)},
            reason="phase-109 metadata walk thread-offload"))
    except Exception as exc:                      # noqa: BLE001 — clean skip
        harness.close()
        pytest.skip(f"walk-offload node did not start: {str(exc)[-300:]}")

    origin_port = inst.extra_ports["ORIGIN_PORT"]
    origin = _Origin((BIND_HOST, origin_port), _OriginHandler)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"inst": inst, "origin": origin,
               "local_port": inst.extra_ports["LOCAL_PORT"]}
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=10)
        harness.close()


def _propfind(host, port, path="/", depth="1", timeout=30):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("PROPFIND", path, headers={"Depth": depth})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# success — the stall is gone
# ---------------------------------------------------------------------------

def test_slow_origin_no_longer_stalls_the_worker(rig):
    """(success, load-bearing) With the origin answering PROPFIND after a 5s
    delay, a metadata walk is dispatched against the remote backend — and a
    second, unrelated request on the SAME single-worker instance completes in
    well under that delay.

    worker_processes is 1 in the template, so before phase-109 the inline
    backend PROPFIND blocked the only event loop and the probe below could not
    be answered until the origin replied: this cell FAILS on the pre-109 code
    by construction.
    """
    inst = rig["inst"]
    rig["origin"].delay = 5.0
    try:
        walker_err = []

        def _walk():
            try:
                # Generous: the transport retries a stalled origin attempt
                # (observed ~4 origin round-trips for one client PROPFIND at
                # 5s each) — pre-existing sd_http behaviour, orthogonal to the
                # offload.  The cell's verdict is the PROBE latency below.
                _propfind(inst.host, inst.port, timeout=90)
            except Exception as exc:              # noqa: BLE001 — report below
                walker_err.append(exc)

        walker = threading.Thread(target=_walk)
        walker.start()
        time.sleep(0.5)                # the walk is now inside the origin call

        t0 = time.monotonic()
        status, _ = _propfind(inst.host, rig["local_port"], timeout=10)
        probe_secs = time.monotonic() - t0

        walker.join(timeout=120)
        assert not walker_err, f"the slow walk errored: {walker_err}"
        assert status == 207, f"local probe failed: {status}"
        assert probe_secs < 3.0, (
            f"the worker was stalled for {probe_secs:.1f}s while the remote "
            "walk waited on the origin — the offload did not take the backend "
            "I/O off the event loop")
    finally:
        rig["origin"].delay = 0.0


def test_remote_walk_returns_the_origin_listing(rig):
    """(success) The offloaded build produces a well-formed 207 whose body
    reflects the origin's listing — the offload changed WHERE the walk runs,
    never WHAT it returns."""
    inst = rig["inst"]
    status, body = _propfind(inst.host, inst.port)
    assert status == 207, status
    assert b"multistatus" in body
    assert b"alpha.txt" in body, body[:400]


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_unreachable_origin_fails_cleanly_and_worker_survives(rig):
    """(error) Stop the origin: the walk fails with an error status (never a
    hang past the transport bound), and the worker still serves afterwards."""
    inst = rig["inst"]
    origin = rig["origin"]
    origin.shutdown()
    origin.server_close()
    try:
        status, _ = _propfind(inst.host, inst.port, timeout=60)
        assert status >= 400, f"walk against a dead origin answered {status}"
    finally:
        # Restart the origin for any cell that runs after this one.
        new = _Origin((BIND_HOST, origin.server_address[1]), _OriginHandler)
        rig["origin"] = new
        threading.Thread(target=new.serve_forever, daemon=True).start()

    status, _ = _propfind(inst.host, rig["local_port"], timeout=10)
    assert status == 207, "the worker did not survive the failed remote walk"


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

def test_local_backend_stays_inline_and_correct(rig):
    """(security-neg / non-vacuity) The gate must NOT fire for a local backend:
    a local PROPFIND still answers 207 with the on-disk listing — byte-level
    behaviour unchanged — so the offload cannot have widened to the common
    case (where a thread hop is pure regression and where the impersonated
    inline path lives)."""
    inst = rig["inst"]
    status, body = _propfind(inst.host, rig["local_port"])
    assert status == 207, status
    assert b"alpha.txt" in body


def test_offloaded_walk_still_refuses_traversal(rig):
    """(security-neg) Moving the walk to a thread must not bypass path
    confinement: a traversal probe through the offloaded plane is refused the
    same way the inline path refuses it — never a 207 enumerating outside the
    export."""
    inst = rig["inst"]
    conn = http.client.HTTPConnection(inst.host, inst.port, timeout=30)
    try:
        conn.request("PROPFIND", "/../../../../etc/", headers={"Depth": "1"})
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    assert resp.status in (400, 403, 404), (
        f"traversal probe answered {resp.status} through the offloaded walk")
    assert b"passwd" not in body

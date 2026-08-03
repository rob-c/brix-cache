"""
tests/test_webdav_tpc_source_egress_guard.py

Online coverage for the WebDAV-plane TPC source-host egress allowlist guard
(brix_webdav_tpc_source_guard / brix_webdav_tpc_source_allow) — the HTTP-COPY
twin of the native stream guard covered in
test_tpc_source_egress_guard.py.

A native TPC pull and a WebDAV COPY pull are the same SSRF primitive: the
DESTINATION server dials the SOURCE authority named in the request. Both planes
therefore enforce the same NAMING allowlist ahead of any outbound leg, sharing
the pure verdict core brix_tpc_source_guard_check() so the two can never
disagree. On the WebDAV side the guard fires in
src/protocols/webdav/tpc.c: webdav_tpc_source_guard() — after the Source URL is
validated (https-only) but BEFORE credential delegation and the curl COPY — and
on a refusal returns 403 plus a fail2ban signal=tpc_egress guard-audit line.

Why this asserts on the audit LOG rather than the HTTP status: an allowlisted
host that the naming guard lets through can still be refused 403 further
downstream (the range/DNS SSRF check in the curl stage), so status alone does
not separate "refused by the naming guard" from "allowed, then failed later".
The guard-audit line (signal=tpc_egress, path="<host>") is the precise,
fail2ban-relevant signal that the naming guard — and only the naming guard —
fired.

The dedicated "webdav-tpc-source-guard" server (port 11219) is configured with:
    brix_webdav_tpc_source_guard on;
    brix_webdav_tpc_source_allow 10.255.255.1 .example.com;

Run:
    pytest tests/test_webdav_tpc_source_egress_guard.py -v
"""

import http.client
import os
import socket
import time

import pytest

from settings import (
    HOST,
    REGISTRY_ROOT,
    WEBDAV_TPC_SRC_GUARD_PORT,
)

pytestmark = pytest.mark.timeout(90)

_TIMEOUT = 20.0
_SIGNAL = "signal=tpc_egress"

_ERROR_LOG = os.path.join(
    REGISTRY_ROOT, "webdav-tpc-source-guard", "logs", "error.log"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _copy(source_url, dst_path="/tpc_guard_dst.dat"):
    """Issue a cleartext WebDAV COPY pull naming source_url; return the status.

    The COPY target (dst) is this same cleartext server; only the Source header
    carries the https URL whose authority the naming guard vets.
    """
    conn = http.client.HTTPConnection(HOST, WEBDAV_TPC_SRC_GUARD_PORT,
                                      timeout=_TIMEOUT)
    try:
        conn.request("COPY", dst_path, headers={
            "Source": source_url,
            "Credential": "none",
        })
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def _log_tail(offset):
    """Return the error-log bytes appended since byte position `offset`."""
    try:
        with open(_ERROR_LOG, "r", errors="replace") as fh:
            fh.seek(offset)
            return fh.read()
    except OSError:
        return ""


def _log_size():
    try:
        return os.path.getsize(_ERROR_LOG)
    except OSError:
        return 0


def _egress_line_for(delta, host):
    """True if the log delta holds a naming-guard refusal audit line for host."""
    for line in delta.splitlines():
        if _SIGNAL in line and ('path="%s"' % host) in line:
            return True
    return False


def _await_log_flush():
    # nginx buffers the worker error log briefly; give it a beat to land.
    time.sleep(0.3)


# ---------------------------------------------------------------------------
# Fixture: reachability probe
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def guard_on():
    try:
        with socket.create_connection(
            (HOST, WEBDAV_TPC_SRC_GUARD_PORT), timeout=5
        ):
            pass
    except OSError:
        pytest.skip(
            "WebDAV TPC source-guard server not reachable at port %d"
            % WEBDAV_TPC_SRC_GUARD_PORT
        )
    return {"port": WEBDAV_TPC_SRC_GUARD_PORT}


# ---------------------------------------------------------------------------
# Guard ON: allowlist = {10.255.255.1, .example.com}
# ---------------------------------------------------------------------------

class TestWebdavSourceGuardRefuse:
    """A COPY whose Source host is not allowlisted is refused before curl."""

    @pytest.mark.registry_server("webdav-tpc-source-guard")
    def test_nonallowlisted_rfc1918_refused(self, guard_on):
        # 192.168.1.1 is RFC-1918 — the range gate would ALLOW it, but the
        # naming guard refuses it because it is not on the allowlist.
        host = "192.168.1.1"
        off = _log_size()
        status = _copy("https://%s//src.dat" % host)
        _await_log_flush()
        assert status == 403, "expected 403, got %d" % status
        assert _egress_line_for(_log_tail(off), host), (
            "expected a signal=tpc_egress refusal line for %s" % host
        )

    @pytest.mark.registry_server("webdav-tpc-source-guard")
    def test_nonmatching_suffix_refused(self, guard_on):
        # host.example.org does not match the .example.com suffix rule.
        host = "host.example.org"
        off = _log_size()
        status = _copy("https://%s//src.dat" % host)
        _await_log_flush()
        assert status == 403, "expected 403, got %d" % status
        assert _egress_line_for(_log_tail(off), host), (
            "sibling TLD must be refused by the naming guard: %s" % host
        )

    @pytest.mark.registry_server("webdav-tpc-source-guard")
    def test_suffix_bare_apex_refused(self, guard_on):
        # A leading-'.' rule is a strict suffix: the bare apex "example.com"
        # must NOT satisfy ".example.com" (host must be strictly longer).
        host = "example.com"
        off = _log_size()
        status = _copy("https://%s//src.dat" % host)
        _await_log_flush()
        assert status == 403, "expected 403, got %d" % status
        assert _egress_line_for(_log_tail(off), host), (
            "bare apex must not match .suffix — expected refusal: %s" % host
        )


class TestWebdavSourceGuardAllow:
    """Allowlisted hosts pass the naming guard and fall through to curl."""

    @pytest.mark.registry_server("webdav-tpc-source-guard")
    def test_allowlisted_suffix_falls_through(self, guard_on):
        # host.example.com matches the .example.com suffix rule; the naming
        # guard permits it and it fails later (DNS/connect), never emitting a
        # signal=tpc_egress line for this host.
        host = "host.example.com"
        off = _log_size()
        _copy("https://%s//src.dat" % host)
        _await_log_flush()
        assert not _egress_line_for(_log_tail(off), host), (
            "suffix-matched host must pass the naming guard: %s" % host
        )

    @pytest.mark.registry_server("webdav-tpc-source-guard")
    def test_allowlisted_ip_falls_through(self, guard_on):
        # 10.255.255.1 is on the allowlist; the naming guard permits it. It then
        # reaches the range gate (RFC-1918 allowed) and a curl connect that fails
        # (bounded by brix_webdav_tpc_timeout) — but never the naming refusal.
        host = "10.255.255.1"
        off = _log_size()
        _copy("https://%s//src.dat" % host)
        _await_log_flush()
        assert not _egress_line_for(_log_tail(off), host), (
            "allowlisted IP must pass the naming guard: %s" % host
        )

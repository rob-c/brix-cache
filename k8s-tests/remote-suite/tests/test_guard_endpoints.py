"""
Phase-65 bad-actor guard — coverage across every protocol front door.

One nginx instance exposes the module's own NATIVE endpoints and this suite
knocks on each with scanner traffic:

- webdav://  native WebDAV location with `brix_guard on` (junk bounced
  pre-handler, clean ops untouched, 404 -> notfound audit);
- s3://      native S3 location with the guard (junk bounced before the S3
  handler, unsigned-but-clean requests still reach S3 auth -> authfail audit);
- http://    a plain ops server (metrics) with a SERVER-level guard — scanner
  probes to any path bounce before nginx even 404s;
- root://    the native stream port: the protocol's own handshake validation
  is the door (guard classification for root:// is the transparent relay —
  tests/test_stream_guard.py); junk knocks must be dropped promptly and the
  server must keep serving legit clients;
- cms://     the cluster-management port: malformed frames close the
  connection and the listener survives.

Finally, every audit line the HTTP surfaces emitted is validated against the
shipped fail2ban filters — real emitted lines must be ban-able, not just the
hand-written samples.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_guard_endpoints.py -v -p no:xdist
"""

import os
import pathlib
import re
import socket
import subprocess
import time

import pytest

from guard_http_lib import NGINX_BIN, AuditLog, GuardServer, free_port
from settings import HOST, BIND_HOST

REPO = pathlib.Path(__file__).resolve().parents[1]
XRDFS = str(REPO / "client" / "bin" / "xrdfs")
FILTER_DIR = REPO / "deploy" / "fail2ban" / "filter.d"

pytestmark = pytest.mark.timeout(180)

SCANNER_PROBES = ["/wp-login.php", "/cgi-bin/probe.cgi", "/phpMyAdmin/index",
                  "/.git/config", "/x/.env"]


def _knock(port, payload, timeout=5.0):
    """Send raw bytes to a stream port; True if the peer closed within
    timeout (EOF / RST), False if it kept the connection open."""
    s = socket.create_connection((HOST, port), timeout=timeout)
    try:
        s.sendall(payload)
        s.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if s.recv(4096) == b"":
                    return True                    # clean EOF
            except (ConnectionResetError, BrokenPipeError):
                return True                        # RST also = door shut
            except socket.timeout:
                return False
        return False
    finally:
        s.close()


def _port_alive(port):
    """The listener still accepts a fresh TCP connection."""
    try:
        socket.create_connection((HOST, port), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("guardendp")
    (root / "logs").mkdir()
    dav_root = root / "dav_export"
    s3_root = root / "s3_export"
    xrd_root = root / "xrd_export"
    for d in (dav_root, s3_root, xrd_root):
        d.mkdir()
    (dav_root / "hello.txt").write_bytes(b"dav-hello\n")
    (s3_root / "bucket").mkdir()
    (s3_root / "bucket" / "obj.bin").write_bytes(b"s3-object\n")
    (xrd_root / "f.bin").write_bytes(os.urandom(4096))

    ports = {name: free_port() for name in ("dav", "s3", "ops", "xrd", "cms")}
    audits = {name: root / f"{name}-audit.log" for name in ("dav", "s3", "ops")}

    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
error_log {root}/logs/error.log info;
pid {root}/nginx.pid;
events {{ worker_connections 128; }}
http {{
    access_log off;
    client_body_temp_path {root}/tmp;
    proxy_temp_path {root}/tmp;
    fastcgi_temp_path {root}/tmp;
    uwsgi_temp_path {root}/tmp;
    scgi_temp_path {root}/tmp;
    server {{
        listen {BIND_HOST}:{ports['dav']};
        location / {{
            brix_guard on;
            brix_guard_profile xrdhttp;
            brix_guard_audit_log {audits['dav']};
            brix_webdav on;
            brix_storage_backend posix:{dav_root};
            brix_webdav_auth none;
            brix_allow_write on;
        }}
    }}
    server {{
        listen {BIND_HOST}:{ports['s3']};
        location / {{
            brix_guard on;
            brix_guard_profile xrdhttp;
            brix_guard_audit_log {audits['s3']};
            brix_s3 on;
            brix_storage_backend posix:{s3_root};
            brix_s3_access_key GUARDTESTKEY;
            brix_s3_secret_key guard-test-secret;
        }}
    }}
    server {{
        listen {BIND_HOST}:{ports['ops']};
        brix_guard on;
        brix_guard_audit_log {audits['ops']};
        location = /metrics {{ brix_metrics on; }}
    }}
}}
stream {{
    server {{
        listen {BIND_HOST}:{ports['xrd']};
        brix_root on;
        brix_export {xrd_root};
        brix_auth none;
    }}
    server {{
        listen {BIND_HOST}:{ports['cms']};
        brix_cms_server on;
    }}
}}
""")
    rc = subprocess.run([NGINX_BIN, "-t", "-p", str(root), "-c", str(conf)],
                        capture_output=True, text=True)
    assert rc.returncode == 0, f"nginx -t failed: {rc.stderr}"
    rc = subprocess.run([NGINX_BIN, "-p", str(root), "-c", str(conf)],
                        capture_output=True, text=True)
    assert rc.returncode == 0, f"nginx start failed: {rc.stderr}"
    deadline = time.time() + 10
    while time.time() < deadline and not all(
            _port_alive(p) for p in ports.values()):
        time.sleep(0.1)

    yield {
        "dav": GuardServer(HOST, ports["dav"]),
        "s3": GuardServer(HOST, ports["s3"]),
        "ops": GuardServer(HOST, ports["ops"]),
        "xrd_port": ports["xrd"],
        "cms_port": ports["cms"],
        "audits": {k: AuditLog(str(v)) for k, v in audits.items()},
        "dav_root": dav_root,
    }
    subprocess.run([NGINX_BIN, "-p", str(root), "-c", str(conf), "-s", "stop"],
                   capture_output=True)


class TestWebdavEndpointGuard:
    """Guard composed with the module's own WebDAV handler."""

    def test_scanner_put_bounced_before_handler(self, fleet):
        """A junk-path PUT is bounced pre-handler: 444 and no file created."""
        r = fleet["dav"].request("PUT", "/wp-config-backup.php",
                                 body=b"<?php evil();")
        assert r.status == 444, f"expected bounce, got {r.status}"
        assert not (fleet["dav_root"] / "wp-config-backup.php").exists(), \
            "junk PUT must never reach the WebDAV handler"
        assert fleet["audits"]["dav"].wait_for_count(1), "no audit line"
        assert fleet["audits"]["dav"].last_line_has(signal="signature",
                                                    proto="xrdhttp")

    def test_clean_webdav_roundtrip_unaffected(self, fleet):
        """A clean PUT + GET round-trip works and is not flagged."""
        baseline = fleet["audits"]["dav"].line_count()
        put = fleet["dav"].request("PUT", "/data.bin", body=b"payload-1234")
        assert put.status in (200, 201, 204), f"PUT failed: {put.status}"
        get = fleet["dav"].get("/data.bin")
        assert get.status == 200 and get.body == b"payload-1234"
        time.sleep(0.3)
        assert fleet["audits"]["dav"].line_count() == baseline, \
            "clean WebDAV traffic was flagged"

    def test_webdav_404_logged_notfound(self, fleet):
        """The native handler's 404 feeds the LOG-phase notfound signal."""
        baseline = fleet["audits"]["dav"].line_count()
        r = fleet["dav"].get("/no-such-file.bin")
        assert r.status == 404
        assert fleet["audits"]["dav"].wait_for_count(baseline + 1)
        assert fleet["audits"]["dav"].last_line_has(signal="notfound",
                                                    status="404")


class TestS3EndpointGuard:
    """Guard composed with the module's own S3 handler."""

    @pytest.mark.parametrize("probe", ["/x/.env", "/bucket/shell.php"])
    def test_scanner_probe_bounced_before_handler(self, fleet, probe):
        """Junk paths never reach S3 dispatch: 444 + signature audit."""
        baseline = fleet["audits"]["s3"].line_count()
        r = fleet["s3"].get(probe)
        assert r.status == 444, f"{probe}: expected bounce, got {r.status}"
        assert fleet["audits"]["s3"].wait_for_count(baseline + 1)
        assert fleet["audits"]["s3"].last_line_has(signal="signature")

    def test_unsigned_request_reaches_s3_auth(self, fleet):
        """A clean-path unsigned request still reaches S3's own SigV4 gate
        (guard passes it) and the auth failure feeds the authfail signal.
        This is the S3 credential-stuffing knock: no Authorization header."""
        baseline = fleet["audits"]["s3"].line_count()
        r = fleet["s3"].get("/bucket/obj.bin")
        assert r.status in (401, 403), \
            f"S3 auth should reject unsigned, got {r.status}"
        # The whole point: the SigV4 rejection must reach the LOG-phase guard.
        # Regression guard for the double-dispatch bug where the S3 handler
        # continued past the auth error into GetObject, overwriting the sent
        # 403 with status 200 and hiding the auth failure.
        assert fleet["audits"]["s3"].wait_for_count(baseline + 1), \
            "S3 auth failure did not reach the guard (double-dispatch bug?)"
        assert fleet["audits"]["s3"].last_line_has(signal="authfail",
                                                   status="403")
        # And the 403 body must not have leaked the object.
        assert b"s3-object" not in r.body, "object content leaked on auth fail"

    def test_malformed_auth_header_logged_authfail(self, fleet):
        """A garbage Authorization header (cred-stuffing with junk creds) is
        rejected and audited, not silently swallowed."""
        baseline = fleet["audits"]["s3"].line_count()
        r = fleet["s3"].request(
            "GET", "/bucket/obj.bin",
            headers={"Authorization": "AWS4-HMAC-SHA256 not-a-real-sig"})
        assert r.status in (401, 403), f"expected reject, got {r.status}"
        assert fleet["audits"]["s3"].wait_for_count(baseline + 1)
        assert fleet["audits"]["s3"].last_line_has(signal="authfail")

    def test_repeated_stuffing_yields_bannable_streak(self, fleet):
        """A burst of unsigned knocks from one IP yields one audit line each —
        the streak fail2ban's authfail jail bans on (5 in 120s)."""
        baseline = fleet["audits"]["s3"].line_count()
        for _ in range(5):
            fleet["s3"].get("/bucket/obj.bin")
        assert fleet["audits"]["s3"].wait_for_count(baseline + 5), \
            "cred-stuffing burst under-counted — jail threshold would miss it"
        recent = fleet["audits"]["s3"].lines()[-5:]
        assert all("signal=authfail" in ln for ln in recent)


class TestOpsServerGuard:
    """Server-level guard on a plain ops/metrics vhost."""

    @pytest.mark.parametrize("probe", SCANNER_PROBES)
    def test_scanner_probe_bounced(self, fleet, probe):
        """Every scanner probe bounces with a signature audit line."""
        baseline = fleet["audits"]["ops"].line_count()
        r = fleet["ops"].get(probe)
        assert r.status == 444, f"{probe}: expected bounce, got {r.status}"
        assert fleet["audits"]["ops"].wait_for_count(baseline + 1)
        assert fleet["audits"]["ops"].last_line_has(signal="signature")

    def test_metrics_still_served(self, fleet):
        """The guarded vhost still serves its real endpoint cleanly."""
        baseline = fleet["audits"]["ops"].line_count()
        r = fleet["ops"].get("/metrics")
        assert r.status == 200, f"/metrics failed: {r.status}"
        assert b"brix" in r.body
        time.sleep(0.3)
        assert fleet["audits"]["ops"].line_count() == baseline


class TestRootNativeDoor:
    """The native root:// port. The terminating server's own handshake
    validation is the door here — guard classification for root:// rides
    the transparent relay (tests/test_stream_guard.py)."""

    def test_http_knock_dropped(self, fleet):
        """An HTTP request on the root:// port is closed, not serviced."""
        assert _knock(fleet["xrd_port"],
                      b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n"), \
            "root:// port must drop an HTTP knock promptly"

    def test_garbage_knock_dropped(self, fleet):
        """70KB of non-protocol garbage is closed, never buffered forever."""
        assert _knock(fleet["xrd_port"], b"\xde\xad\xbe\xef" * (70 * 256)), \
            "root:// port must drop protocol garbage promptly"

    def test_door_survives_and_serves(self, fleet):
        """After the knocks, a legitimate client still gets served."""
        env = dict(os.environ, XRDC_MAX_STALL_MS="0")
        result = subprocess.run(
            [XRDFS, f"root://{BIND_HOST}:{fleet['xrd_port']}",
             "stat", "/f.bin"],
            capture_output=True, text=True, timeout=30, env=env)
        assert result.returncode == 0, \
            f"legit client failed after knocks: {result.stderr}"


class TestCmsDoor:
    """The cms:// cluster-management port."""

    def test_garbage_knock_dropped(self, fleet):
        """A malformed CMS frame closes the connection."""
        assert _knock(fleet["cms_port"], b"\xde\xad\xbe\xef" * (70 * 256)), \
            "cms:// port must drop malformed frames promptly"

    def test_listener_survives(self, fleet):
        """The CMS listener keeps accepting after garbage."""
        assert _port_alive(fleet["cms_port"]), "cms listener died"


class TestAuditLinesAreBannable:
    """Every audit line the HTTP surfaces actually emitted in this suite
    must match the shipped fail2ban filters and yield the client IP."""

    HOST_RE = r"(?P<host>[0-9a-fA-F.:]+)"

    def _failregex(self, signal):
        text = (FILTER_DIR / f"xrootd-guard-{signal}.conf").read_text()
        line = [ln for ln in text.splitlines()
                if ln.startswith("failregex")][0]
        return line.split("=", 1)[1].strip().replace("<HOST>", self.HOST_RE)

    def test_emitted_lines_match_filters(self, fleet):
        """Cross-check real emitted lines (not samples) against the filters."""
        lines = []
        for audit in fleet["audits"].values():
            lines.extend(audit.lines())
        assert lines, "suite should have produced audit lines by now"
        for line in lines:
            signal = re.search(r"signal=(\w+)", line).group(1)
            match = re.search(self._failregex(signal), line)
            assert match, f"filter {signal} missed emitted line: {line}"
            assert match.group("host"), f"no IP extracted from: {line}"
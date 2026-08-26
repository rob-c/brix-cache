"""phase-105 W1 — brix_rate_limit is effective on S3 (and stays scoped).

The rate-limit/zones family used to be registered by the webdav module, so
`brix_rate_limit` in (or above) an S3 location parsed cleanly and enforced
NOTHING — the phase-101 W1 silent-no-op class on a DoS-protection knob.
Phase-105 W1 moved the family to the common module + shared preamble and
added the S3 gate (s3_rate_limit in s3/handler.c, byte-parallel to webdav's
access_rate_limit).

Three pins (the 3-class rule):
  success      — one http{}-scope line sheds S3 AND webdav traffic with 429;
  error        — bad grammar EMERG unchanged after the move (setter moved
                 verbatim; also covered by test_phase20_kv_shm parse tests);
  security-neg — a limiter configured ONLY in a webdav location never
                 throttles the adjacent s3 server (location scoping holds).
"""

import socket
import time

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import (
    PARSE_PLACEHOLDER_PORT,
    SHARED_PARSE_PLACEHOLDER_PORT,
    lifecycle_ports_for,
)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

HOST = "127.0.0.1"  # net-literal-allow: loopback literal is the subject under test

_RL_PORT, _RL_EXTRA = lifecycle_ports_for("lc-p105-rl-s3")
WEBDAV_PORT = _RL_PORT
S3_PORT = _RL_EXTRA["S3_PORT"]

_SIB_PORT, _SIB_EXTRA = lifecycle_ports_for("lc-p105-rl-sibling")
SIB_WEBDAV_PORT = _SIB_PORT
SIB_S3_PORT = _SIB_EXTRA["S3_PORT"]


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _http_get_status(port, path):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
            .encode()
        )
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    status_line = data.split(b"\r\n", 1)[0].decode(errors="replace")
    return int(status_line.split()[1])


@pytest.fixture
def shared_limit_server():
    harness = LifecycleHarness()
    try:
        harness.start(NginxInstanceSpec(
            name="lc-p105-rl-s3",
            template="nginx_p105_rl_s3.conf",
            protocol="http", readiness="tcp"))
        assert _wait_port(S3_PORT), "s3 listener did not come up"
        yield
    finally:
        harness.close()


@pytest.fixture
def sibling_limit_server():
    harness = LifecycleHarness()
    try:
        harness.start(NginxInstanceSpec(
            name="lc-p105-rl-sibling",
            template="nginx_p105_rl_sibling.conf",
            protocol="http", readiness="tcp"))
        assert _wait_port(SIB_S3_PORT), "s3 listener did not come up"
        yield
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# success — one http{}-scope line covers S3 and webdav                         #
# --------------------------------------------------------------------------- #

def test_http_scope_limit_sheds_s3_with_429(shared_limit_server):
    # burst=2: the first request must be admitted (any non-429 status — the
    # admitted unsigned S3 GET fails auth with its own code, which is fine:
    # the gate runs BEFORE the auth burden), the hammer must hit 429.
    statuses = [_http_get_status(S3_PORT, "/bucket/key") for _ in range(6)]
    assert statuses[0] != 429, f"first request should be admitted: {statuses}"
    assert 429 in statuses, f"expected a 429 on s3, got {statuses}"


def test_http_scope_limit_sheds_webdav_too(shared_limit_server):
    # Same zone, same budget — wait for the 1r/s bucket to refill after the
    # S3 hammer, then prove the SAME http{}-scope line throttles webdav.
    time.sleep(3)
    statuses = [_http_get_status(WEBDAV_PORT, "/nonexistent")
                for _ in range(6)]
    assert statuses[0] != 429, f"first request should be admitted: {statuses}"
    assert 429 in statuses, f"expected a 429 on webdav, got {statuses}"


# --------------------------------------------------------------------------- #
# security-neg — location scoping holds through the move                       #
# --------------------------------------------------------------------------- #

def test_webdav_location_limit_does_not_leak_to_s3(sibling_limit_server):
    # The s3 server has NO limiter: hammer it well past the webdav burst —
    # not one 429 may appear (a leak here would mean adopt-at-merge smeared a
    # location-scoped limiter across siblings).
    statuses = [_http_get_status(SIB_S3_PORT, "/bucket/key")
                for _ in range(8)]
    assert 429 not in statuses, f"limiter leaked into the s3 sibling: {statuses}"

    # And the limiter is live in this very instance: webdav sheds.
    statuses = [_http_get_status(SIB_WEBDAV_PORT, "/nonexistent")
                for _ in range(6)]
    assert 429 in statuses, f"webdav limiter inert: {statuses}"


# --------------------------------------------------------------------------- #
# parse pin — the http{}-scope spelling parses (was impossible pre-105: the    #
# directive existed at loc scope on webdav's table only). The grammar-error    #
# EMERGs are pinned by test_phase20_kv_shm's parse tests, which now exercise   #
# the moved setters.                                                           #
# --------------------------------------------------------------------------- #

def test_http_scope_template_parses(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "logs").mkdir()
    (tmp_path / "tmp").mkdir()
    r = nginx_t("nginx_p105_rl_s3.conf", tmp_path,
                PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                S3_PORT=PARSE_PLACEHOLDER_PORT,
                DATA_ROOT=str(tmp_path / "data"),
                LOG_DIR=str(tmp_path / "logs"),
                TMP_DIR=str(tmp_path / "tmp"))
    assert r.returncode == 0, (r.stdout or "") + (r.stderr or "")

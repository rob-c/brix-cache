"""
Admin-API per-IP rate limiting (phase-23 "Rate limiting" item, phase-88 §3.5).

The dashboard admin API carries a built-in per-source-IP throttle with separate
read (GET/HEAD) and write (POST/PUT/DELETE) leaky buckets in a dedicated SHM
zone, generous by default (120 writes/min, 1200 reads/min) and tunable or
disableable via `brix_admin_rate_limit`.

Coverage (success + error + security-negative):
  1. Reads under sustained legitimate load pass untouched (default limits).
  2. A write flood hits 429 + Retry-After; the read bucket is independent, so
     querying keeps working while writes are throttled.
  3. Security-negative: an unauthenticated flood is answered 403 and consumes
     NO bucket capacity (the gate runs after auth), so it cannot lock out the
     real operator; `off` disables the throttle entirely; a garbage directive
     argument is rejected at config time.

Registry-backed: throwaway nginx instances via the `lifecycle` harness.
"""

import json
import os
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST, url_host

# The four live admin-API instances (lc-admin-rl-*) draw fixed ports from the
# fleet_lifecycle_ports ledger; xdist_group serialises the file so no fixed port
# ever has two concurrent drivers.
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-admin-rl")]

SECRET = "admin-ratelimit-secret-token-value"

# Invalid-host register body: rejected 400 by the whitelist AFTER the rate gate,
# so floods charge the bucket without churning the cluster registry SHM.
BAD_WRITE = json.dumps({"host": "bad;host", "port": 1094, "paths": "/store"})


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


class _AdminServer:
    """Handle for one admin-API instance: curl through the harness runner."""

    def __init__(self, harness, endpoint):
        self.harness = harness
        self.port = endpoint.port
        self.error_log = Path(endpoint.prefix) / "logs" / "error.log"

    @property
    def base(self):
        return f"http://{url_host(HOST)}:{self.port}/brix/api/v1/admin"

    def request(self, method, path, token=SECRET, data=None):
        """Returns (status:int, headers:str, body:str)."""
        args = ["curl", "-s", "-D", "-", "-X", method]
        if token is not None:
            args += ["-H", f"Authorization: Bearer {token}"]
        if data is not None:
            args += ["-H", "Content-Type: application/json", "--data", data]
        args += ["-w", "\n%{http_code}", f"{self.base}{path}"]
        rc = self.harness.run_cmd(args, timeout=10)
        assert rc.returncode == 0, rc.stderr
        rest, _, status = rc.stdout.rpartition("\n")
        headers, _, body = rest.partition("\r\n\r\n")
        return int(status), headers, body


def _start(lifecycle, tmp_path, name, rl_line):
    secret = tmp_path / "admin.secret"
    secret.write_text(SECRET + "\n")
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_admin_ratelimit.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST,
                         "SECRET_FILE": str(secret),
                         "RL_LINE": rl_line},
        reason="admin API per-IP rate-limit coverage",
    ))
    return _AdminServer(lifecycle, endpoint)


# --------------------------------------------------------------------------- #
# 1. Success: generous defaults never clip legitimate query load               #
# --------------------------------------------------------------------------- #

def test_reads_pass_under_extensive_querying(lifecycle, tmp_path):
    """40 rapid GETs against the default limits (1200 reads/min, burst 300)
    all succeed — extensive dashboard/monitoring polling keeps working."""
    srv = _start(lifecycle, tmp_path, "lc-admin-rl-defaults", "")
    for i in range(40):
        status, _, body = srv.request("GET", "/proxy/backends")
        assert status == 200, f"read #{i} throttled: {status} {body}"


# --------------------------------------------------------------------------- #
# 2. Error: a write flood is throttled; the read bucket stays independent      #
# --------------------------------------------------------------------------- #

def test_write_flood_throttled_and_reads_survive(lifecycle, tmp_path):
    srv = _start(lifecycle, tmp_path, "lc-admin-rl-tight",
                 "brix_admin_rate_limit 5 600;")

    statuses, retry_after = [], None
    for _ in range(30):
        status, headers, _ = srv.request("POST", "/cluster/servers",
                                         data=BAD_WRITE)
        statuses.append(status)
        if status == 429:
            for line in headers.splitlines():
                if line.lower().startswith("retry-after:"):
                    retry_after = line.split(":", 1)[1].strip()
            break

    # The burst floor (10 requests) passes first, then the bucket overflows.
    assert statuses[0] == 400, "first write must reach the validator"
    assert 429 in statuses, f"write flood never throttled: {statuses}"
    assert retry_after is not None and int(retry_after) >= 1, \
        "429 must carry Retry-After"
    assert set(statuses) <= {400, 429}, statuses

    # Separate read bucket: querying still works while writes are exhausted.
    status, _, body = srv.request("GET", "/proxy/backends")
    assert status == 200, f"read starved by write throttle: {status} {body}"

    # The throttle event is audit-logged.
    assert "result=throttled" in srv.error_log.read_text(
        encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# 3. Security-negative                                                          #
# --------------------------------------------------------------------------- #

def test_unauth_flood_denied_403_and_consumes_no_bucket(lifecycle, tmp_path):
    """The gate runs AFTER auth: 15 unauthenticated writes (over the 5/min
    bucket, were they counted) all get 403 — never 429 — and afterwards the
    authorized operator still has full write capacity."""
    srv = _start(lifecycle, tmp_path, "lc-admin-rl-unauth",
                 "brix_admin_rate_limit 5 600;")
    for _ in range(15):
        status, _, _ = srv.request("POST", "/cluster/servers",
                                   token=None, data=BAD_WRITE)
        assert status == 403, "unauthenticated flood must stay a plain 403"

    status, _, body = srv.request("POST", "/cluster/servers", data=BAD_WRITE)
    assert status == 400, \
        f"unauth flood consumed the operator's bucket: {status} {body}"


def test_off_disables_throttle(lifecycle, tmp_path):
    srv = _start(lifecycle, tmp_path, "lc-admin-rl-off",
                 "brix_admin_rate_limit off;")
    for i in range(30):
        status, _, _ = srv.request("POST", "/cluster/servers", data=BAD_WRITE)
        assert status == 400, f"write #{i} throttled despite off: {status}"


def test_bad_directive_argument_rejected(tmp_path):
    # Pure config-parse property: render + `nginx -t`, no server ever boots.
    secret = tmp_path / "admin.secret"
    secret.write_text(SECRET + "\n")
    result = nginx_t(
        "nginx_admin_ratelimit.conf",
        tmp_path,
        BIND_HOST=BIND_HOST,
        PORT=PARSE_PLACEHOLDER_PORT,  # nginx -t never binds; non-binding placeholder
        LOG_DIR=str(tmp_path),
        TMP_DIR=str(tmp_path),
        SECRET_FILE=str(secret),
        RL_LINE="brix_admin_rate_limit banana;",
    )
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0
    assert "requests/minute" in out

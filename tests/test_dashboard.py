"""
HTTPS dashboard API tests.

These cover the API-foundation milestone: the legacy `/xrootd/transfers`
endpoint keeps its old shape, while `/xrootd/api/v1/*` returns schema-tagged
JSON and unknown v1 API paths do not fall through to the HTML dashboard.
"""

import json
import re
import subprocess

import pytest
from settings import NGINX_WEBDAV_PORT, SERVER_HOST

BASE_URL = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"


def _curl(*args, timeout=10):
    cmd = ["curl", "-sk", *args]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _dashboard_cookie():
    rc, out, err = _curl(
        "-i",
        "-X", "POST",
        "--data", "password=testpassword",
        f"{BASE_URL}/xrootd/login",
    )
    assert rc == 0, f"dashboard login curl failed: {err.decode()}"

    text = out.decode("latin1")
    match = re.search(r"(?im)^Set-Cookie:\s*(xrd_dashboard=[^;]+)", text)
    assert match, f"dashboard login did not set cookie:\n{text}"
    return match.group(1)


def _dashboard_login_bad_password():
    rc, out, err = _curl(
        "-i",
        "-X", "POST",
        "--data", "password=wrong-password",
        f"{BASE_URL}/xrootd/login",
    )
    assert rc == 0, f"dashboard failed-login curl failed: {err.decode()}"

    text = out.decode("latin1")
    assert "Set-Cookie:" not in text
    assert "Incorrect password" in text


def _get(path, cookie=None):
    args = ["-w", "\n%{http_code}", f"{BASE_URL}{path}"]
    if cookie is not None:
        args = ["-H", f"Cookie: {cookie}", *args]

    rc, out, err = _curl(*args)
    assert rc == 0, f"curl GET {path} failed: {err.decode()}"

    body, status = out.rsplit(b"\n", 1)
    return int(status), body


class TestDashboardApiFoundation:
    def test_v1_snapshot_requires_auth(self):
        status, _ = _get("/xrootd/api/v1/snapshot")
        assert status == 401

    def test_legacy_transfers_shape_is_unchanged(self):
        cookie = _dashboard_cookie()
        status, body = _get("/xrootd/transfers", cookie)

        assert status == 200
        data = json.loads(body.decode())
        assert "schema" not in data
        assert set(["server_ms", "active_transfers", "totals"]).issubset(data)
        assert isinstance(data["active_transfers"], list)
        assert "connections_total" in data["totals"]

    def test_v1_transfers_has_schema_and_limits(self):
        cookie = _dashboard_cookie()
        status, body = _get("/xrootd/api/v1/transfers", cookie)

        assert status == 200
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert "server_ms" in data
        assert data["limits"]["max_active_transfers"] >= 1
        assert data["limits"]["max_tpc_registry_transfers"] >= 1
        assert isinstance(data["active_transfers"], list)
        assert isinstance(data["tpc_transfers"], list)
        assert "totals" in data

    def test_v1_transfer_detail_validates_ids(self):
        cookie = _dashboard_cookie()

        status, body = _get("/xrootd/api/v1/transfers/not-a-number", cookie)
        assert status == 400
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert data["error"] == "bad_transfer_id"

        status, body = _get("/xrootd/api/v1/transfers/999999", cookie)
        assert status == 404
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert data["error"] == "not_found"

    def test_v1_snapshot_has_foundation_sections(self):
        cookie = _dashboard_cookie()
        status, body = _get("/xrootd/api/v1/snapshot", cookie)

        assert status == 200
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        for key in (
            "limits",
            "active_transfers",
            "tpc_transfers",
            "protocols",
            "cache",
            "cluster",
            "events",
            "history",
            "totals",
        ):
            assert key in data

        assert set(data["protocols"]) == {"root", "webdav", "s3", "tpc"}
        for summary in data["protocols"].values():
            assert "active" in summary
            assert "ingress_bps" in summary
            assert "egress_bps" in summary

    def test_v1_empty_foundation_endpoints(self):
        cookie = _dashboard_cookie()
        expected = {
            "/xrootd/api/v1/events": "events",
            "/xrootd/api/v1/history": "buckets",
            "/xrootd/api/v1/cluster": "servers",
        }

        for path, field in expected.items():
            status, body = _get(path, cookie)
            assert status == 200
            data = json.loads(body.decode())
            assert data["schema"] == "xrootd-dashboard.v1"
            assert isinstance(data[field], list)
            # We don't assert empty anymore because the login itself generates events

        status, body = _get("/xrootd/api/v1/cache", cookie)
        assert status == 200
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert data["enabled"] is False
        assert data["listeners"] == []

    def test_unknown_v1_path_returns_json_404(self):
        cookie = _dashboard_cookie()
        status, body = _get("/xrootd/api/v1/not-a-real-endpoint", cookie)

        assert status == 404
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert data["error"] == "not_found"

    def test_dashboard_page_contains_triage_controls(self):
        cookie = _dashboard_cookie()
        status, body = _get("/xrootd/", cookie)

        assert status == 200
        html = body.decode("utf-8")
        for marker in (
            'id="protocol-filter"',
            'id="direction-filter"',
            'id="state-filter"',
            'id="sort-select"',
            'id="search-box"',
            'id="detail-panel"',
            'id="export-snapshot"',
            'id="events-panel"',
            'aria-live="polite"',
        ):
            assert marker in html

    def test_failed_dashboard_login_records_auth_event(self):
        _dashboard_login_bad_password()
        cookie = _dashboard_cookie()
        status, body = _get("/xrootd/api/v1/events", cookie)

        assert status == 200
        data = json.loads(body.decode())
        assert any(
            event["class"] == "auth"
            and event["status"] == 401
            and "login failed" in event["message"]
            for event in data["events"]
        )

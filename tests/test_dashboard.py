"""
HTTPS dashboard API tests.

These cover the API-foundation milestone: the legacy `/xrootd/transfers`
endpoint keeps its old shape, while `/xrootd/api/v1/*` returns schema-tagged
JSON and unknown v1 API paths do not fall through to the HTML dashboard.
"""

import json
import re
import subprocess
import time

import pytest
from settings import NGINX_ANON_PORT, NGINX_WEBDAV_PORT, SERVER_HOST

BASE_URL = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"
ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

try:
    from XRootD import client as _xrd_client
    from XRootD.client.flags import OpenFlags as _OpenFlags
    _HAVE_XROOTD = True
except Exception:  # pragma: no cover - pyxrootd optional in some environments
    _HAVE_XROOTD = False


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
    def test_v1_snapshot_anonymous_is_pii_free(self):
        """With `xrootd_dashboard_anonymous on` (the test fleet config) the read
        API is reachable WITHOUT a login cookie and returns 200 — but the data is
        PII-redacted for anonymous viewers (IPs/identities/paths scrubbed,
        worker_pid omitted; src/observability/dashboard/api.c redact path).  The config-download
        endpoint, by contrast, is always auth-gated (config_download.c) — that is
        the endpoint that must 401 anonymously, not the redacted read snapshot."""
        status, body = _get("/xrootd/api/v1/snapshot")
        assert status == 200, "anonymous read API must be reachable (anonymous tier on)"
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        # Anonymous snapshot must not leak host fingerprints / PII at the top level.
        assert "worker_pid" not in data
        for t in data.get("active_transfers", []):
            assert t.get("client") in ("[redacted]", None)
            assert t.get("identity", "") == ""
            assert t.get("path") in ("[redacted]", None)

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


# Valid transfer-state vocabulary, including the derived "throttled" label that
# the exporter substitutes for "stalled" on rate-limited (but progressing)
# transfers.  See src/observability/dashboard/api.c:dashboard_state_name.
_VALID_STATES = {"active", "idle", "throttled", "stalled", "closing", "error"}


def _snapshot(cookie):
    status, body = _get("/xrootd/api/v1/snapshot", cookie)
    assert status == 200, f"snapshot returned {status}"
    return json.loads(body.decode())


def _rows_for_path(snap, needle):
    return [
        r for r in snap.get("active_transfers", [])
        if needle in (r.get("path") or "")
    ]


def _wait_for_state(cookie, needle, predicate, timeout=20.0):
    """Poll the snapshot until a row matching `needle` and `predicate` is seen
    with idle_ms past the (short, test-config) stalled threshold; return its
    state string, or None on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = _rows_for_path(_snapshot(cookie), needle)
        hits = [r for r in rows if predicate(r) and r.get("idle_ms", 0) >= 3000]
        if hits:
            return hits[0]["state"]
        time.sleep(0.5)
    return None


class TestDashboardThrottledState:
    """Option B: paced transfers read as a steady 'throttled' row with a smoothed
    rate, instead of flapping into the red 'stalled' state every inter-burst gap.

    The test dashboard location uses short idle/stalled thresholds (1s/3s) so the
    transition is observable in seconds rather than the 60s production default.
    """

    def test_dashboard_page_exposes_throttled_control(self):
        """The HTML dashboard offers a 'throttled' filter option and a distinct
        colour class so paced transfers are visually separable from stalled."""
        cookie = _dashboard_cookie()
        status, body = _get("/xrootd/", cookie)

        assert status == 200
        html = body.decode("utf-8")
        assert ">throttled<" in html           # state-filter <option>
        assert "state-throttled" in html       # CSS colour class

    def test_snapshot_state_vocabulary_and_rate_fields(self):
        """Every active transfer reports a known state and carries the smoothed
        instant_bps plus avg_bps integer rate fields (schema regression)."""
        cookie = _dashboard_cookie()
        snap = _snapshot(cookie)
        assert isinstance(snap.get("active_transfers"), list)
        for row in snap["active_transfers"]:
            assert row["state"] in _VALID_STATES, row["state"]
            assert isinstance(row["instant_bps"], int) and row["instant_bps"] >= 0
            assert isinstance(row["avg_bps"], int) and row["avg_bps"] >= 0

    @pytest.mark.skipif(not _HAVE_XROOTD, reason="pyxrootd not available")
    def test_paced_transfer_shows_throttled_not_stalled(self):
        """A transfer that moved data and is then idle past the stalled threshold
        is reported as 'throttled' (making scheduled progress), not 'stalled'."""
        cookie = _dashboard_cookie()
        f = _xrd_client.File()
        st, _ = f.open(f"{ANON_URL}//large200.bin", _OpenFlags.READ)
        assert st.ok, f"open failed: {st.message}"
        try:
            st, data = f.read(0, 65536)   # bytes > 0 => avg_bps > 0 => "moving"
            assert st.ok and len(data) > 0, f"read failed: {st.message}"
            state = _wait_for_state(
                cookie, "large200.bin", lambda r: r.get("avg_bps", 0) > 0)
            assert state == "throttled", f"expected throttled, got {state!r}"
        finally:
            f.close()

    @pytest.mark.skipif(not _HAVE_XROOTD, reason="pyxrootd not available")
    def test_idle_no_progress_transfer_still_shows_stalled(self):
        """Negative guard: the throttled relabel must NOT mask a genuinely stuck
        transfer.  A handle opened but never read (avg_bps == 0) past the stalled
        threshold is still reported as 'stalled', not 'throttled'."""
        cookie = _dashboard_cookie()
        f = _xrd_client.File()
        st, _ = f.open(f"{ANON_URL}//random.bin", _OpenFlags.READ)
        assert st.ok, f"open failed: {st.message}"
        try:
            state = _wait_for_state(
                cookie, "random.bin", lambda r: r.get("avg_bps", 0) == 0)
            assert state == "stalled", f"expected stalled, got {state!r}"
        finally:
            f.close()

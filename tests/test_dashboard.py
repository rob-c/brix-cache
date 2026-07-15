"""
HTTPS dashboard API tests.

These cover the API-foundation milestone: the legacy `/brix/transfers`
endpoint keeps its old shape, while `/brix/api/v1/*` returns schema-tagged
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
        f"{BASE_URL}/brix/login",
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
        f"{BASE_URL}/brix/login",
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
        """With `brix_dashboard_anonymous on` (the test fleet config) the read
        API is reachable WITHOUT a login cookie and returns 200 — but the data is
        PII-redacted for anonymous viewers (IPs/identities/paths scrubbed,
        worker_pid omitted; src/observability/dashboard/api.c redact path).  The config-download
        endpoint, by contrast, is always auth-gated (config_download.c) — that is
        the endpoint that must 401 anonymously, not the redacted read snapshot."""
        status, body = _get("/brix/api/v1/snapshot")
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
        status, body = _get("/brix/transfers", cookie)

        assert status == 200
        data = json.loads(body.decode())
        assert "schema" not in data
        assert set(["server_ms", "active_transfers", "totals"]).issubset(data)
        assert isinstance(data["active_transfers"], list)
        assert "connections_total" in data["totals"]

    def test_v1_transfers_has_schema_and_limits(self):
        cookie = _dashboard_cookie()
        status, body = _get("/brix/api/v1/transfers", cookie)

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

        status, body = _get("/brix/api/v1/transfers/not-a-number", cookie)
        assert status == 400
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert data["error"] == "bad_transfer_id"

        status, body = _get("/brix/api/v1/transfers/999999", cookie)
        assert status == 404
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert data["error"] == "not_found"

    def test_v1_snapshot_has_foundation_sections(self):
        cookie = _dashboard_cookie()
        status, body = _get("/brix/api/v1/snapshot", cookie)

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

        assert set(data["protocols"]) == {"root", "webdav", "s3", "cvmfs", "tpc"}
        for summary in data["protocols"].values():
            assert "active" in summary
            assert "ingress_bps" in summary
            assert "egress_bps" in summary

    def test_v1_empty_foundation_endpoints(self):
        cookie = _dashboard_cookie()
        expected = {
            "/brix/api/v1/events": "events",
            "/brix/api/v1/history": "buckets",
            "/brix/api/v1/cluster": "servers",
        }

        for path, field in expected.items():
            status, body = _get(path, cookie)
            assert status == 200
            data = json.loads(body.decode())
            assert data["schema"] == "xrootd-dashboard.v1"
            assert isinstance(data[field], list)
            # We don't assert empty anymore because the login itself generates events

        status, body = _get("/brix/api/v1/cache", cookie)
        assert status == 200
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert data["enabled"] is False
        assert data["listeners"] == []

    def test_unknown_v1_path_returns_json_404(self):
        cookie = _dashboard_cookie()
        status, body = _get("/brix/api/v1/not-a-real-endpoint", cookie)

        assert status == 404
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert data["error"] == "not_found"

    def test_dashboard_page_contains_triage_controls(self):
        cookie = _dashboard_cookie()
        status, body = _get("/brix/", cookie)

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
        status, body = _get("/brix/api/v1/events", cookie)

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
    status, body = _get("/brix/api/v1/snapshot", cookie)
    assert status == 200, f"snapshot returned {status}"
    return json.loads(body.decode())


def _rows_for_path(snap, needle):
    return [
        r for r in snap.get("active_transfers", [])
        if needle in (r.get("path") or "")
    ]


def _wait_for_state(cookie, needle, predicate, timeout=45.0):
    """Poll the snapshot until a row matching `needle` and `predicate` is seen
    with idle_ms past the (short, test-config) stalled threshold; return its
    state string, or None on timeout.

    The budget is generous (45s) on purpose: under the -n8 fast lane the fleet's
    dashboard/metrics refresh loop is CPU-starved, so idle_ms/avg_bps propagate
    into the snapshot more slowly than the transfer's real timeline. The
    throttled window itself is wide (avg_bps is a slowly-decaying lifetime rate),
    so a longer poll only tolerates slow propagation — it does not relax WHAT is
    asserted (still an exact 'throttled'/'stalled' state)."""
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
        status, body = _get("/brix/", cookie)

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


class TestDashboardCvmfs:
    """cvmfs:// site-cache section of the dashboard API (api_cvmfs.c).

    The metrics SHM zone always exists on the test fleet, so the endpoint
    returns the full aggregate shape even when no cvmfs traffic has flowed
    (enabled=false); repo/upstream slot tables are empty until a cvmfs
    request registers one.
    """

    CVMFS_SCALARS = (
        "negative_hits_total",
        "fills_total",
        "fill_failures_total",
        "verify_failures_total",
        "origin_failovers_total",
        "secure_requests_total",
        "bytes_served_hit_total",
        "bytes_served_fill_total",
        "origin_bytes_total",
    )

    def test_v1_cvmfs_endpoint_schema(self):
        """Success path: authenticated GET returns the schema envelope plus the
        aggregate counters, the request-mix object, and the slot-table arrays."""
        cookie = _dashboard_cookie()
        status, body = _get("/brix/api/v1/cvmfs", cookie)

        assert status == 200
        data = json.loads(body.decode())
        assert data["schema"] == "xrootd-dashboard.v1"
        assert isinstance(data["enabled"], bool)
        assert set(data["requests"]) == {"cas", "manifest", "geo", "reject"}
        for key in self.CVMFS_SCALARS:
            assert key in data, f"missing cvmfs counter {key}"
            assert isinstance(data[key], int)
        assert isinstance(data["repos"], list)
        assert isinstance(data["upstreams"], list)

    def test_v1_snapshot_has_cvmfs_section_and_totals(self):
        """The snapshot nests the same section under "cvmfs", and the generated
        per-protocol totals now carry the cvmfs in/out byte counters (in = WAN
        origin pull, out = LAN bytes served)."""
        cookie = _dashboard_cookie()
        status, body = _get("/brix/api/v1/snapshot", cookie)

        assert status == 200
        data = json.loads(body.decode())
        cvmfs = data["cvmfs"]
        assert isinstance(cvmfs["enabled"], bool)
        assert isinstance(cvmfs["repos"], list)
        assert isinstance(cvmfs["upstreams"], list)
        assert "cvmfs_bytes_rx" in data["totals"]
        assert "cvmfs_bytes_tx" in data["totals"]
        assert "cvmfs_errors_total" in data["totals"]
        # bytes_*_total keys appear in the per-protocol summary only once
        # traffic has flowed (dashboard_build_proto_summary elides zero/zero);
        # the always-present rate/active fields prove the summary is wired.
        for key in ("active", "ingress_bps", "egress_bps"):
            assert key in data["protocols"]["cvmfs"]

    def test_v1_cvmfs_rejects_non_get(self):
        """Error path: the endpoint is read-only — POST is 405, like every other
        JSON read endpoint (method gate in api.c)."""
        rc, out, err = _curl(
            "-X", "POST",
            "-o", "/dev/null",
            "-w", "%{http_code}",
            f"{BASE_URL}/brix/api/v1/cvmfs",
        )
        assert rc == 0, f"curl POST failed: {err.decode()}"
        assert out == b"405"

    def test_v1_cvmfs_anonymous_redacts_names(self):
        """Security-negative: repo fqrns and upstream hosts arrive from the
        wire/config, so the anonymous (cookieless) view must redact every name
        while keeping the counters."""
        status, body = _get("/brix/api/v1/cvmfs")

        assert status == 200, "anonymous read tier must serve the endpoint"
        data = json.loads(body.decode())
        assert data["anonymous"] is True
        for row in data["repos"] + data["upstreams"]:
            assert row["name"] == "[redacted]"

    def test_dashboard_page_contains_cvmfs_ui(self):
        """The embedded page ships the cvmfs card/panel/filter markers."""
        cookie = _dashboard_cookie()
        status, body = _get("/brix/", cookie)

        assert status == 200
        html = body.decode("utf-8")
        for marker in (
            'id="cvmfs-panel"',
            "<option>cvmfs</option>",
            "renderCvmfs",
        ):
            assert marker in html

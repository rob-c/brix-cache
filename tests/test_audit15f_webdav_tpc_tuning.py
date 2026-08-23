"""
test_audit15f_webdav_tpc_tuning.py — the WebDAV HTTP-TPC tuning surface (audit
§A2, testsuite-combinatorial-coverage-audit 2026-08-15: seven directives in
`src/protocols/webdav/directives_tpc.h` had ZERO occurrences anywhere in the
tree — `brix_webdav_tpc_marker_interval`, `_max_streams`, `_low_speed_bytes`,
`_low_speed_secs`, `_token_client_id`, `_token_client_secret` and `_curl` —
while every one of their table siblings was exercised).

Drive: a COPY with a `Source:` header (pull mode) against a capturing TLS mock
source, one nginx location per knob-set.  The mock records every request it
receives (method, path, Range, Authorization), so each knob is asserted on the
SOURCE-side wire, not merely on the destination's return code.

Two DEFECT-CANDIDATE pins, and one plane-twin pin:

  * `brix_webdav_tpc_marker_interval` arms only by accident (defect candidate
    #9).  `webdav_tpc_marker_start()` bare-NULL-checks `conf->common.thread_pool`
    (tpc_marker_start.c:308) and declines; postconfig only resolves that field
    for a SERVER-level `brix_webdav on` (postconfig.c:299-317), which the
    directive's own location-only type makes impossible.  Every other offload
    site instead calls `brix_shared_thread_pool()`, which resolves by name at
    first use and CACHES the result back onto the loc-conf (shared_conf.h:534,
    written for exactly this hazard).  So a location's marker path stays
    disarmed until some unrelated threaded request — a PUT, a MOVE, a
    collection COPY — happens to warm the same loc-conf.  Both halves are
    pinned: cold location declines to 201, warmed location streams markers.
  * `brix_webdav_tpc_curl` (defect candidate #10) is config-validated (regular
    file, X_OK, config_merge.c:499) and then never used: the only fork/exec'd curl in the
    WebDAV TPC path — the RFC 8693 exchange in tpc_cred_exchange.c:94 —
    hardcodes `argv[0] = "curl"` and runs it through `brix_subprocess_capture`,
    whose `execvp` PATH-resolves the name (core/compat/subprocess.c:66).  An
    operator pointing the directive at a curl of their choosing silently gets
    the PATH one.  Pinned by giving the directive a recording wrapper that
    always fails: the COPY still succeeds and the wrapper's log stays empty.
  * the client-credential argv defect already pinned on the native plane
    (`test_audit15c_tpc_token_exchange.py`) is pinned here on its WebDAV twin:
    `"-u", id, secret` as three argv words means curl sends `id:` with an
    EMPTY password and treats the secret as an extra URL.

Both pins assert today's observed wire behavior and must be inverted when the
defects are fixed.
"""

import base64
import json
import os
import re
import shutil
import ssl
import time
from http.server import BaseHTTPRequestHandler

import pytest
import requests

from _test_audit15f_helpers import (CapturingSource, gets, heads,
                                    mint_localhost_cert, serve)
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST

def _phase_tpctune_1(export):
    for plane in PLANES:
        _plane_dir(export, plane).mkdir(parents=True)

def _phase_tpctune_2(source, idp):
    for server in (source, idp):
        server.shutdown()
        server.server_close()


def _guard_tpctune_1():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

def _guard_tpctune_2():
    if shutil.which("openssl") is None:
        pytest.skip("openssl not found — cannot mint the mock source's cert")

def _check_test_max_streams_splits_the_object_into_ranges_1(source):
    assert len(heads(source, "/obj.bin")) == 1, source

def _check_test_max_streams_splits_the_object_into_ranges_2(ranges):
    assert len(ranges) == 4, ranges

def _check_test_max_streams_splits_the_object_into_ranges_3(spans):
    assert spans[0][0] == 0 and spans[-1][1] == len(PAYLOAD) - 1, spans

def _check_test_max_streams_splits_the_object_into_ranges_4(s1, spans, e0):
    assert s1 == e0 + 1, ("the range split left a hole or overlapped",
                          spans)


pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15f-tpctune")]

_EXTRA = LIFECYCLE_SHARED_PORTS["lc-audit15f-tpctune"]["extra"]
MOCK_PORT = _EXTRA["MOCK_PORT"]
IDP_PORT = _EXTRA["IDP_PORT"]

# 14 KiB: large enough that a 4-way range split gives every stream real work,
# small enough that the whole suite stays inside the per-test timeout.
PAYLOAD = b"audit15f-tpc-tuning-payload-" * 512
SUBJECT = "subject-token-audit15f"
DELEGATED = "delegated-token-audit15f"
STALL_SECS = 3.0
PLANES = ("nomark", "mark", "markcold", "multi", "slow", "tokx", "tokstd")


class _IdpHandler(BaseHTTPRequestHandler):
    """Capturing RFC 8693 token endpoint (plain HTTP: the exchange subprocess
    is a bare `curl` invocation with no CA options of its own)."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.server.recorded.append({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "ctype": self.headers.get("Content-Type"),
            "body": self.rfile.read(length) if length else b"",
        })
        out = json.dumps({"access_token": DELEGATED}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST

    def log_message(self, *args):
        pass


@pytest.fixture()
def tpctune(lifecycle, tmp_path):
    _guard_tpctune_1()
    _guard_tpctune_2()

    cert, key = mint_localhost_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    source = serve(CapturingSource, MOCK_PORT, tls=ctx, payload=PAYLOAD,
                   stall_secs=STALL_SECS)
    idp = serve(_IdpHandler, IDP_PORT)

    # The poisoned curl: recorded and always-failing, so "the COPY succeeded
    # and this log is empty" is two-sided evidence it was never exec'd.
    curl_log = tmp_path / "fake-curl.log"
    fake_curl = tmp_path / "fake-curl.sh"
    fake_curl.write_text("#!/bin/sh\n"
                         f'printf "%s\\n" "$*" >> {curl_log}\n'
                         "exit 42\n")
    fake_curl.chmod(0o755)

    export = tmp_path / "export"
    _phase_tpctune_1(export)
    for path in (tmp_path, export, *(export / p for p in PLANES),
                 *(_plane_dir(export, p) for p in PLANES)):
        os.chmod(path, 0o777)

    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-audit15f-tpctune",
            template="nginx_audit15f_tpctune.conf",
            protocol="webdav",
            data_root=str(export),
            template_values={"BIND_HOST": BIND_HOST,
                             "EXPORT_ROOT": str(export),
                             "CA_PEM": str(cert),
                             "TOKEN_ENDPOINT": f"http://{HOST}:{IDP_PORT}/token",
                             "FAKE_CURL": str(fake_curl)},
            reason="audit-15f webdav TPC tuning knobs"))
        yield ep, export, source.recorded, idp.recorded, curl_log
    finally:
        _phase_tpctune_2(source, idp)


def _copy(ep, plane, name, obj="/obj.bin", headers=None, timeout=60):
    hdrs = {"Source": f"https://{HOST}:{MOCK_PORT}{obj}"}
    hdrs.update(headers or {})
    return requests.request("COPY", f"http://{HOST}:{ep.port}/{plane}/{name}",
                            headers=hdrs, timeout=timeout)


def _put(ep, plane, name, body=b"warm-the-loc-conf-thread-pool"):
    """An ordinary in-memory PUT.  webdav_put_try_threaded() resolves the pool
    through brix_shared_thread_pool() (put_body.c:245), which caches it onto
    this location's conf — the side effect the marker pins turn on."""
    return requests.put(f"http://{HOST}:{ep.port}/{plane}/{name}",
                        data=body, timeout=30)


def _errlog(ep):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()[-4000:]
    except FileNotFoundError:
        return ""


def _plane_dir(export, plane):
    """Each location has its own export root, and the wire path keeps the
    location prefix — so plane P's objects land under <root-of-P>/P/."""
    return export / plane / plane


def _landed(export, plane, name):
    path = _plane_dir(export, plane) / name
    return path.read_bytes() if path.exists() else None


def test_baseline_pull_is_one_plain_get(tpctune):
    """The control every other case is read against: defaults mean one
    unranged GET, no HEAD probe, and the object committed byte-exact."""
    ep, export, source, _idp, _log = tpctune
    r = _copy(ep, "nomark", "base.bin")
    assert r.status_code == 201, (r.status_code, r.text[:400], _errlog(ep))
    assert _landed(export, "nomark", "base.bin") == PAYLOAD
    assert len(gets(source, "/obj.bin")) == 1, source
    assert not heads(source, "/obj.bin"), source
    assert source[0]["range"] is None, source


def test_marker_interval_streams_perf_markers(tpctune):
    """brix_webdav_tpc_marker_interval 1: the COPY is answered 202 up front and
    the body carries WLCG Performance-Marker blocks while the transfer runs,
    terminated by "success" (tpc_marker.c).

    The PUT is not decoration — it is what arms the marker path, by resolving
    and caching this location's thread pool (see the cold twin below)."""
    ep, export, _source, _idp, _log = tpctune
    warm = _put(ep, "mark", "warm.bin")
    assert warm.status_code in (201, 204), (warm.status_code, _errlog(ep))

    # /slow.bin dribbles and then pauses STALL_SECS, and this plane carries no
    # low-speed bound — so the poll timer has time to emit at least one marker.
    r = _copy(ep, "mark", "marked.bin", obj="/slow.bin")
    assert r.status_code == 202, (r.status_code, r.text[:400], _errlog(ep))
    body = r.text
    assert "Perf Marker" in body, body[:400]
    assert body.rstrip().endswith("success"), body[-400:]
    # Single-stream pull: exactly one stripe, indexed 0.
    assert "Total Stripe Count: 1" in body, body[:400]
    assert "Stripe Index: 0" in body, body[:400]
    assert _landed(export, "mark", "marked.bin") == PAYLOAD


def test_marker_interval_arms_on_a_cold_location(tpctune):
    """A location-level TPC marker interval resolves its shared pool lazily.

    The marker path must behave the same before and after an unrelated threaded
    request has warmed the location configuration.
    """
    ep, export, _source, _idp, _log = tpctune
    r = _copy(ep, "markcold", "unmarked.bin", obj="/slow.bin")
    assert r.status_code == 202, (r.status_code, r.text[:400], _errlog(ep))
    assert "Perf Marker" in r.text, r.text[:400]
    assert r.text.rstrip().endswith("success"), r.text[-400:]
    assert _landed(export, "markcold", "unmarked.bin") == PAYLOAD


def test_max_streams_splits_the_object_into_ranges(tpctune):
    """brix_webdav_tpc_max_streams 4 + X-Number-Of-Streams: 4 — one HEAD to
    learn the size, then four ranged GETs that tile the object exactly
    (tpc_curl_multi.c tpc_ms_setup_stream)."""
    ep, export, source, _idp, _log = tpctune
    r = _copy(ep, "multi", "split.bin", headers={"X-Number-Of-Streams": "4"})
    def _assert_test_max_streams_splits_the_object_into_ranges_1():
        assert r.status_code == 201, (r.status_code, r.text[:400])
        assert _landed(export, "multi", "split.bin") == PAYLOAD, \
            "the reassembled multi-stream object differs from the source"

    _assert_test_max_streams_splits_the_object_into_ranges_1()
    _check_test_max_streams_splits_the_object_into_ranges_1(source)
    ranges = [r["range"] for r in gets(source, "/obj.bin")]
    _check_test_max_streams_splits_the_object_into_ranges_2(ranges)
    spans = sorted(tuple(int(v) for v in re.match(r"bytes=(\d+)-(\d+)", rng)
                         .groups())
                   for rng in ranges)
    _check_test_max_streams_splits_the_object_into_ranges_3(spans)
    for (_s0, e0), (s1, _e1) in zip(spans, spans[1:]):
        _check_test_max_streams_splits_the_object_into_ranges_4(s1, spans, e0)


def test_client_cannot_exceed_the_configured_stream_cap(tpctune):
    """Security-negative: X-Number-Of-Streams is a CLIENT header.  On a
    location that never raised the cap (default 1) a client asking for 8
    streams still gets one plain GET — the fan-out amplification stays the
    operator's decision (webdav_tpc_parse_stream_count)."""
    ep, export, source, _idp, _log = tpctune
    r = _copy(ep, "nomark", "capped.bin", headers={"X-Number-Of-Streams": "8"})
    assert r.status_code == 201, (r.status_code, r.text[:400])
    assert _landed(export, "nomark", "capped.bin") == PAYLOAD
    assert not heads(source, "/obj.bin"), \
        "the client header alone put the pull on the multi-stream path"
    pulled = gets(source, "/obj.bin")
    assert len(pulled) == 1, pulled
    assert pulled[0]["range"] is None, pulled


def test_low_speed_bound_aborts_a_stalled_pull(tpctune):
    """Error case: the source sends 16 bytes and goes quiet.  With a 1 MB/s
    floor held for 1 s the leg is aborted (CURLOPT_LOW_SPEED_LIMIT/TIME,
    tpc_curl_setup.c:111) and nothing is committed — while the same object
    over the unbounded control location completes."""
    ep, export, _source, _idp, _log = tpctune
    started = time.monotonic()
    r = _copy(ep, "slow", "stalled.bin", obj="/slow.bin")
    elapsed = time.monotonic() - started
    assert r.status_code >= 400, (r.status_code, r.text[:400])
    assert _landed(export, "slow", "stalled.bin") is None, \
        "the aborted pull still committed an object"
    assert elapsed < STALL_SECS, \
        f"the bound did not fire early: gave up after {elapsed:.1f}s"

    control = _copy(ep, "nomark", "patient.bin", obj="/slow.bin")
    assert control.status_code == 201, (control.status_code,
                                        control.text[:400])
    assert _landed(export, "nomark", "patient.bin") == PAYLOAD, \
        "the same slow source failed without the bound — not a stall test"


def test_token_exchange_delegates_to_the_source(tpctune):
    """brix_webdav_tpc_token_client_id/_secret: a COPY carrying
    `Credential: token-exchange` exchanges the caller's bearer at the IdP and
    presents the DELEGATED token to the source — the user's own subject token
    must not travel onward."""
    ep, export, source, idp, _log = tpctune
    r = _copy(ep, "tokstd", "delegated.bin",
              headers={"Credential": "token-exchange",
                       "Authorization": f"Bearer {SUBJECT}"})
    assert r.status_code == 201, (r.status_code, r.text[:400])
    assert _landed(export, "tokstd", "delegated.bin") == PAYLOAD
    assert idp, "the exchange never reached the token endpoint"
    assert idp[-1]["ctype"] == "application/x-www-form-urlencoded"
    auths = [g["auth"] for g in gets(source, "/obj.bin")]
    assert auths == [f"Bearer {DELEGATED}"], auths


def test_client_secret_never_reaches_the_idp_defect_pin(tpctune):
    # Client credentials must be one curl -u value.  Passing the id and secret
    # as separate argv words makes curl treat the secret as another URL and can
    # drop the request instead of completing the exchange.
    ep, _export, _source, idp, _log = tpctune
    r = _copy(ep, "tokstd", "secret.bin",
              headers={"Credential": "token-exchange",
                       "Authorization": f"Bearer {SUBJECT}"})
    assert r.status_code == 201, (r.status_code, r.text[:400])
    with_auth = [row for row in idp if row["auth"]]
    assert with_auth, idp
    kind, b64 = with_auth[-1]["auth"].split()
    assert kind == "Basic"
    assert base64.b64decode(b64).decode() == "audit15f-client:s3cret-audit15f"


def test_configured_curl_binary_is_never_executed_defect_pin(tpctune):
    # The configured curl path is used by the token-exchange subprocess.
    ep, export, _source, idp, curl_log = tpctune
    r = _copy(ep, "tokx", "poisoned.bin",
              headers={"Credential": "token-exchange",
                       "Authorization": f"Bearer {SUBJECT}"})
    assert r.status_code >= 400, (r.status_code, r.text[:400])
    assert _landed(export, "tokx", "poisoned.bin") is None
    assert not idp, "the configured failing curl reached the token endpoint"
    assert curl_log.exists(), "the configured curl binary was not executed"

"""
test_audit15c_tpc_token_exchange.py — native-TPC outbound RFC 8693 token
exchange, driven live against a capturing mock token endpoint (audit §A2,
testsuite-combinatorial-coverage-audit 2026-08-15: the whole
`brix_tpc_outbound_token_endpoint`/`_client_id`/`_client_secret` exchange flow
had opaque-parser units and a WebDAV dead-endpoint probe only — the native
plane had never executed an exchange).

Drive: destination write-open with the TPC opaque + `tpc.token_mode=
token-exchange` → kXR_sync #1 arms → kXR_sync #2 starts the pull; the sync
reply (possibly via kXR_waitresp + pushed kXR_attn) carries the outcome
(src/protocols/root/write/sync.c, src/tpc/outbound/tpc_token_exchange.c).

Three DEFECT-CANDIDATE pins (verified against real curl before writing):

  * the argv builder passes `-d <staged-file>` without the `@` prefix, so the
    literal staged-file PATH is POSTed — the RFC 8693 form body never reaches
    the IdP (the WebDAV twin tpc_cred_exchange.c even says "for curl --data
    @file" while building the same argv);
  * client credentials go out as three argv words ("-u", id, secret): curl
    takes `-u id` with an EMPTY password and treats the secret as an extra
    URL, so the secret is absent from the Basic header and leaks into
    URL/DNS resolution instead.  curl exits with the LAST transfer's status,
    so the exchange still "succeeds";
  * `brix_tpc_outbound_scope` (defect candidate #11) is carried all the way
    into the staged form body (launch.c copies it to t->token_scope,
    tpc_token_exchange.c interpolates `&scope=%s`) and then dies with it: a configured scope is INERT on
    the wire, so a site that narrows its exchanged token is not narrowing
    anything.  It is a consequence of the first pin, pinned separately because
    it is the directive's whole observable contract.

All three pins assert today's observed wire behavior and must be inverted when
the defects are fixed.
"""

import base64
import json
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import HOST
from test_phase25_ratelimit import (KXR_OK, KXR_WAIT, _xrd_login, _xrd_open,
                                    _xrd_recv_status)
from test_ssi_async import _parse_asynresp, kXR_attn, kXR_waitresp

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15c-tpcx")]

KXR_ERROR = 4003
KXR_AUTH_FAILED = 3030
KXR_SYNC = 3016

SEED = b"tpcx-source-payload\n"
OUTBOUND_SCOPE = "storage.modify"      # not the "storage.read" default
DELEGATED = "delegated-tok-audit15c"
MOCK_PORT = LIFECYCLE_SHARED_PORTS["lc-audit15c-tpcx-good"]["extra"]["MOCK_PORT"]


@pytest.fixture()
def token_mock():
    """Capturing token endpoint: /token answers RFC 8693-shaped JSON, /junk
    answers non-JSON garbage; every request is recorded."""
    recorded = []

    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            recorded.append({"method": self.command, "path": self.path,
                             "auth": self.headers.get("Authorization"),
                             "ctype": self.headers.get("Content-Type"),
                             "body": body})
            if self.path.startswith("/junk"):
                out = b"<html>not a token response</html>"
            else:
                out = json.dumps({"access_token": DELEGATED}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = do_POST = _serve

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer((HOST, MOCK_PORT), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield recorded
    server.shutdown()
    server.server_close()


def _start_dest(lifecycle, name, data, bearer, endpoint, extra_knobs=""):
    return lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_audit15c_tpcx.conf",
        data_root=str(data),
        template_values={"BIND_HOST": HOST, "BEARER_FILE": str(bearer),
                         "TOKEN_ENDPOINT": endpoint,
                         "OUTBOUND_KNOBS": extra_knobs},
        reason="audit-15c native TPC outbound token exchange")).port


@pytest.fixture()
def tpcx(lifecycle, tmp_path, token_mock):
    """(ports, data, recorded): five token-exchange destinations over one
    export — good endpoint, good+client-credentials, good+an explicit outbound
    scope, dead endpoint, and an endpoint answering junk.  Every instance can
    also serve as pull source."""
    data = tmp_path / "data"
    data.mkdir()
    (data / "src.bin").write_bytes(SEED)
    bearer = tmp_path / "bearer.tok"
    bearer.write_text("subject-token-audit15c\n")
    bearer.chmod(0o600)
    base = f"http://{HOST}:{MOCK_PORT}"
    ports = {
        "good": _start_dest(lifecycle, "lc-audit15c-tpcx-good", data, bearer,
                            f"{base}/token"),
        "cc": _start_dest(
            lifecycle, "lc-audit15c-tpcx-cc", data, bearer, f"{base}/token",
            "        brix_tpc_outbound_client_id audit15c-client;\n"
            "        brix_tpc_outbound_client_secret s3cret-audit15c;\n"),
        "scope": _start_dest(
            lifecycle, "lc-audit15c-tpcx-scope", data, bearer,
            f"{base}/token",
            f"        brix_tpc_outbound_scope {OUTBOUND_SCOPE};\n"),
        "dead": _start_dest(lifecycle, "lc-audit15c-tpcx-dead", data, bearer,
                            "http://127.0.0.1:1/token"),  # net-literal-allow: deliberately dead local token endpoint
        "junk": _start_dest(lifecycle, "lc-audit15c-tpcx-junk", data, bearer,
                            f"{base}/junk"),
    }
    return ports, data, token_mock


def _arm_source(src_port, key):
    """Client leg 1 of the native rendezvous: a read-open on the source with
    tpc.key + tpc.dst registers the key (open_tpc.c tpc_handle_source); the
    destination's pull leg later presents the same key with tpc.org and
    consumes it.  Returns the open socket — the arm outlives the pull."""
    s = _xrd_login(HOST, src_port)
    status, body = _xrd_open(
        s, f"/src.bin?tpc.key={key}&tpc.dst=127.0.0.1&tpc.stage=placement")  # net-literal-allow: local TPC wire payload
    assert status == KXR_OK, ("TPC source arm open refused", status, body)
    return s


def _tpc_dst_open(s, path, src_port, key):
    """Destination write-open selecting token-exchange for the outbound leg."""
    opaque = (f"?tpc.src=127.0.0.1:{src_port}&tpc.key={key}"  # net-literal-allow: local TPC wire payload
              f"&tpc.lfn=/src.bin&tpc.stage=copy&oss.asize={len(SEED)}"
              f"&tpc.token_mode=token-exchange")
    payload = (path + opaque).encode()
    # kXR_new | kXR_open_wrto | kXR_mkpath
    body = struct.pack(">HH12s", 0o644, 0x0008 | 0x4000 | 0x0100, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _sync(s, fhandle):
    s.sendall(struct.pack(">BBH", 0, 1, KXR_SYNC) + fhandle[:4]
              + b"\x00" * 12 + struct.pack(">I", 0))
    return _xrd_recv_status(s)


def _drive_pull(s, fhandle):
    """Arm (sync #1), start the pull (sync #2), then unwrap wait/attn frames
    until a terminal kXR_ok / kXR_error; returns (status, body)."""
    status, body = _sync(s, fhandle)
    assert status == KXR_OK, ("TPC arm sync refused", status, body)
    status, body = _sync(s, fhandle)
    for _ in range(64):
        if status == KXR_WAIT:
            time.sleep(0.25)
            status, body = _sync(s, fhandle)
        elif status == kXR_waitresp:
            status, body = _xrd_recv_status(s)
        elif status == kXR_attn:
            _, status, body = _parse_asynresp(body)
        else:
            return status, body
    raise AssertionError(f"no terminal TPC outcome: {status} {body!r}")


def _pull(dst_port, src_port, dest_path):
    key = "a15c" + dest_path.strip("/").replace(".", "").replace("-", "")
    arm = _arm_source(src_port, key)
    s = _xrd_login(HOST, dst_port)
    s.settimeout(30)
    try:
        status, body = _tpc_dst_open(s, dest_path, src_port, key)
        assert status == KXR_OK, ("TPC dest-open refused", status, body)
        return _drive_pull(s, body[:4])
    finally:
        s.close()
        arm.close()


def _wait_file(path, want, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.read_bytes() == want:
            return True
        time.sleep(0.2)
    return False


def _token_posts(recorded, path="/token"):
    return [r for r in recorded if r["path"] == path]


def test_token_exchange_pull_completes(tpcx):
    ports, data, recorded = tpcx
    status, body = _pull(ports["good"], ports["dead"], "/pulled-good.bin")
    assert status == KXR_OK, (status, body)
    assert _wait_file(data / "pulled-good.bin", SEED), \
        "TPC pull reported ok but the destination file never matched the seed"
    posts = _token_posts(recorded)
    assert posts, recorded
    assert posts[-1]["method"] == "POST"
    assert posts[-1]["ctype"] == "application/x-www-form-urlencoded"


def test_exchange_post_body_is_staged_path_defect_pin(tpcx):
    # The staged body must be read by curl, so the RFC 8693 form reaches the IdP.
    ports, data, recorded = tpcx
    status, body = _pull(ports["good"], ports["dead"], "/pulled-pin.bin")
    assert status == KXR_OK, (status, body)
    wire_body = _token_posts(recorded)[-1]["body"]
    assert b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" \
        in wire_body or b"grant_type=urn:ietf:params:oauth:grant-type:token-exchange" in wire_body
    assert b"subject_token=subject-token-audit15c" in wire_body


def test_client_secret_never_reaches_idp_defect_pin(tpcx):
    # Client credentials must be one curl -u value, so the IdP sees the secret.
    ports, data, recorded = tpcx
    status, body = _pull(ports["cc"], ports["good"], "/pulled-cc.bin")
    assert status == KXR_OK, (status, body)
    assert _wait_file(data / "pulled-cc.bin", SEED)
    with_auth = [r for r in _token_posts(recorded) if r["auth"]]
    assert with_auth, recorded
    kind, b64 = with_auth[-1]["auth"].split()
    assert kind == "Basic"
    assert base64.b64decode(b64).decode() == "audit15c-client:s3cret-audit15c"


def test_dead_endpoint_fails_closed(tpcx):
    ports, data, recorded = tpcx
    status, body = _pull(ports["dead"], ports["good"], "/pulled-dead.bin")
    assert status == KXR_ERROR, (status, body)
    assert b"token exchange failed" in body, body
    # Fail-closed: no anonymous fallback — the pull never commits the seed.
    dest = data / "pulled-dead.bin"
    assert not dest.exists() or dest.read_bytes() != SEED
    assert not _token_posts(recorded), recorded


def test_junk_token_response_fails(tpcx):
    ports, data, recorded = tpcx
    status, body = _pull(ports["junk"], ports["good"], "/pulled-junk.bin")
    assert status == KXR_ERROR, (status, body)
    # The access_token parse failure surfaces as kXR_AuthFailed with the
    # generic "TPC pull failed" text (the specific message stays in the log).
    errnum = struct.unpack(">I", body[:4])[0]
    assert errnum == KXR_AUTH_FAILED, (errnum, body)
    # Unlike the dead endpoint, the mock WAS reached — the refusal is the
    # access_token parse, not connectivity.
    assert _token_posts(recorded, "/junk"), recorded
    dest = data / "pulled-junk.bin"
    assert not dest.exists() or dest.read_bytes() != SEED


def test_a_configured_outbound_scope_still_exchanges(tpcx):
    """success (audit §B1: brix_tpc_outbound_scope was configured nowhere):
    the directive replaces the "storage.read" default that
    server_conf_merge_cluster.c merges in, launch.c copies it onto the pull
    task, and the exchange and the pull complete exactly as they do without
    it — a narrowed scope is not a refusal."""
    ports, data, recorded = tpcx
    status, body = _pull(ports["scope"], ports["dead"], "/pulled-scope.bin")
    assert status == KXR_OK, (status, body)
    assert _wait_file(data / "pulled-scope.bin", SEED), \
        "scoped exchange reported ok but the destination file never matched"
    assert _token_posts(recorded), recorded


def test_outbound_scope_never_reaches_the_idp_defect_pin(tpcx):
    # The configured outbound scope must reach the IdP on the wire.
    ports, data, recorded = tpcx
    status, body = _pull(ports["scope"], ports["good"], "/pulled-scope-pin.bin")
    assert status == KXR_OK, (status, body)
    post = _token_posts(recorded)[-1]
    seen = post["body"] + post["path"].encode() + (post["auth"] or "").encode()
    assert OUTBOUND_SCOPE.encode() in seen, post

"""Executable Phase-118 native TPC conformance coverage."""
import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import struct
import subprocess
import threading
from urllib.parse import urlsplit

import pytest

from _test_phase115_pgread_verify_helpers import (
    error_frame, kXR_close, kXR_open, kXR_query, ok_frame,
)
from settings import HOST, ROOT_TPC_NGINX_PORT, TPC_SRC_GUARD_PORT, url_host
from test_xrd_conform_cache import EvictOrigin
from test_xrd_conform_http_semantics import XRD, _clean_environment


kXR_Unsupported = 3013
kXR_IOError = 3007
kXR_sync = 3016


class TpcClaimServer(EvictOrigin):
    """Writable source that refuses rendezvous opens after a numeric claim."""

    def __init__(self, claim, refusal=kXR_Unsupported):
        self.claim = claim
        self.refusal = refusal
        self.tpc_attempts = 0
        super().__init__()

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_query:
            if b"phase118.tpc_attempts" in body:
                conn.sendall(ok_frame(
                    sid, str(self.tpc_attempts).encode("ascii"),
                ))
                return authenticated
            conn.sendall(self._claim_frame(sid))
            return authenticated
        if reqid == kXR_open and b"tpc.key=" in body:
            with self._lock:
                self.tpc_attempts += 1
            conn.sendall(error_frame(
                sid, self.refusal, b"TPC denied by fixture",
            ))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)

    def _claim_frame(self, sid):
        from _test_phase115_pgread_verify_helpers import ok_frame

        return ok_frame(sid, str(self.claim).encode("ascii"))


class AbortDestination(EvictOrigin):
    """Hidden POSC staging fixture whose transfer aborts at the fire sync."""

    def __init__(self):
        self.tpc_connections = set()
        self.sync_counts = {}
        self.close_seen = 0
        super().__init__()

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_query:
            self._query_response(conn, sid)
            return authenticated
        return self._dispatch_nonquery(
            conn, sid, reqid, hdr, body, authenticated,
        )

    def _dispatch_nonquery(self, conn, sid, reqid, hdr, body,
                           authenticated):
        key = conn.fileno()
        if reqid == kXR_open and b"tpc.key=" in body:
            with self._lock:
                self.tpc_connections.add(key)
                self.sync_counts[key] = 0
            conn.sendall(ok_frame(sid, struct.pack("!I", 7) + b"\x00" * 8))
            return authenticated
        if reqid == kXR_sync and key in self.tpc_connections:
            self._sync_response(conn, sid, key)
            return authenticated
        if reqid == kXR_close and key in self.tpc_connections:
            self._close_response(conn, sid)
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)

    @staticmethod
    def _query_response(conn, sid):
        conn.sendall(ok_frame(sid, b"1"))

    def _sync_response(self, conn, sid, key):
        with self._lock:
            self.sync_counts[key] += 1
            count = self.sync_counts[key]
        if count == 1:
            conn.sendall(ok_frame(sid))
            return
        conn.sendall(error_frame(
            sid, kXR_IOError, b"destination abort fixture",
        ))

    def _close_response(self, conn, sid):
        with self._lock:
            self.close_seen += 1
        conn.sendall(ok_frame(sid))


class WebdavTpcHandler(BaseHTTPRequestHandler):
    """Bearer-gated in-memory WebDAV TPC endpoint for runner validation."""

    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def _authorized(self):
        return self.headers.get("Authorization") == "Bearer phase118-bearer"

    def _reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_PUT(self):
        if not self._authorized():
            self._reply(401)
            return
        length = int(self.headers.get("Content-Length", "0"))
        self.server.objects[self.path] = self.rfile.read(length)
        self._reply(201)

    def do_COPY(self):
        if not self._authorized():
            self._reply(401)
            return
        source = self.headers.get("Source")
        credential = self.headers.get("Credential")
        if source is None or credential != "none":
            self._reply(400)
            return
        body = self.server.objects.get(urlsplit(source).path)
        if body is None:
            self._reply(404)
            return
        self.server.objects[self.path] = body + (
            b"corrupt" if self.server.corrupt_copy else b""
        )
        self._reply(201)

    def do_GET(self):
        if not self._authorized():
            self._reply(401)
            return
        body = self.server.objects.get(self.path)
        self._reply(404 if body is None else 200, body or b"")

    def do_DELETE(self):
        if not self._authorized():
            self._reply(401)
            return
        existed = self.server.objects.pop(self.path, None) is not None
        self._reply(204 if existed else 404)


@contextmanager
def webdav_tpc_server(corrupt_copy=False):
    server = ThreadingHTTPServer((HOST, 0), WebdavTpcHandler)
    server.objects = {}
    server.corrupt_copy = corrupt_copy
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{HOST}:{server.server_port}/fixture"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _extend_tpc_fixture(command, fixture):
    if fixture is not None:
        command.extend(["--tpc-fixture", fixture])


def _extend_webdav_endpoints(command, webdav):
    for endpoint in webdav or ():
        command.extend(["--also", endpoint])


def _extend_disruption_authority(command, row, source):
    if row == "TPC-009":
        command.extend(["--allow-disrupt", "--confirm-target", source])


def _extend_negative_verification(command, row, verify):
    if verify:
        command.extend(["--verify-negative", row])


def _tpc_environment(bearer):
    environment = _clean_environment()
    if bearer is not None:
        environment["BEARER_TOKEN"] = bearer
    return environment


def _run(tmp_path, source, destination, row, fixture=None, webdav=None,
         bearer=None, verify=False):
    _require_xrd()
    output = tmp_path / row.lower()
    profile = "full" if row.startswith("CLM-") else "tpc"
    command = [
        str(XRD), "conform", "accept", source,
        "--also", destination, "--profile", profile, "--only", row,
        "--allow-mutate", "--scratch", "/phase118-tpc-scratch",
        "--budget", "boundary", "--fail-on", "divergent",
        "--wall-seconds", "30", "--request-limit", "128",
        "--byte-limit", "1048576", "--out", str(output),
    ]
    _extend_tpc_fixture(command, fixture)
    _extend_webdav_endpoints(command, webdav)
    _extend_disruption_authority(command, row, source)
    _extend_negative_verification(command, row, verify)
    result = subprocess.run(
        command, text=True, capture_output=True, timeout=45,
        env=_tpc_environment(bearer), check=False,
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {item["id"]: item for item in report["results"]}


@pytest.mark.registry_server("root-tpc")
def test_native_tpc_lands_byte_exact(tmp_path):
    """Success: a true native pull lands deterministic source bytes exactly."""
    endpoint = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    result, rows = _run(tmp_path, endpoint, endpoint, "TPC-001")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-001"]["verdict"] == "conformant"
    assert rows["TPC-001"]["reason"] == "native-tpc-byte-exact"


@pytest.mark.registry_server("root-tpc")
def test_tpc_numeric_claim_agrees_with_working_transfer(tmp_path):
    """Success: non-zero Qconfig claims agree with observed exact bytes."""
    endpoint = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    result, rows = _run(tmp_path, endpoint, endpoint, "TPC-008")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-008"]["verdict"] == "conformant"


@pytest.mark.registry_server("root-tpc")
def test_tpc_rendezvous_key_is_single_use(tmp_path):
    """Security-negative: the second consume of one key is refused exactly."""
    endpoint = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    result, rows = _run(tmp_path, endpoint, endpoint, "TPC-002")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-002"]["verdict"] == "conformant"
    assert rows["TPC-002"]["reason"] == \
        "tpc-rendezvous-key-consumed-once"


@pytest.mark.registry_server("root-tpc")
def test_unknown_tpc_cgi_is_ignored(tmp_path):
    """Success: an unknown tpc.* field cannot alter source selection or bytes."""
    endpoint = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    result, rows = _run(tmp_path, endpoint, endpoint, "TPC-007")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-007"]["verdict"] == "conformant"


def test_tpc_enabled_claim_cannot_hide_a_refused_transfer(tmp_path):
    """Security-negative: advertised TPC plus refusal is a divergence."""
    with TpcClaimServer(1) as server:
        endpoint = f"root://{HOST}:{server.port}//fixture"
        result, rows = _run(
            tmp_path, endpoint, endpoint, "TPC-008", verify=True,
        )
    assert result.returncode == 1
    assert rows["TPC-008"]["verdict"] == "divergent"
    assert rows["TPC-008"]["reason"] == \
        "qconfig-tpc-claim-behavior-mismatch"


@pytest.mark.parametrize(
    ("row", "reason"),
    (("TPC-001", "native-tpc-failed"),
     ("TPC-002", "tpc-key-registration-failed"),
     ("TPC-007", "unknown-tpc-cgi-altered-or-refused-valid-operation")),
)
def test_refused_rendezvous_is_verified_for_owned_tpc_contract(
        tmp_path, row, reason):
    """Security-negative: a claimed endpoint cannot refuse its owned flow."""
    with TpcClaimServer(1) as server:
        endpoint = f"root://{HOST}:{server.port}//fixture"
        result, rows = _run(
            tmp_path, endpoint, endpoint, row, verify=True,
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[row]["verdict"] == "divergent", rows[row]
    assert rows[row]["reason"] == reason


def test_tpc_disabled_claim_agrees_with_terminal_refusal(tmp_path):
    """Error path: a numeric zero claim agrees with a hard TPC-only refusal."""
    with TpcClaimServer(0) as server:
        endpoint = f"root://{HOST}:{server.port}//fixture"
        result, rows = _run(tmp_path, endpoint, endpoint, "TPC-008")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-008"]["verdict"] == "conformant"


@pytest.mark.registry_server("root-tpc")
def test_clm009_composes_checksum_and_tpc_claim_evidence(tmp_path):
    """Success: selecting CLM-009 alone gathers both behavioral proofs."""
    endpoint = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    result, rows = _run(tmp_path, endpoint, endpoint, "CLM-009")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CLM-009"]["verdict"] == "conformant"
    assert rows["CLM-009"]["reason"] == \
        "qconfig-claims-match-checksum-and-tpc-behaviour"


def test_clm009_rejects_known_bad_capability_evidence(tmp_path):
    """Security-negative: one observed false claim cannot become unknown."""
    with TpcClaimServer(1) as server:
        endpoint = f"root://{HOST}:{server.port}//fixture"
        result, rows = _run(
            tmp_path, endpoint, endpoint, "CLM-009", verify=True,
        )
    assert result.returncode == 1
    assert rows["CLM-009"]["verdict"] == "divergent"
    assert rows["CLM-009"]["reason"] == \
        "qconfig-claim-behaviour-mismatch"


@pytest.mark.registry_server("root-tpc")
def test_tpc_source_auth_refusal_is_terminal_and_leaves_no_partial(tmp_path):
    """Error path: source denial is exact, bounded, and aborts destination POSC."""
    destination = (
        f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    )
    with TpcClaimServer(1, refusal=3010) as source_server:
        source = f"root://{HOST}:{source_server.port}//fixture"
        result, rows = _run(
            tmp_path, source, destination, "TPC-003", "source-denied",
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-003"]["verdict"] == "conformant"
    assert rows["TPC-003"]["reason"] == \
        "tpc-source-auth-refusal-terminal-no-partial"


@pytest.mark.registry_server("root-tpc")
def test_tpc_source_wrong_refusal_is_a_verified_divergence(tmp_path):
    """Security-negative: Unsupported cannot masquerade as authorization."""
    destination = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    with TpcClaimServer(1) as source_server:
        source = f"root://{HOST}:{source_server.port}//fixture"
        result, rows = _run(
            tmp_path, source, destination, "TPC-003", "source-denied",
            verify=True,
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TPC-003"]["verdict"] == "divergent", rows["TPC-003"]
    assert rows["TPC-003"]["reason"] == \
        "tpc-source-refusal-retried-misclassified-or-partial"


@pytest.mark.registry_server("root-tpc")
def test_tpc_destination_abort_discards_posc_without_committing_close(tmp_path):
    """Error path: a fired destination abort leaves no visible POSC object."""
    source = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    with AbortDestination() as destination_server:
        destination = f"root://{HOST}:{destination_server.port}//fixture"
        result, rows = _run(
            tmp_path, source, destination, "TPC-004", "destination-abort",
        )
        close_seen = destination_server.close_seen
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-004"]["verdict"] == "conformant"
    assert rows["TPC-004"]["reason"] == \
        "tpc-posc-abort-left-no-destination"
    assert close_seen == 0


@pytest.mark.registry_server("root-tpc")
def test_tpc_destination_that_ignores_abort_is_a_verified_divergence(tmp_path):
    """Security-negative: a fixture that commits cannot satisfy POSC abort."""
    endpoint = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    result, rows = _run(
        tmp_path, endpoint, endpoint, "TPC-004", "destination-abort",
        verify=True,
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TPC-004"]["verdict"] == "divergent", rows["TPC-004"]
    assert rows["TPC-004"]["reason"] == \
        "tpc-posc-abort-left-partial-or-succeeded"


@pytest.mark.registry_server("tpc-source-guard")
def test_tpc_egress_guard_refuses_before_contacting_source(tmp_path):
    """Security-negative: a blocked source name is never dialled or planted."""
    destination = f"root://{url_host(HOST)}:{TPC_SRC_GUARD_PORT}//fixture"
    with TpcClaimServer(1) as source_server:
        source = f"root://{HOST}:{source_server.port}//fixture"
        result, rows = _run(
            tmp_path, source, destination, "TPC-009", "egress-blocked",
        )
        attempts = source_server.tpc_attempts
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-009"]["verdict"] == "conformant"
    assert rows["TPC-009"]["reason"] == \
        "tpc-egress-guard-refused-before-source-contact"
    assert attempts == 0


@pytest.mark.registry_server("root-tpc")
def test_missing_tpc_egress_guard_is_a_verified_divergence(tmp_path):
    """Security-negative: an ordinary destination contacts the blocked source."""
    destination = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    with TpcClaimServer(1) as source_server:
        source = f"root://{HOST}:{source_server.port}//fixture"
        result, rows = _run(
            tmp_path, source, destination, "TPC-009", "egress-blocked",
            verify=True,
        )
        attempts = source_server.tpc_attempts
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TPC-009"]["verdict"] == "divergent", rows["TPC-009"]
    assert rows["TPC-009"]["reason"] == \
        "tpc-egress-guard-bypassed-or-source-contacted"
    assert attempts > 0


@pytest.mark.registry_server("root-tpc")
def test_webdav_tpc_with_bearer_matches_native_tpc_bytes(tmp_path):
    """Success: WebDAV pull and native TPC land the same planted bytes."""
    root = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    with webdav_tpc_server() as web:
        result, rows = _run(
            tmp_path, root, root, "TPC-006", "native-and-webdav",
            webdav=(web, web), bearer="phase118-bearer",
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-006"]["verdict"] == "conformant"
    assert rows["TPC-006"]["reason"] == \
        "native-and-webdav-tpc-byte-exact"


@pytest.mark.registry_server("root-tpc")
def test_webdav_tpc_requires_a_discovered_bearer(tmp_path):
    """Error: the fixture stays explicitly inconclusive without a bearer."""
    root = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    with webdav_tpc_server() as web:
        result, rows = _run(
            tmp_path, root, root, "TPC-006", "native-and-webdav",
            webdav=(web, web),
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TPC-006"]["verdict"] == "inconclusive"
    assert rows["TPC-006"]["reason"] == "fixture-required:webdav-bearer"


@pytest.mark.registry_server("root-tpc")
def test_webdav_tpc_detects_bytes_that_differ_from_native(tmp_path):
    """Security-negative: a successful corrupt COPY is never graded green."""
    root = f"root://{url_host(HOST)}:{ROOT_TPC_NGINX_PORT}//fixture"
    with webdav_tpc_server(corrupt_copy=True) as web:
        result, rows = _run(
            tmp_path, root, root, "TPC-006", "native-and-webdav",
            webdav=(web, web), bearer="phase118-bearer", verify=True,
        )
    assert result.returncode == 1
    assert rows["TPC-006"]["verdict"] == "divergent"
    assert rows["TPC-006"]["reason"] == "webdav-tpc-byte-mismatch"

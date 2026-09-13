"""Pytest wrapper for the self-contained CVMFS live scenarios.

`cmdscripts/cvmfs_live.py` holds six of the ten scenarios the CVMFS chapter
cites as its evidence (manifest TTL/revalidate, origin failover, kernel
keepalive on the wire, shared cache, connection reuse, minimal fill) — and
after the bash fleet was dissolved it was reachable only by hand, exactly the
gap `test_cmd_cvmfs_verify.py` was written to close for its sibling. Without
this wrapper a scenario could be dropped from `SCENARIOS`, or start failing,
with no suite anywhere going red.
"""

import http.client
import http.server
import os
from pathlib import Path
import threading

import pytest

from cmdscripts import cvmfs_live
from cmdscripts.live_common import LiveFailure, config_listen_ports
from ephemeral_port import free_port

pytestmark = [pytest.mark.xdist_group("cmd-cvmfs_live"), pytest.mark.slow]

EXPECTED_SCENARIOS = {
    "connection-reuse",
    "failover",
    "keepalive",
    "manifest",
    "minimal",
    "shared-cache",
}


def test_cvmfs_live_scenario_set_is_pinned():
    """Every scenario docs/04-protocols/cvmfs.md §11.1 cites still exists."""
    assert set(cvmfs_live.SCENARIOS) == EXPECTED_SCENARIOS
    assert all(callable(fn) for fn in cvmfs_live.SCENARIOS.values())


def test_cvmfs_live_rejects_unknown_scenario():
    """An unknown scenario name is refused by the parser, never dispatched."""
    with pytest.raises(SystemExit) as excinfo:
        cvmfs_live.main(["../etc/passwd"])
    assert excinfo.value.code == 2


def test_cvmfs_live_failure_is_never_reported_green(monkeypatch):
    """A failing scenario exits non-zero — a red must not be able to read green."""
    def boom(_nginx):
        raise LiveFailure("origin served corrupt bytes")

    monkeypatch.setitem(cvmfs_live.SCENARIOS, "minimal", boom)
    assert cvmfs_live.main(["minimal"]) == 2


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(EXPECTED_SCENARIOS))
def test_cvmfs_live_scenario(scenario: str):
    nginx = _require_live_cvmfs()
    assert cvmfs_live.SCENARIOS[scenario](nginx) == 0


def _require_live_cvmfs():
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live cvmfs scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    return nginx


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 — stdlib handler contract
        body = b"x" * 64
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture()
def keepalive_server():
    server = http.server.HTTPServer(("127.0.0.1", free_port()), _Handler)  # net-literal-allow: loopback test listener
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_drain_permits_a_second_request_on_one_socket(keepalive_server):
    """`_drain` reads the body, so the socket stays usable for the next request.

    The keepalive scenario's whole point is that ONE socket carries 200 requests
    plus a reject.  Without the body read the failure is client-side
    (`ResponseNotReady`), not a server keepalive defect — so this pin is what
    keeps the scenario honest about what it measures.
    """
    host, port = keepalive_server
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        for _ in range(3):
            connection.request("GET", "/obj")
            assert cvmfs_live._drain(connection) == 200
    finally:
        connection.close()


def test_undrained_response_breaks_the_socket(keepalive_server):
    """Negative control: the pin above is not vacuous.

    Skipping the body read is exactly what the scenario used to do, and it makes
    the very next request on the connection raise — silently swallowed by the
    scenario's `except http.client.HTTPException` into a bare FAIL line.
    """
    host, port = keepalive_server
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        connection.request("GET", "/obj")
        assert connection.getresponse().status == 200  # deliberately undrained
        connection.request("GET", "/obj")
        with pytest.raises(http.client.ResponseNotReady):
            connection.getresponse()
    finally:
        connection.close()


def test_multi_listen_config_reaps_every_port(tmp_path):
    """A leaked squatter on a config's SECOND listen must also be reaped.

    `start_nginx` is handed one port (the one it polls for readiness); the
    keepalive scenario's config binds two.  Reaping only the polled port left the
    other squatted and nginx died with "still could not bind()" — invisible while
    each scenario owned distinct absolute ports.
    """
    config = tmp_path / "nginx.conf"
    config.write_text(
        "http {\n"
        "  server { listen 127.0.0.1:19001 so_keepalive=60s:10s:6 backlog=2048; }\n"
        "  server { listen 127.0.0.1:19002; }\n"
        "  server { listen [::1]:19003; }\n"
        "}\n"  # net-literal-allow: config-listener literals are the reaper subject
    )
    assert config_listen_ports(config) == [19001, 19002, 19003]

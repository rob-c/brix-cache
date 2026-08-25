"""Minimal Kubernetes init-container and independently observed sidecar example."""

import os
import urllib.request

import pytest

from brixtest import Placement, case, endpoint, server, task, tcp

pytestmark = pytest.mark.skipif(
    os.environ.get("BRIXTEST_EXAMPLE_MINIKUBE_GROUPS") != "1",
    reason="set BRIXTEST_EXAMPLE_MINIKUBE_GROUPS=1 for the grouped Pod example",
)

IMAGE = (
    "python@sha256:"
    "ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a"
)
GROUP = "http_stack"
PLACEMENT = Placement(backend="kubernetes", image=IMAGE, group=GROUP)
PREPARE = task(
    "prepare_job", command=("python3", "-c", "print('prepared')"),
    placement=Placement(backend="kubernetes", image=IMAGE),
)
SEED = task(
    "seed_group", command=("python3", "-c", "print('seeded')"), phase="init",
    placement=PLACEMENT,
)


def _http_server(name: str, message: str):
    source = (
        "import http.server,sys\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  data=sys.argv[2].encode();self.send_response(200);self.end_headers();self.wfile.write(data)\n"
        " def log_message(self,*args): pass\n"
        "http.server.ThreadingHTTPServer(('0.0.0.0',int(sys.argv[1])),H).serve_forever()"
    )
    return server(
        name, command=("python3", "-u", "-c", source, "{http_port}", message),
        endpoints=(endpoint("http", scheme="http"),), readiness=tcp("http"),
        placement=PLACEMENT,
    )


ORIGIN = _http_server("group_origin", "origin")
MONITOR = _http_server("group_monitor", "monitor")


@case(PREPARE, SEED, ORIGIN, MONITOR, backend="minikube", keep="never")
def test_init_and_sidecar_members_need_only_a_shared_group_name(run):
    origin = run.server(ORIGIN)
    monitor = run.server(MONITOR)
    with urllib.request.urlopen(origin.url(role="http"), timeout=5) as response:
        assert response.read() == b"origin"
    with urllib.request.urlopen(monitor.url(role="http"), timeout=5) as response:
        assert response.read() == b"monitor"
    assert origin.replicas[0].uid == monitor.replicas[0].uid
    assert run.task(PREPARE).ok and "prepared" in run.task(PREPARE).stdout
    assert run.task(SEED).ok and "seeded" in run.task(SEED).stdout

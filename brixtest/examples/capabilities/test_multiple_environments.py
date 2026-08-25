"""Minimal same-context, cross-namespace service-discovery example."""

import os
import urllib.request

import pytest

from brixtest import Placement, case, endpoint, environment, server, tcp

pytestmark = pytest.mark.skipif(
    os.environ.get("BRIXTEST_EXAMPLE_MINIKUBE_ENVIRONMENTS") != "1",
    reason="set BRIXTEST_EXAMPLE_MINIKUBE_ENVIRONMENTS=1 for this Minikube example",
)

IMAGE = (
    "python@sha256:"
    "ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a"
)
FRONT = environment("front", backend="kubernetes", namespace="front")
BACK = environment("back", backend="kubernetes", namespace="back")

HTTP_SOURCE = (
    "import http.server,sys\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    " def do_GET(self):\n"
    "  data=sys.argv[2].encode();self.send_response(200);self.end_headers();self.wfile.write(data)\n"
    " def log_message(self,*args): pass\n"
    "http.server.ThreadingHTTPServer(('0.0.0.0',int(sys.argv[1])),H).serve_forever()"
)
ORIGIN = server(
    "environment_origin",
    command=("python3", "-u", "-c", HTTP_SOURCE, "{http_port}", "origin-ready"),
    endpoints=(endpoint("http", scheme="http"),), readiness=tcp("http"),
    image=IMAGE, placement=Placement(environment=BACK),
)
PROXY_SOURCE = (
    "import http.server,sys,urllib.request\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    " def do_GET(self):\n"
    "  data=urllib.request.urlopen(sys.argv[2],timeout=3).read();self.send_response(200);"
    "self.end_headers();self.wfile.write(data)\n"
    " def log_message(self,*args): pass\n"
    "http.server.ThreadingHTTPServer(('0.0.0.0',int(sys.argv[1])),H).serve_forever()"
)
PROXY = server(
    "environment_proxy",
    command=("python3", "-u", "-c", PROXY_SOURCE, "{http_port}", ORIGIN.url("http")),
    endpoints=(endpoint("http", scheme="http"),), readiness=tcp("http"),
    image=IMAGE, depends_on=(ORIGIN,), placement=Placement(environment=FRONT),
)


@case(FRONT, BACK, ORIGIN, PROXY, backend="minikube", keep="never")
def test_environment_names_are_the_only_cluster_topology_boilerplate(run):
    with urllib.request.urlopen(run.server(PROXY).url("http"), timeout=5) as response:
        assert response.read() == b"origin-ready"
    assert run.server(ORIGIN).metadata["environment"] == "back"
    assert run.server(PROXY).metadata["environment"] == "front"

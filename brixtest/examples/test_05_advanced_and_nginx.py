"""Examples 17-20: readiness, dependencies, explicit placement, and nginx."""

import shutil
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from brixtest import (
    binary,
    case,
    file_artifact,
    http_endpoint,
    http_probe,
    immediate,
    process,
    server,
    static_config,
    tcp,
    template_config,
    text_artifact,
)

HERE = Path(__file__).parent
SLEEPER = file_artifact("example_sleeper", HERE / "support" / "sleeper.py")
STATIC_SERVICE = server(
    "static_service",
    command=[sys.executable, "{artifact_example_sleeper}", "{config}"],
    config=static_config("configs/static.conf", destination="static.conf"),
    ports=["control"],
    env={"EXAMPLE_MODE": "immediate"},
    readiness=immediate(),
)


@case(servers=[STATIC_SERVICE], artifacts=[SLEEPER], keep="never")
def test_17_static_config_and_immediate_readiness(run):
    service = run.server(STATIC_SERVICE)
    deadline = time.monotonic() + 5
    while "mode=immediate" not in service.log.read_text(errors="replace"):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert service.config.read_text() == (HERE / "configs" / "static.conf").read_text()


HTTP_SERVER = file_artifact("dependency_http_server", HERE / "support" / "http_server.py")
UPSTREAM = server(
    "upstream",
    command=[sys.executable, "{artifact_dependency_http_server}", "{config}"],
    config=template_config("configs/http.json.in", destination="upstream.json"),
    ports=["http"], env={"BRIXTEST_EXAMPLE_BODY": "upstream"}, readiness=tcp("http"),
)
DOWNSTREAM = server(
    "downstream",
    command=[sys.executable, "{artifact_dependency_http_server}", "{config}"],
    config=template_config("configs/http.json.in", destination="downstream.json"),
    ports=["http"], env={"BRIXTEST_EXAMPLE_BODY": "downstream"},
    readiness=tcp("http"), depends_on=[UPSTREAM],
)


@case(servers=[UPSTREAM, DOWNSTREAM], artifacts=[HTTP_SERVER], keep="never")
def test_18_server_dependency_graph(run):
    upstream = urllib.request.urlopen(run.server(UPSTREAM).url(role="http"), timeout=5).read()
    downstream = urllib.request.urlopen(run.server(DOWNSTREAM).url(role="http"), timeout=5).read()
    assert (upstream, downstream) == (b"upstream", b"downstream")


@case(backend="local", isolation=process(), timeout=15, keep="never")
def test_19_explicit_local_process_isolation(run):
    assert run.backend == "local"
    assert run.root.parent.name != "examples"
    run.metrics.tag("isolation", "process")


NGINX_PATH = shutil.which("nginx")
NGINX = binary(
    "nginx", NGINX_PATH or "/usr/sbin/nginx",
    runtime_files={"/etc/passwd": "/etc/passwd", "/etc/group": "/etc/group"},
)
NGINX_PAGE = text_artifact(
    "nginx_page",
    "<!doctype html><title>BriXTest nginx</title><h1>served by nginx</h1>\n",
    filename="index.html",
)
NGINX_SERVER = server(
    "nginx_site",
    command=[
        NGINX, "-e", "stderr", "-p", "{workspace}/", "-c", "{config}",
    ],
    config=template_config("configs/nginx.conf.in", destination="nginx.conf"),
    endpoints=[http_endpoint()], probe=http_probe(timeout=10),
)


@pytest.mark.skipif(NGINX_PATH is None, reason="the nginx executable is not installed")
@case(
    servers=[NGINX_SERVER], artifacts=[NGINX_PAGE], binaries=[NGINX],
    timeout=30, keep="never",
)
def test_20_nginx_serves_html_page(run):
    service = run.server(NGINX_SERVER)
    response = urllib.request.urlopen(service.url(role="http"), timeout=5)
    body = response.read().decode()
    assert response.status == 200
    assert response.headers.get_content_type() == "text/html"
    assert "<h1>served by nginx</h1>" in body

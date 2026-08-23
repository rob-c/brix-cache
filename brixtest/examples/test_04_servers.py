"""Examples 13-16: backend-neutral server endpoints and rendered configs."""

import json
import sys
import urllib.request
from pathlib import Path

from brixtest import (
    binary,
    case,
    client,
    command,
    configs,
    file_artifact,
    http_endpoint,
    http_probe,
    load_template,
    server,
    server_config,
)

HERE = Path(__file__).parent
PYTHON_SERVER = binary("example_python_server", sys.executable)
HTTP_SERVER = file_artifact("example_http_server", HERE / "support" / "http_server.py")
ORIGIN_CONFIG = load_template("configs/http-user.json.in").fill(
    filename="origin.json", message="hello from the BriXTest example server",
)
ORIGIN_METADATA = server_config(
    "owner=brixtest-example\n", "metadata.conf", template=False,
)
ORIGIN = server(
    "python_origin",
    binary=PYTHON_SERVER,
    args=["{artifact_example_http_server}", "{config}"],
    configs=configs(ORIGIN_CONFIG, ORIGIN_METADATA, primary="origin.json"),
    endpoints=[http_endpoint()],
    probe=http_probe(timeout=10),
    scope="session",
)


@case(servers=[ORIGIN], artifacts=[HTTP_SERVER], keep="never")
def test_13_python_http_server(run):
    response = urllib.request.urlopen(run.server(ORIGIN).url(role="http"), timeout=5)
    assert response.status == 200
    assert response.read() == b"hello from the BriXTest example server"


HTTP_CLIENT = client(
    "http_reader",
    command=command(
        sys.executable, "-c",
        "import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1]).read().decode())",
        "{server_python_origin_url}",
        timeout=10, output_limit=64 << 10,
    ),
)


@case(servers=[ORIGIN], clients=[HTTP_CLIENT], artifacts=[HTTP_SERVER], keep="never")
def test_14_backend_neutral_client_url(run):
    result = run.client(HTTP_CLIENT).run()
    assert result.stdout.strip() == "hello from the BriXTest example server"


@case(servers=[ORIGIN], artifacts=[HTTP_SERVER], keep="never")
def test_15_named_port_and_rendered_config(run):
    service = run.server("python_origin")
    rendered = json.loads(service.config.read_text())
    assert service.address("http") == ("127.0.0.1", service.port("http"))
    assert rendered["host"] == service.host
    assert rendered["port"] == service.port("http")
    assert service.read_config("metadata.conf") == "owner=brixtest-example\n"


ENV_ORIGIN = server(
    "environment_origin",
    binary=PYTHON_SERVER,
    args=["{artifact_example_http_server}", "{config}"],
    config=load_template("configs/http-user.json.in").fill(
        filename="environment.json", message="config fallback body",
    ),
    endpoints=[http_endpoint()],
    env={"BRIXTEST_EXAMPLE_BODY": "body supplied by server env"},
    probe=http_probe(timeout=10),
)


@case(servers=[ENV_ORIGIN], artifacts=[HTTP_SERVER], keep="never")
def test_16_server_environment(run):
    response = urllib.request.urlopen(run.server(ENV_ORIGIN).url(role="http"), timeout=5)
    assert response.read() == b"body supplied by server env"

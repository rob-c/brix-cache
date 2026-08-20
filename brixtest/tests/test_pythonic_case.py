"""Executable quick-start example and end-to-end framework success test."""

import hashlib
import os
import sys
from pathlib import Path

from brixtest import (
    binary,
    case,
    client,
    file_artifact,
    noise,
    server,
    tcp,
    template_config,
)

HERE = Path(__file__).parent
python = binary("python", sys.executable)
origin = server(
    "origin",
    command=[python, "{artifact_server_code}", "{config}"],
    config=template_config(
        "../configs/servers/echo.json.in", destination="origin.json"
    ),
    ports=["http"],
    readiness=tcp("http", timeout=10),
)
reader = client(
    "reader",
    command=[
        python, "-c",
        "import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1]).read().decode())",
        "{server_origin_url}",
    ],
)


@case(
    servers=[origin], clients=[reader], binaries=[python],
    artifacts=[
        file_artifact("server_code", HERE / "support" / "config_server.py"),
        noise("random_input", size=2 * 1024 * 1024, seed=2026),
    ],
    timeout=30, keep="never",
)
def test_pythonic_server_client_case(run):
    assert os.getpid() != int(os.environ["BRIXTEST_CONTROLLER_PID"])
    endpoint = run.server(origin)
    assert endpoint.url(role="http").startswith("http://127.0.0.1:")
    with run.metrics.timer("example.download"):
        response = run.client(reader).run()
    run.metrics.gauge("example.response_bytes", len(response.stdout), unit="bytes")
    assert response.stdout.strip() == "hello from BriXTest"

    payload = run.artifact("random_input")
    assert payload.size == 2 * 1024 * 1024
    assert hashlib.sha256(payload.path.read_bytes()).hexdigest() == payload.sha256

    captured = run.binary("python")
    assert captured.path != Path(sys.executable)
    assert captured.path.is_file()
    assert (run.root / "summary.json").is_file()

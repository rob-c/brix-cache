"""Opt-in live validation against the Docker-driven Minikube profile."""

import json
import os
import socket
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

if os.environ.get("BRIXTEST_MINIKUBE") != "1":
    pytest.skip("set BRIXTEST_MINIKUBE=1 or use tools/minikube_cluster.py test", allow_module_level=True)

from brixtest import (  # noqa: E402
    Placement, case, host_mapping, server, static_config, tcp, token_auth, tool,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = json.loads((ROOT / "k8s" / "minikube" / "cluster.json").read_text())
TOKENS = token_auth(secret="minikube-server-verification-secret")
AUTH_HOST = host_mapping(
    "minikube_auth", "auth.minikube.test", address="127.0.0.77",
    aliases=("alias.minikube.test",),
)
ECHO = server(
    "minikube_secure",
    command=[
        "/bin/sh", "-c",
        "getent hosts {host_minikube_auth} > /tmp/brixtest-response; "
        "getent hosts {host_minikube_auth_address} >> /tmp/brixtest-response; "
        "cat {auth_token_secret} >> /tmp/brixtest-response; "
        "exec /usr/bin/socat TCP-LISTEN:{port},fork,reuseaddr OPEN:/tmp/brixtest-response,rdonly",
    ],
    config=static_config("../../k8s/minikube/response.txt", destination="response.txt"),
    ports=["echo"], readiness=tcp("echo", timeout=60), image=CONFIG["server_image"],
)
AUTH_CLIENT = tool(
    "minikube_auth_client",
    command=[
        "/bin/sh", "-c",
        "getent hosts minikube-secure >/dev/null && "
        "test -n \"$BEARER_TOKEN\" && test -s \"$BEARER_TOKEN_FILE\" && "
        "test \"$BEARER_TOKEN\" = \"$(cat \"$BEARER_TOKEN_FILE\")\" && printf ready",
    ],
    placement=Placement(backend="kubernetes", image=CONFIG["server_image"]),
)


@case(
    servers=[ECHO], clients=[AUTH_CLIENT], auth=[TOKENS], hosts=[AUTH_HOST],
    backend="minikube",
    timeout=120, keep="never",
)
def test_minikube_projects_credentials_dns_and_forwarded_port(run):
    with socket.create_connection(run.server(ECHO).address("echo"), timeout=10) as connection:
        received = connection.recv(4096).decode()
    assert received.count(AUTH_HOST.hostname) >= 2
    assert run.auth(TOKENS).path("secret").read_text() in received
    assert run.tool(AUTH_CLIENT).run().stdout == "ready"

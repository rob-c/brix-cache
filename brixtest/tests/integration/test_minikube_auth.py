"""Opt-in live validation against the Docker-driven Minikube profile."""

import json
import os
import socket
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

if os.environ.get("BRIXTEST_MINIKUBE") != "1":
    pytest.skip(
        "set BRIXTEST_MINIKUBE=1 or use tools/minikube_cluster.py test", allow_module_level=True
    )

from brixtest import (  # noqa: E402
    Placement,
    case,
    host_mapping,
    kerberos_auth,
    server,
    static_config,
    tcp,
    tls_auth,
    token_auth,
    tool,
    voms_auth,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = json.loads((ROOT / "k8s" / "minikube" / "cluster.json").read_text())
TOKENS = token_auth(secret="minikube-server-verification-secret")
KERBEROS = kerberos_auth(name="minikube_kerberos")
TLS = tls_auth(name="minikube_tls", hostname="tls.auth.minikube.test")
VOMS = voms_auth(
    name="minikube_voms", vo="brixtest", hostname="gsi.auth.minikube.test",
)
AUTH_HOST = host_mapping(
    "minikube_auth",
    "auth.minikube.test",
    address="127.0.0.77",
    aliases=("alias.minikube.test",),
    libc=True,
)
TLS_HOST = host_mapping(
    "tls_rdns", TLS.hostname, address="127.0.0.78", libc=True,
)
GSI_HOST = host_mapping(
    "gsi_rdns", VOMS.hostname, address="127.0.0.79", libc=True,
)
ECHO = server(
    "minikube_secure",
    command=[
        "/bin/sh",
        "-c",
        (
            "getent hosts {host_minikube_auth} > /tmp/brixtest-response; "
            "getent hosts {host_minikube_auth_address} >> /tmp/brixtest-response; "
            "getent hosts {host_tls_rdns} >> /tmp/brixtest-response; "
            "getent hosts {host_tls_rdns_address} >> /tmp/brixtest-response; "
            "getent hosts {host_gsi_rdns} >> /tmp/brixtest-response; "
            "getent hosts {host_gsi_rdns_address} >> /tmp/brixtest-response; "
            "cat {auth_token_secret} >> /tmp/brixtest-response; "
            "exec /usr/bin/socat TCP-LISTEN:{port},fork,reuseaddr "
            "OPEN:/tmp/brixtest-response,rdonly"
        ),
    ],
    config=static_config("../../k8s/minikube/response.txt", destination="response.txt"),
    ports=["echo"],
    readiness=tcp("echo", timeout=60),
    image=CONFIG["server_image"],
)
AUTH_CLIENT = tool(
    "minikube_auth_client",
    command=[
        "/bin/sh",
        "-c",
        (
            "getent hosts minikube-secure >/dev/null && "
            "getent hosts auth.minikube.test >/dev/null && "
            "getent hosts 127.0.0.77 | grep -q auth.minikube.test && "
            'test -n "$BEARER_TOKEN" && test -s "$BEARER_TOKEN_FILE" && '
            'test "$BEARER_TOKEN" = "$(cat "$BEARER_TOKEN_FILE")" && printf ready'
        ),
    ],
    placement=Placement(backend="kubernetes", image=CONFIG["server_image"]),
)
PTY_CLIENT = tool(
    "minikube_pty_client",
    command=[
        "python3", "-c",
        (
            "import os,sys;"
            "print(os.isatty(0),os.isatty(1),os.isatty(2));"
            "print(sys.stdin.readline().strip())"
        ),
    ],
    input="hello from Minikube\n",
    mode="pty",
    placement=Placement(backend="kubernetes", image=CONFIG["helper_image"]),
)


@case(
    servers=[ECHO],
    clients=[AUTH_CLIENT, PTY_CLIENT],
    auth=[TOKENS, TLS, VOMS],
    hosts=[AUTH_HOST, TLS_HOST, GSI_HOST],
    backend="minikube",
    timeout=120,
    keep="never",
)
def test_minikube_projects_credentials_dns_and_forwarded_port(run):
    service = run.server(ECHO)
    service.fs.mkdir("state")
    service.fs.write_bytes("state/payload", b"\x00\xffBriX-MinKube")
    assert service.fs.read_bytes("state/payload") == b"\x00\xffBriX-MinKube"
    assert service.fs.stat("state/payload")["size"] == 14
    assert service.fs.list("state") == ("payload",)
    with socket.create_connection(service.address("echo"), timeout=10) as connection:
        received = connection.recv(4096).decode()
    assert received.count(AUTH_HOST.hostname) >= 2
    assert received.count(TLS_HOST.hostname) >= 2
    assert received.count(GSI_HOST.hostname) >= 2
    assert run.auth(TOKENS).path("secret").read_text() in received
    assert run.tool(AUTH_CLIENT).run().stdout == "ready"
    terminal = run.tool(PTY_CLIENT).run().stdout
    assert "True True True" in terminal
    assert "hello from Minikube" in terminal


@case(auth=[KERBEROS], backend="minikube", timeout=180, keep="never")
def test_minikube_manages_reachable_kerberos_authority(run):
    authority = run.auth(KERBEROS)
    assert authority.available()
    authority.stop()
    assert not authority.available()
    authority.start()
    assert authority.available()

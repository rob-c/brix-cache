"""Backend-neutral IPv6, UDP, and reverse-callback examples."""

import socket
import sys
import time

from brixtest import binary, case, endpoint, probe, server, tcp

PYTHON = binary(
    "network_python", path=sys.executable,
    image="python@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a",
    image_path="/usr/local/bin/python3",
)

IPV6 = server(
    "ipv6_echo",
    command=(
        PYTHON, "-u", "-c",
        "import socket,sys\n"
        "s=socket.socket(socket.AF_INET6);s.bind((sys.argv[1],int(sys.argv[2])));s.listen()\n"
        "while True:\n c,_=s.accept();c.sendall(c.recv(4096));c.close()",
        "{host}", "{port}",
    ),
    endpoints=(endpoint("echo", family="ipv6"),), readiness=tcp("echo"),
)


@case(IPV6, PYTHON, backend="auto", keep="never")
def test_ipv6_uses_a_real_socket(run):
    with socket.create_connection(run.server(IPV6).address("echo"), timeout=2) as client:
        client.sendall(b"ipv6")
        assert client.recv(16) == b"ipv6"


UDP = server(
    "udp_echo",
    command=(
        PYTHON, "-u", "-c",
        "import socket,sys\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],int(sys.argv[2])))\n"
        "while True:\n data,peer=s.recvfrom(65507);s.sendto(data,peer)",
        "{host}", "{echo_port}",
    ),
    endpoints=(endpoint("echo", protocol="udp"),), probe=probe("none"),
)


@case(UDP, PYTHON, backend="auto", keep="never")
def test_udp_has_the_same_service_surface(run):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.sendto(b"udp\x00\xff", run.server(UDP).address("echo"))
        assert client.recv(16) == b"udp\x00\xff"


CALLBACK = server(
    "callback",
    command=(
        PYTHON, "-u", "-c",
        "import socket,sys\n"
        "s=socket.socket();s.bind((sys.argv[1],int(sys.argv[2])));s.listen()\n"
        "while True:\n c,_=s.accept();print(c.recv(64).hex(),flush=True);c.close()",
        "{host}", "{callback_port}",
    ),
    endpoints=(endpoint("callback"),), readiness=tcp("callback"),
)
CALLER = server(
    "caller",
    command=(
        PYTHON, "-u", "-c",
        "import socket,sys,time\n"
        "c=socket.create_connection((sys.argv[1],int(sys.argv[2])));c.sendall(b'reverse');c.close()\n"
        "print('delivered',flush=True);time.sleep(300)",
        CALLBACK.host, CALLBACK.port("callback"),
    ),
    depends_on=(CALLBACK,), probe=probe("none"),
)


@case(CALLBACK, CALLER, PYTHON, backend="auto", keep="never")
def test_server_to_server_reverse_callback(run):
    expected = b"reverse".hex()
    deadline = time.monotonic() + 5
    while expected not in run.server(CALLBACK).read_log():
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert "delivered" in run.server(CALLER).read_log()

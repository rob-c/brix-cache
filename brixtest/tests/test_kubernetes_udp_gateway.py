"""Binary UDP gateway contracts for Kubernetes service access."""

import socket
import subprocess
import sys

import pytest

from brixtest.runtime import udp_gateway


def _arguments(kubectl):
    return udp_gateway._parser().parse_args([
        "--kubectl", str(kubectl), "--namespace", "case-one",
        "--target", "dns-server", "--target-host", "127.0.0.1",
        "--target-port", "5353", "--timeout", "1",
    ])


def test_gateway_preserves_binary_datagrams_through_shell_free_kubectl(tmp_path):
    kubectl = tmp_path / "kubectl"
    kubectl.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read()[::-1])\n")
    kubectl.chmod(0o755)
    process = subprocess.Popen(
        [sys.executable, "-m", "brixtest.runtime.udp_gateway", *(
            value for pair in (
                ("--kubectl", str(kubectl)), ("--namespace", "case-one"),
                ("--target", "dns-server"), ("--target-host", "127.0.0.1"),
                ("--target-port", "5353"), ("--timeout", "1"),
            ) for value in pair
        )],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    try:
        assert process.stdout is not None
        port = int(process.stdout.readline().rpartition(" ")[2])
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3)
        client.sendto(b"\x00payload\xff", ("127.0.0.1", port))
        assert client.recv(100) == b"\xffdaolyap\x00"
    finally:
        process.terminate()
        process.wait(timeout=3)


@pytest.mark.parametrize("field,value,message", [
    ("namespace", "case;touch", "DNS label"),
    ("target", "../pod", "DNS label"),
    ("target_host", "example.test", "loopback"),
    ("target_port", 0, "between 1 and 65535"),
])
def test_gateway_rejects_untrusted_routing_values(field, value, message, tmp_path):
    args = _arguments(tmp_path / "kubectl")
    setattr(args, field, value)
    with pytest.raises(ValueError, match=message):
        udp_gateway._validate(args)


def test_gateway_command_is_exact_argv_and_selects_filesystem_sidecar(tmp_path):
    command = udp_gateway._command(_arguments(tmp_path / "kubectl"))
    assert command[:5] == [str(tmp_path / "kubectl"), "-n", "case-one", "exec", "-i"]
    assert command[5:9] == [
        "deployment/dns-server", "-c", "brixtest-filesystem", "--",
    ]
    assert command[-3:] == ["127.0.0.1", "5353", "1.0"]

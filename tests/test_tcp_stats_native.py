"""Native socket accounting must measure transfers and fail without fake usage."""

import socket
import subprocess

import pytest

from ephemeral_port import free_port
from settings import HOST
from test_platform_linux_native import native_compile
from cmdscripts.compile_run import platform_host_name


@pytest.fixture(scope="module")
def tcp_stats_driver(native_compile):
    host = platform_host_name()
    libraries = ["-framework", "Security"] if host == "darwin" else []
    # FreeBSD's public TCP_INFO has no full-width cumulative byte counters.
    # Pin its explicit refusal contract instead of accepting invented counts.
    capability = ["-DBRIX_TEST_TCP_STATS_UNSUPPORTED=1"] if host == "freebsd" else []
    return native_compile("tcp-stats", _DRIVER,
                          [f"src/platform/{host}/posix_wrapper.c"],
                          ["-ffunction-sections", "-fdata-sections",
                           "-Wl,--gc-sections", *libraries, *capability])


def _check(binary, mode, connection=None):
    descriptor = connection.fileno() if connection is not None else -1
    inherited = (descriptor,) if descriptor >= 0 else ()
    result = subprocess.run([str(binary), mode, str(descriptor)], pass_fds=inherited,
                            capture_output=True, text=True, check=True, timeout=10)
    return result.stdout.strip()


def transfer_accounting_contract(tcp_stats_driver):
    """Observe the actual native PAL on a connected socket with known traffic."""
    with socket.socket() as listener:
        listener.bind((HOST, free_port()))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=5) as sender:
            peer, _ = listener.accept()
            with peer:
                sender.sendall(b"request")
                assert peer.recv(7) == b"request"
                peer.sendall(b"response")
                assert sender.recv(8) == b"response"
                return _check(tcp_stats_driver, "transfer", sender)


def test_tcp_stats_transfer_obeys_native_accounting_contract(tcp_stats_driver):
    expected = 'unsupported' if platform_host_name() == 'freebsd' else 'measured'
    assert transfer_accounting_contract(tcp_stats_driver) == expected


def test_tcp_stats_invalid_descriptor_clears_outputs(tcp_stats_driver):
    _check(tcp_stats_driver, "invalid")


def test_udp_socket_cannot_publish_tcp_usage(tcp_stats_driver):
    with socket.socket(type=socket.SOCK_DGRAM) as connection:
        _check(tcp_stats_driver, "invalid", connection)


def test_tcp_stats_null_output_is_refused(tcp_stats_driver):
    _check(tcp_stats_driver, "null")


_DRIVER = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/platform_api.h"
int main(int argc, char **argv) {
    assert(argc == 3);
    uint64_t sent = 123, received = 456;
    uint32_t rtt = 789;
    int fd = atoi(argv[2]);
    if (strcmp(argv[1], "null") == 0) {
        assert(brix_plat_tcp_stats(fd, NULL, &received, &rtt) == -1);
        assert(errno == EINVAL);
        return 0;
    }
    int result = brix_plat_tcp_stats(fd, &sent, &received, &rtt);
    if (strcmp(argv[1], "transfer") == 0) {
#if BRIX_TEST_TCP_STATS_UNSUPPORTED
        assert(result == -1 && errno == ENOTSUP);
        assert(sent == 0 && received == 0 && rtt == 0);
        puts("unsupported");
#else
        assert(result == 0 && sent >= 7 && received >= 8);
        puts("measured");
#endif
    } else {
        assert(result == -1);
        assert(sent == 0 && received == 0 && rtt == 0);
    }
    return 0;
}
'''

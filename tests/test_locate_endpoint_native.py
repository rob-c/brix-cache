"""Locate advertises the accepted endpoint, never a wildcard listener address."""
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def locate_endpoint_driver(native_compile):
    """Execute the production formatter with a controlled nginx address seam."""
    return native_compile("locate-endpoint", _DRIVER, extra=[
        "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])


@pytest.mark.parametrize("case", ["ipv4", "ipv6", "preferred", "failure", "short"])
def test_locate_materializes_local_address_before_advertising(locate_endpoint_driver, case):
    """Resolved endpoints, inspection errors and bounded output stay explicit."""
    result = subprocess.run([str(locate_endpoint_driver), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_DRIVER = r'''
/* net-literal-allow: controlled numeric endpoint formatting; no connections. */
#include "protocols/root/read/locate.c"
#include <assert.h>
#include <string.h>

static int refuse_address;
static unsigned address_calls;

ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *connection,
                                       ngx_str_t *text, ngx_uint_t include_port)
{
    (void) text; (void) include_port;
    address_calls++;
    if (refuse_address) return NGX_ERROR;
    if (connection->local_sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *) connection->local_sockaddr;
        assert(address->sin_addr.s_addr == htonl(INADDR_ANY));
        assert(inet_pton(AF_INET, "127.0.0.1", &address->sin_addr) == 1);
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *) connection->local_sockaddr;
        assert(IN6_IS_ADDR_UNSPECIFIED(&address->sin6_addr));
        assert(inet_pton(AF_INET6, "::1", &address->sin6_addr) == 1);
    }
    return NGX_OK;
}

const char *brix_host_identity(void) { return "native.example"; }

int main(int argc, char **argv)
{
    ngx_stream_brix_srv_conf_t conf = {0};
    ngx_connection_t connection = {0};
    struct sockaddr_in ipv4 = {0};
    struct sockaddr_in6 ipv6 = {0};
    char output[128];
    int result;
    int preferred;
    assert(argc == 2);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(1094);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(1094);
    connection.local_sockaddr = strcmp(argv[1], "ipv6") == 0
        ? (struct sockaddr *) &ipv6 : (struct sockaddr *) &ipv4;
    preferred = strcmp(argv[1], "preferred") == 0;
    refuse_address = strcmp(argv[1], "failure") == 0;
    result = locate_format_local(&conf, &connection, preferred, output,
                                 strcmp(argv[1], "short") == 0 ? 4 : sizeof(output));
    assert(address_calls == 1);
    if (refuse_address) {
        assert(result == -1);
    } else if (strcmp(argv[1], "short") == 0) {
        assert(result >= 4 && output[3] == '\0');
    } else {
        const char *expected = preferred ? "Srnative.example:1094"
            : strcmp(argv[1], "ipv6") == 0 ? "Sr[::1]:1094" : "Sr127.0.0.1:1094";
        assert(result == (int) strlen(expected) && strcmp(output, expected) == 0);
    }
    return 0;
}
'''

/*
 * Native regression for GridFTP passive transport-peer canonicalization.
 *
 * Exercises equivalent IPv4/mapped-IPv6 spellings, native IPv6 scope, ignored
 * ephemeral ports, and fail-closed malformed/unsupported inputs without nginx.
 */

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

#include "protocols/gridftp/ftp_peer_addr.h"


/* ---- Build one IPv4 test address ----
 * WHAT: Return an initialized IPv4 sockaddr for `text` and `port`.
 * WHY: Every comparison case must differ only in the field named by the test.
 * HOW: Zero the value, assign family/port, and require literal parsing success.
 */
static struct sockaddr_in
address4(const char *text, unsigned short port)
{
    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    assert(inet_pton(AF_INET, text, &address.sin_addr) == 1);
    return address;
}


/* ---- Build one IPv6 test address ----
 * WHAT: Return an initialized IPv6 sockaddr for `text`, `port`, and `scope`.
 * WHY: Native and mapped IPv6 cases need deterministic bytes and scope IDs.
 * HOW: Zero the value, assign metadata, and require literal parsing success.
 */
static struct sockaddr_in6
address6(const char *text, unsigned short port, uint32_t scope)
{
    struct sockaddr_in6 address;

    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_port = htons(port);
    address.sin6_scope_id = scope;
    assert(inet_pton(AF_INET6, text, &address.sin6_addr) == 1);
    return address;
}


/* ---- Exercise the complete peer-address security contract ----
 * WHAT: Return success only after every equality and refusal assertion holds.
 * WHY: Equivalent encodings must agree and malformed inputs must fail closed.
 * HOW: Construct controlled v4/v6 values, compare both directions, then probe
 * short, NULL, unknown-family, different-address, and different-scope inputs.
 */
int
main(void)
{
    struct sockaddr_in  control4 = address4("127.0.0.1", 2100);
    struct sockaddr_in  same4 = address4("127.0.0.1", 62000);
    struct sockaddr_in  other4 = address4("127.0.0.2", 62000);
    struct sockaddr_in6 mapped4 = address6("::ffff:127.0.0.1", 3300, 0);
    struct sockaddr_in6 control6 = address6("fe80::1234", 2100, 7);
    struct sockaddr_in6 same6 = address6("fe80::1234", 62000, 7);
    struct sockaddr_in6 other6 = address6("fe80::1235", 62000, 7);
    struct sockaddr_in6 scope6 = address6("fe80::1234", 62000, 8);
    struct sockaddr     unknown;

    memset(&unknown, 0, sizeof(unknown));
    unknown.sa_family = AF_UNSPEC;

    assert(brix_ftp_peer_addr_equal(
        (struct sockaddr *) &control4, sizeof(control4),
        (struct sockaddr *) &same4, sizeof(same4)) == 1);
    assert(brix_ftp_peer_addr_equal(
        (struct sockaddr *) &control4, sizeof(control4),
        (struct sockaddr *) &mapped4, sizeof(mapped4)) == 1);
    assert(brix_ftp_peer_addr_equal(
        (struct sockaddr *) &mapped4, sizeof(mapped4),
        (struct sockaddr *) &control4, sizeof(control4)) == 1);
    assert(brix_ftp_peer_addr_equal(
        (struct sockaddr *) &control4, sizeof(control4),
        (struct sockaddr *) &other4, sizeof(other4)) == 0);

    assert(brix_ftp_peer_addr_equal(
        (struct sockaddr *) &control6, sizeof(control6),
        (struct sockaddr *) &same6, sizeof(same6)) == 1);
    assert(brix_ftp_peer_addr_equal(
        (struct sockaddr *) &control6, sizeof(control6),
        (struct sockaddr *) &other6, sizeof(other6)) == 0);
    assert(brix_ftp_peer_addr_equal(
        (struct sockaddr *) &control6, sizeof(control6),
        (struct sockaddr *) &scope6, sizeof(scope6)) == 0);

    assert(brix_ftp_peer_addr_equal(
        (struct sockaddr *) &control4, sizeof(control4) - 1,
        (struct sockaddr *) &same4, sizeof(same4)) == 0);
    assert(brix_ftp_peer_addr_equal(
        NULL, 0, (struct sockaddr *) &same4, sizeof(same4)) == 0);
    assert(brix_ftp_peer_addr_equal(
        &unknown, sizeof(unknown),
        (struct sockaddr *) &same4, sizeof(same4)) == 0);
    return 0;
}

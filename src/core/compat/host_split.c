/*
 * host_split.c — parse "host[:port]" / "[ipv6][:port]" (see host_split.h).
 *
 * The bracketed-IPv6-aware authority parser the native client reimplements in
 * several places. ngx-free; libc only.
 */
#include "host_split.h"

#include <string.h>
#include <stdlib.h>

/* ---- Validate and store a decimal port string ----
 *
 * WHAT: Parses `port_str` as a decimal port, storing it into `*port` and
 *       returning 0 on success; returns -1 when the value is out of the valid
 *       1..65535 range (or non-numeric, which atoi maps to 0).
 *
 * WHY: The bracketed and plain paths both accept an explicit port with the
 *      identical accept/reject rule; centralising it keeps that boundary
 *      byte-for-byte consistent and out of the two split helpers.
 *
 * HOW:
 *   1. Convert with atoi (non-numeric leading input yields 0).
 *   2. Reject values <= 0 or > 65535.
 *   3. Publish the accepted value to `*port` and return 0.
 */
static int
brix_parse_port_str(const char *port_str, int *port)
{
    int p = atoi(port_str);
    if (p <= 0 || p > 65535) {
        return -1;
    }
    *port = p;
    return 0;
}

/* ---- Copy a bounded host substring into the caller's buffer ----
 *
 * WHAT: Copies `hlen` bytes from `src` into `host` and NUL-terminates it,
 *       returning 0 on success; returns -1 when `hlen` is empty or would not
 *       fit (including the terminator) in `hsz`.
 *
 * WHY: Every parse path applies the same empty-and-overflow guard before the
 *      copy; sharing it preserves the exact length boundaries and avoids
 *      duplicating the memcpy/terminate idiom.
 *
 * HOW:
 *   1. Reject an empty host or one whose length is >= the buffer size (leaving
 *      no room for the terminator).
 *   2. memcpy the bytes and write the trailing NUL.
 */
static int
brix_copy_host(char *host, size_t hsz, const char *src, size_t hlen)
{
    if (hlen == 0 || hlen >= hsz) {
        return -1;
    }
    memcpy(host, src, hlen);
    host[hlen] = '\0';
    return 0;
}

/* ---- Parse a bracketed IPv6 authority "[addr]" or "[addr]:port" ----
 *
 * WHAT: Extracts the bracket-delimited literal into `host` and resolves the
 *       trailing port (explicit or `default_port`), returning 0 on success and
 *       -1 for an unterminated literal, an unusable host length, a bad port,
 *       or junk after the closing bracket.
 *
 * WHY: Brackets disambiguate the address colons from the port colon; isolating
 *      this case keeps that special IPv6 handling separate from the plain
 *      host:port rule.
 *
 * HOW:
 *   1. Locate the closing ']'; a missing one is an unterminated literal.
 *   2. Copy the inner literal (length excludes both brackets) into `host`.
 *   3. If ':' follows ']', parse the explicit port; if the string ends there,
 *      use `default_port`; anything else after ']' is junk and rejected.
 */
static int
brix_split_bracketed(const char *in, char *host, size_t hsz, int *port,
                       int default_port)
{
    const char *rb = strchr(in, ']');
    if (rb == NULL) {
        return -1;   /* unterminated literal */
    }
    if (brix_copy_host(host, hsz, in + 1, (size_t) (rb - in - 1)) != 0) {
        return -1;
    }
    if (rb[1] == ':') {
        return brix_parse_port_str(rb + 2, port);
    }
    if (rb[1] == '\0') {
        *port = default_port;
        return 0;
    }
    return -1;   /* junk after ']' */
}

/* ---- Parse a plain authority "host" or "host:port" ----
 *
 * WHAT: Splits `in` on the last ':' into `host` and a port (or uses
 *       `default_port` when no colon is present), returning 0 on success and
 *       -1 for an unusable host length or a bad port.
 *
 * WHY: Handles the non-bracketed case, where the rightmost colon separates the
 *      port so that bare hostnames and IPv4 literals parse correctly.
 *
 * HOW:
 *   1. Find the last ':' with strrchr.
 *   2. With a colon: copy the leading host and parse the trailing port.
 *   3. Without a colon: copy the whole string as host and apply
 *      `default_port`.
 */
static int
brix_split_plain(const char *in, char *host, size_t hsz, int *port,
                   int default_port)
{
    const char *colon = strrchr(in, ':');
    if (colon != NULL) {
        if (brix_copy_host(host, hsz, in, (size_t) (colon - in)) != 0) {
            return -1;
        }
        return brix_parse_port_str(colon + 1, port);
    }
    if (brix_copy_host(host, hsz, in, strlen(in)) != 0) {
        return -1;
    }
    *port = default_port;
    return 0;
}

/* ---- Parse "host[:port]" / "[ipv6][:port]" into host and port ----
 *
 * WHAT: Validates the arguments then routes to the bracketed-IPv6 or plain
 *       authority parser, writing the host into `host`/`hsz` and the resolved
 *       port into `*port`; returns 0 on success and -1 on any malformed input.
 *
 * WHY: The single entry point the native client relies on for authority
 *      parsing; a leading '[' selects the IPv6-bracket grammar, everything else
 *      the plain grammar.
 *
 * HOW:
 *   1. Reject NULL pointers and a zero-sized host buffer.
 *   2. A leading '[' dispatches to the bracketed parser.
 *   3. Otherwise dispatch to the plain host:port parser.
 */
int
brix_split_host_port(const char *in, char *host, size_t hsz, int *port,
                       int default_port)
{
    if (in == NULL || host == NULL || hsz == 0 || port == NULL) {
        return -1;
    }

    /* Bracketed IPv6 literal: "[::1]" or "[::1]:port" — the brackets disambiguate
     * the address colons from the port colon, and are stripped from `host`. */
    if (in[0] == '[') {
        return brix_split_bracketed(in, host, hsz, port, default_port);
    }

    return brix_split_plain(in, host, hsz, port, default_port);
}

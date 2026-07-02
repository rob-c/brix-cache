/*
 * host_split.h — parse "host[:port]" / "[ipv6][:port]" (the PARSE side).
 *
 * WHAT: split an authority into an unbracketed host + a port, IPv6-literal aware.
 * WHY:  the native client reimplements this bracketed-IPv6 host:port split in ~5
 *       places (url.c, xrddiag, xrdmapc, mpxstats); this is the one ngx-free leaf
 *       they can share. (host_format.h is the inverse — the EMIT side.)
 * HOW:  pure libc string scan over a caller buffer; no ngx, no allocation. The
 *       server's net_target parser is ngx_str_t/pool-coupled, so it can't share
 *       this as-is today (a future ptr+len core could back both).
 */
#ifndef XROOTD_COMPAT_HOST_SPLIT_H
#define XROOTD_COMPAT_HOST_SPLIT_H

#include <stddef.h>

/*
 * Parse `in` = "host", "host:port", "[ipv6]", or "[ipv6]:port" into:
 *   host  ← the unbracketed host, NUL-terminated, into host[hsz]
 *   *port ← the explicit port, or `default_port` if none was given
 * Returns 0 on success; -1 on a malformed input: an unterminated "[..]", junk
 * after "]", an empty/oversized host, or an explicit port outside 1..65535.
 * Does NOT handle a leading "user@" — the caller strips that first.
 */
int xrootd_split_host_port(const char *in, char *host, size_t hsz,
                           int *port, int default_port);

#endif /* XROOTD_COMPAT_HOST_SPLIT_H */

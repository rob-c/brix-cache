/*
 * sd_xroot_fwd_key.h — parse a forwarding-proxy key into an origin target.
 *
 * WHAT: The ngx-free leaf of the forwarding root:// driver (sd_xroot_fwd.c).
 *       A client of a `forward://` export names the origin INSIDE the path
 *       (`/root://host:port//file`, the XrdPss forwarding convention); this
 *       header turns that key into {host, port, tls, remote path} and answers
 *       the operator's `permit=` host allowlist.
 * WHY:  The verdicts here decide which remote host a proxy will dial on a
 *       client's say-so, so they live in a pure function with a standalone
 *       unit test (tests/test_sd_xroot_fwd_key.c) rather than inside the
 *       nginx-coupled driver.
 * HOW:  libc string scanning over caller buffers; the host:port split is the
 *       shared core/compat/host_split.h and the host-pattern match is the TPC
 *       egress guard's brix_tpc_host_pattern_match, so a forwarded open and a
 *       TPC pull agree on what ".example.org" permits.
 */
#ifndef BRIX_SD_XROOT_FWD_KEY_H
#define BRIX_SD_XROOT_FWD_KEY_H

#include <stddef.h>

#define BRIX_SD_XROOT_FWD_HOST_MAX  256
#define BRIX_SD_XROOT_FWD_PATH_MAX  4096
#define BRIX_SD_XROOT_FWD_PORT_DEF  1094

typedef struct {
    char  host[BRIX_SD_XROOT_FWD_HOST_MAX];   /* unbracketed origin host */
    int   port;                               /* explicit or 1094 */
    int   tls;                                /* 1 = roots:// */
    char  path[BRIX_SD_XROOT_FWD_PATH_MAX];   /* absolute path ON the origin */
} brix_sd_xroot_fwd_target_t;

/*
 * Parse `key` — either the wire shape `/root://host[:port]//path` or the
 * VFS-shaped `/root:/host[:port]/path` (brix_candidate_append_req collapses
 * slash runs) — into *t.  Returns 0 on success or an errno:
 *   ENOENT       the first component names no "<scheme>:" — the client did
 *                not name an origin, so there is nothing to forward to
 *   ENOTSUP      a scheme other than root / roots
 *   EINVAL       an empty or malformed authority (host_split rules, or a
 *                character outside [A-Za-z0-9.-:[]])
 *   ENAMETOOLONG the host or the remote path overflows the target buffers
 * The remote path is always absolute ("/" when the key ends at the host).
 */
int brix_sd_xroot_fwd_parse_key(const char *key,
    brix_sd_xroot_fwd_target_t *t);

/*
 * Is `host` allowed by the space-separated `permit` list?  Each entry is
 * either an exact host or a leading-dot domain suffix (".example.org"), as
 * brix_tpc_host_pattern_match defines them.  Fails closed: an empty or NULL
 * list permits nothing.  Returns 1 = permitted, 0 = refused.
 */
int brix_sd_xroot_fwd_host_permitted(const char *permit, const char *host);

#endif /* BRIX_SD_XROOT_FWD_KEY_H */

#ifndef XROOTD_CMS_FORWARD_H
#define XROOTD_CMS_FORWARD_H

/*
 * forward.h — manager-side Plane B fan-out primitive.
 *
 * WHAT: encode a forwarded namespace op (chmod/mkdir/mkpath/mv/rm/rmdir/trunc)
 *       and transmit it to one data-node CMS connection, byte-exact with stock
 *       cmsd's forwarded request frames.
 * WHY:  the reusable core of manager fan-out: the manager calls this once per
 *       eligible node when a client mutates the namespace. The node executes it
 *       confined (see node_ops.c) and replies silent-on-success / kYR_error.
 * HOW:  xrootd_cms_rrdata_encode() builds the Pup payload; xrootd_cms_send_frame()
 *       writes the header+payload on the given connection. The caller chooses the
 *       streamid (its correlation key for aggregating replies) and the nodes.
 *
 * NOTE: the client trigger (manager-mode root:// mutation handler), eligible-node
 *       selection across workers, and reply aggregation are the remaining
 *       manager-side integration — see the Plane B design spec. This primitive is
 *       the byte-exact, unit-tested wire half they build on.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Encode + send forwarded op `code` (streamid as the caller's correlation key)
 * to one node connection `c`. ident/path are required; path2 (mv), mode
 * (chmod/mkdir/trunc-size), and opaque are op-dependent and may be NULL.
 * Returns NGX_OK on a full send, NGX_ERROR on an encode overflow or write error.
 */
ngx_int_t xrootd_cms_forward_to_node(ngx_connection_t *c, u_char code,
    uint32_t streamid, const char *ident, const char *path,
    const char *path2, const char *mode, const char *opaque);

#endif /* XROOTD_CMS_FORWARD_H */

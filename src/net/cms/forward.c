#include "cms_internal.h"
#include "forward.h"
#include "frame_io.h"
#include "rrdata.h"

/*
 * forward.c — manager-side Plane B fan-out primitive. See forward.h.
 *
 * This is the wire half of manager forwarding: encode a forwarded namespace op
 * with the byte-exact Pup codec (rrdata.c) and send it on a node connection. The
 * orchestration that selects nodes and aggregates replies is layered above.
 */

ngx_int_t
brix_cms_forward_to_node(ngx_connection_t *c, u_char code, uint32_t streamid,
    const char *ident, const char *path, const char *path2,
    const char *mode, const char *opaque)
{
    u_char  payload[NGX_BRIX_CMS_MAX_FRAME];
    int     plen;

    plen = brix_cms_rrdata_encode(code, ident, path, path2, mode, opaque,
                                    payload, sizeof(payload));
    if (plen < 0) {
        return NGX_ERROR;
    }

    return brix_cms_send_frame(c, streamid, code, 0, payload, (size_t) plen);
}

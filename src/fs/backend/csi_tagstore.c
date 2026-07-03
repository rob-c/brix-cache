/*
 * fs/backend/csi_tagstore.c — CSI handle lifecycle on the unified metadata
 * record (xmeta P3). See csi_tagstore.h for the engine contract; the
 * verify/update/flush logic lives in csi_verify.c.
 */

#include "csi_tagstore.h"
#include "fs/meta/xmeta_path.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int
brix_csi_open(brix_csi_t *c, const char *abs_path,
    uint32_t granule, int writable)
{
    size_t plen;

    if (c == NULL || abs_path == NULL || granule == 0) {
        errno = EINVAL;
        return BRIX_CSI_ERR;
    }
    plen = strlen(abs_path);
    if (plen == 0 || plen >= sizeof(c->path)) {
        errno = ENAMETOOLONG;
        return BRIX_CSI_ERR;
    }

    memset(c, 0, sizeof(*c));
    memcpy(c->path, abs_path, plen + 1);
    c->granule  = granule;
    c->writable = writable ? 1 : 0;

    if (writable) {
        return BRIX_CSI_OK;       /* the record is created/merged at flush */
    }

    /* Read handle: report whether there is anything verifiable, so the
     * caller can enforce csi_require at open. */
    {
        brix_xmeta_t xm;
        int rc = brix_xmeta_path_load(c->path, &xm);

        if (rc == BRIX_XMETA_ERR) {
            return BRIX_CSI_ERR;
        }
        if (rc == BRIX_XMETA_FOREIGN) {
            return BRIX_CSI_NOTAGS;
        }
        rc = (xm.have_blockcrc && xm.blockcrc != NULL)
             ? BRIX_CSI_OK : BRIX_CSI_NOTAGS;
        brix_xmeta_free(&xm);
        return rc;
    }
}

void
brix_csi_close(brix_csi_t *c)
{
    if (c == NULL) {
        return;
    }
    if (c->writable && c->dirty) {
        (void) brix_csi_flush(c);     /* best-effort; tags stay unset on
                                           failure (never falsely failing) */
    }
    free(c->local);
    memset(c, 0, sizeof(*c));
}

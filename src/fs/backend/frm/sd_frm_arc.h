/*
 * sd_frm_arc.h — dataset archiver MSS adapter (phase-115 W3.1, the OssArc analog)
 *
 * WHAT: a DECORATOR over any brix_mss_adapter_t (stub | exec | lib). Keys
 *       deeper than `depth` components belong to a DATASET (their first
 *       `depth` components); a dataset's files are written online one by one,
 *       and the moment its completion marker `.brix-dataset-complete` is
 *       committed the adapter seals every member into ONE store-only ZIP,
 *       migrates that single object, and writes an index sidecar. A later
 *       read of one member recalls the archive and extracts just that member.
 *
 * WHY:  tape systems bill per object and HEP datasets are thousands of small
 *       files; stock XRootD's OssArc solves it the same way (zip per dataset +
 *       index). Doing it as a decorator keeps every real MSS dialect untouched.
 *
 * HOW:  enabled by the `?arc=<depth>` query of the tape:// store URL
 *       (brix_sd_frm_parse_query). Archive key `<dataset>.brixarc.zip`
 *       (reserved: no client may create it); sidecar `<base>/.arcidx<dataset>.idx`
 *       (outside `.online`, so the purge engine never sees it). Sealed datasets
 *       are immutable: a new member is refused with EPERM, a second marker with
 *       EEXIST. Member names come from the online walk and are validated by
 *       brix_zip_name_ok on both seal and recall.
 */

#ifndef BRIX_FS_BACKEND_FRM_SD_FRM_ARC_H
#define BRIX_FS_BACKEND_FRM_SD_FRM_ARC_H

#include "sd_frm.h"

#define BRIX_ARC_MARKER     ".brix-dataset-complete"
#define BRIX_ARC_SUFFIX     ".brixarc.zip"
#define BRIX_ARC_IDX_DIR    ".arcidx"
#define BRIX_ARC_MAX_DEPTH  8u

extern const brix_mss_adapter_t brix_mss_arc_adapter;

/* Wrap `inner`/`ictx` (ownership of ictx passes to the decorator: destroy()
 * destroys both). `base` is the tape:// base the online buffer hangs off;
 * `depth` is 1..BRIX_ARC_MAX_DEPTH. NULL with errno on failure. */
void *brix_mss_arc_create(const brix_mss_adapter_t *inner, void *ictx,
    const char *base, unsigned depth, ngx_log_t *log);

#endif /* BRIX_FS_BACKEND_FRM_SD_FRM_ARC_H */

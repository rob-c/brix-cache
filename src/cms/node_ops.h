#ifndef XROOTD_CMS_NODE_OPS_H
#define XROOTD_CMS_NODE_OPS_H

/*
 * node_ops.h — data-node execution of namespace ops forwarded by the manager.
 *
 * WHAT: when a manager forwards kYR_chmod/mkdir/mkpath/mv/rm/rmdir/trunc down to
 *       this data node, node_ops decodes the request, runs it against local
 *       storage UNDER KERNEL CONFINEMENT (openat2 RESOLVE_BENEATH), and — exactly
 *       like stock cmsd — stays silent on success or returns a kYR_error on
 *       failure (ecode always kYR_EINVAL, text = strerror, per XrdCmsProtocol).
 * WHY:  Plane B write-cluster parity. The headline security property: a hostile
 *       or compromised manager cannot make a node mutate anything outside its
 *       export root — every path is resolved beneath the export rootfd.
 * HOW:  xrootd_cms_node_plan() is a PURE mapping (opcode+rrdata -> action) so the
 *       arg handling (mode/size parsing, mv needs two paths) is unit-testable;
 *       the executor applies the plan via the src/path/beneath.h confined helpers.
 */

#include <sys/types.h>
#include "rrdata.h"

typedef enum {
    XRDCMS_NACT_NONE = 0,
    XRDCMS_NACT_MKDIR,
    XRDCMS_NACT_MKPATH,
    XRDCMS_NACT_RMDIR,
    XRDCMS_NACT_RM,
    XRDCMS_NACT_MV,
    XRDCMS_NACT_CHMOD,
    XRDCMS_NACT_TRUNC
} xrootd_cms_node_action_t;

typedef struct {
    xrootd_cms_node_action_t action;
    const char *path;    /* primary path (borrows rrdata, NUL-terminated) */
    const char *path2;   /* mv destination */
    mode_t      mode;    /* mkdir/mkpath/chmod permission bits */
    long long   size;    /* trunc target size */
} xrootd_cms_node_plan_t;

#define XRDCMS_NODE_DEFAULT_DIR_MODE 0755

/*
 * Map a forwarded opcode + decoded rrdata to a confined filesystem action.
 * Returns 0 with *plan filled, or -1 on a missing/invalid argument (e.g. no
 * path, mv without a second path, chmod/trunc without a mode/size, or an opcode
 * this node does not execute) — the caller then replies kYR_error.
 */
int xrootd_cms_node_plan(unsigned char code, const xrootd_cms_rrdata_t *d,
                         xrootd_cms_node_plan_t *plan);

#endif /* XROOTD_CMS_NODE_OPS_H */

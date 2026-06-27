/*
 * node_ops.c — data-node execution of forwarded namespace ops. See node_ops.h.
 *
 * This file holds the PURE planner; the confined executor + reply live in the
 * recv.c node dispatch (which has the ctx/rootfd). Keeping the planner pure makes
 * the arg handling (mode/size parsing, mv-needs-two-paths) unit-testable.
 */

#include "node_ops.h"
#include <stddef.h>
#include <stdlib.h>

/* kYR_* request opcodes (wire constants). */
#define K_CHMOD    1
#define K_MKDIR    3
#define K_MKPATH   4
#define K_MV       5
#define K_RM       8
#define K_RMDIR    9
#define K_TRUNC   23

/* A decoded rrdata "char" field is NUL-terminated in place; treat a present span
 * as a C string. Returns NULL when the field is absent. */
static const char *
field_str(const unsigned char *p, size_t len)
{
    return (p != NULL && len > 0) ? (const char *) p : NULL;
}

int
xrootd_cms_node_plan(unsigned char code, const xrootd_cms_rrdata_t *d,
                     xrootd_cms_node_plan_t *plan)
{
    const char *path  = field_str(d->path,  d->path_len);
    const char *path2 = field_str(d->path2, d->path2_len);
    const char *mode  = field_str(d->mode,  d->mode_len);

    plan->action = XRDCMS_NACT_NONE;
    plan->path   = path;
    plan->path2  = NULL;
    plan->mode   = 0;
    plan->size   = 0;

    /* Every executed op needs a primary path. */
    if (path == NULL) {
        return -1;
    }

    switch (code) {

    case K_MKDIR:
    case K_MKPATH:
        plan->action = (code == K_MKDIR) ? XRDCMS_NACT_MKDIR
                                         : XRDCMS_NACT_MKPATH;
        plan->mode = mode ? (mode_t) strtol(mode, NULL, 8)
                          : (mode_t) XRDCMS_NODE_DEFAULT_DIR_MODE;
        return 0;

    case K_CHMOD:
        if (mode == NULL) {
            return -1;
        }
        plan->action = XRDCMS_NACT_CHMOD;
        plan->mode = (mode_t) strtol(mode, NULL, 8);
        return 0;

    case K_TRUNC:
        /* fwdArgA reuses the Mode field to carry the truncate size (decimal). */
        if (mode == NULL) {
            return -1;
        }
        plan->action = XRDCMS_NACT_TRUNC;
        plan->size = strtoll(mode, NULL, 10);
        return 0;

    case K_RM:
        plan->action = XRDCMS_NACT_RM;
        return 0;

    case K_RMDIR:
        plan->action = XRDCMS_NACT_RMDIR;
        return 0;

    case K_MV:
        if (path2 == NULL) {
            return -1;
        }
        plan->action = XRDCMS_NACT_MV;
        plan->path2  = path2;
        return 0;

    default:
        return -1;     /* prepadd/prepdel (staging) + anything else: not here */
    }
}

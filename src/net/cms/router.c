/*
 * router.c — table-driven CMS opcode routing. See router.h.
 *
 * The tables mirror XrdCmsRouting.cc: the manager table merges the redirector
 * routing (client-facing forwardable ops, initRDRrouting) with the server group
 * (node->manager status frames, initRouter); the node table is the set of ops a
 * data server executes when forwarded down from its manager (leaf — no FORWARD
 * flag).  Phase-61 W7 adds the two upward-leg valid-ops tables for explicit
 * multi-tier roles: SUBMAN (manVOps — what a sub-manager accepts from its
 * meta-manager) and SUPER (supVOps — what a supervisor accepts from its
 * manager, namespace ops FORWARDed down to its own nodes).
 */

#include "router.h"
#include <stddef.h>

/* kYR_* opcodes (wire constants from XProtocol/YProtocol.hh). */
#define K_LOGIN    0
#define K_CHMOD    1
#define K_LOCATE   2
#define K_MKDIR    3
#define K_MKPATH   4
#define K_MV       5
#define K_PREPADD  6
#define K_PREPDEL  7
#define K_RM       8
#define K_RMDIR    9
#define K_SELECT  10
#define K_STATS   11
#define K_AVAIL   12
#define K_DISC    13
#define K_GONE    14
#define K_HAVE    15
#define K_LOAD    16
#define K_PING    17
#define K_PONG    18
#define K_SPACE   19
#define K_STATE   20
#define K_STATFS  21
#define K_STATUS  22
#define K_TRUNC   23
#define K_TRY     24
#define K_UPDATE  25
#define K_USAGE   26
#define K_XAUTH   27

#define RF_FWD  (XRDCMS_RF_FORWARD | XRDCMS_RF_REPLIABLE | XRDCMS_RF_DELAYABLE)
#define RF_RD   (XRDCMS_RF_REPLIABLE | XRDCMS_RF_DELAYABLE)
#define RF_SYNC XRDCMS_RF_SYNC
#define RF_HDR  (XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS)   /* header-only status frame */
#define RF_PUSH XRDCMS_RF_FORWARD                     /* pushed down, not local */
#define RF_UPD  (XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS | XRDCMS_RF_REPLIABLE)

/*
 * The routing matrix: one row per opcode, one column per role leg —
 *   manager  initRDRrouting (forwardable client ops) + initRouter server
 *            group (node -> manager status/heartbeat frames)
 *   node     initRouter leaf: ops a data server executes when forwarded down
 *   subman   initMANrouting/manVOps (Phase-61 W7): a meta-manager may only ask
 *            for non-destructive service — stock cmsd "prohibit[s] a
 *            meta-manager from requesting potentially destructive actions"
 *   super    initSUProuting/supVOps (Phase-61 W7): namespace mutations carry
 *            FORWARD — a supervisor pushes them DOWN to its own data nodes
 * 0 = that role does not accept the opcode (lookup returns NULL: caller logs
 * and drops, matching cmsd tolerance).
 */
#define BRIX_CMS_ROUTE_LIST(R_) \
    /*  opcode      name      manager          node             subman           super          */ \
    R_( K_LOGIN,   "login",   RF_SYNC,         0,               0,               0               ) \
    R_( K_CHMOD,   "chmod",   RF_FWD,          RF_RD,           0,               RF_PUSH         ) \
    R_( K_LOCATE,  "locate",  RF_RD,           RF_RD,           0,               0               ) \
    R_( K_MKDIR,   "mkdir",   RF_FWD,          RF_RD,           0,               RF_PUSH         ) \
    R_( K_MKPATH,  "mkpath",  RF_FWD,          RF_RD,           0,               RF_PUSH         ) \
    R_( K_MV,      "mv",      RF_FWD,          RF_RD,           0,               RF_PUSH         ) \
    R_( K_PREPADD, "prepadd", RF_SYNC | RF_RD, RF_SYNC | RF_RD, RF_SYNC,         RF_SYNC         ) \
    R_( K_PREPDEL, "prepdel", RF_SYNC | RF_FWD,RF_SYNC | RF_RD, RF_SYNC | RF_PUSH, RF_SYNC | RF_PUSH ) \
    R_( K_RM,      "rm",      RF_FWD,          RF_RD,           0,               RF_PUSH         ) \
    R_( K_RMDIR,   "rmdir",   RF_FWD,          RF_RD,           0,               RF_PUSH         ) \
    R_( K_SELECT,  "select",  RF_RD,           RF_RD,           0,               0               ) \
    R_( K_STATS,   "stats",   RF_RD,           RF_RD,           XRDCMS_RF_NOARGS,XRDCMS_RF_NOARGS) \
    R_( K_AVAIL,   "avail",   RF_SYNC,         0,               0,               0               ) \
    R_( K_DISC,    "disc",    RF_HDR,          RF_HDR,          RF_HDR,          RF_HDR          ) \
    R_( K_GONE,    "gone",    RF_SYNC,         0,               0,               0               ) \
    R_( K_HAVE,    "have",    RF_SYNC,         0,               0,               0               ) \
    R_( K_LOAD,    "load",    RF_SYNC,         0,               0,               0               ) \
    R_( K_PING,    "ping",    RF_HDR,          RF_HDR,          RF_HDR,          RF_HDR          ) \
    R_( K_PONG,    "pong",    RF_HDR,          0,               0,               0               ) \
    R_( K_SPACE,   "space",   RF_HDR,          0,               RF_HDR,          RF_HDR          ) \
    R_( K_STATE,   "state",   RF_SYNC,         RF_SYNC,         RF_SYNC,         RF_SYNC         ) \
    R_( K_STATFS,  "statfs",  RF_RD,           RF_RD,           0,               0               ) \
    R_( K_STATUS,  "status",  RF_SYNC,         0,               0,               0               ) \
    R_( K_TRUNC,   "trunc",   RF_FWD,          RF_RD,           0,               RF_PUSH         ) \
    R_( K_TRY,     "try",     RF_SYNC,         0,               RF_SYNC,         RF_SYNC         ) \
    R_( K_UPDATE,  "update",  RF_UPD,          RF_UPD,          0,               0               ) \
    R_( K_USAGE,   "usage",   RF_HDR,          0,               RF_HDR,          RF_HDR          ) \
    R_( K_XAUTH,   "xauth",   RF_SYNC,         0,               0,               0               )

/* Per-role tables generated from the matrix; a 0-flag row means "this role
 * does not accept the opcode" and route_scan reports it as absent. */
#define ROUTE_MANAGER(c, n, mgr, nd, sm, sp) { c, n, (mgr) },
#define ROUTE_NODE(c, n, mgr, nd, sm, sp)    { c, n, (nd) },
#define ROUTE_SUBMAN(c, n, mgr, nd, sm, sp)  { c, n, (sm) },
#define ROUTE_SUPER(c, n, mgr, nd, sm, sp)   { c, n, (sp) },

static const brix_cms_route_t manager_routes[] = { BRIX_CMS_ROUTE_LIST(ROUTE_MANAGER) };
static const brix_cms_route_t node_routes[]    = { BRIX_CMS_ROUTE_LIST(ROUTE_NODE) };
static const brix_cms_route_t subman_routes[]  = { BRIX_CMS_ROUTE_LIST(ROUTE_SUBMAN) };
static const brix_cms_route_t super_routes[]   = { BRIX_CMS_ROUTE_LIST(ROUTE_SUPER) };

static const brix_cms_route_t *
route_scan(const brix_cms_route_t *tbl, size_t n, unsigned char code)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (tbl[i].code == code) {
            return (tbl[i].flags != 0) ? &tbl[i] : NULL;
        }
    }
    return NULL;
}

const brix_cms_route_t *
brix_cms_route_lookup(brix_cms_role_t role, unsigned char code)
{
    switch (role) {
    case XRDCMS_ROLE_NODE:
        return route_scan(node_routes,
                          sizeof(node_routes) / sizeof(node_routes[0]), code);
    case XRDCMS_ROLE_SUBMAN:
        return route_scan(subman_routes,
                          sizeof(subman_routes) / sizeof(subman_routes[0]),
                          code);
    case XRDCMS_ROLE_SUPER:
        return route_scan(super_routes,
                          sizeof(super_routes) / sizeof(super_routes[0]),
                          code);
    default:
        return route_scan(manager_routes,
                          sizeof(manager_routes) / sizeof(manager_routes[0]),
                          code);
    }
}

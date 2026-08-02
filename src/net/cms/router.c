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

/* Manager role: forwardable client ops (initRDRrouting) + node status frames. */
static const brix_cms_route_t manager_routes[] = {
    /* forwardable / redirector client-facing ops */
    { K_CHMOD,   "chmod",  RF_FWD },
    { K_LOCATE,  "locate", RF_RD },
    { K_MKDIR,   "mkdir",  RF_FWD },
    { K_MKPATH,  "mkpath", RF_FWD },
    { K_MV,      "mv",     RF_FWD },
    { K_PREPADD, "prepadd",XRDCMS_RF_SYNC | RF_RD },
    { K_PREPDEL, "prepdel",XRDCMS_RF_SYNC | RF_FWD },
    { K_RM,      "rm",     RF_FWD },
    { K_RMDIR,   "rmdir",  RF_FWD },
    { K_SELECT,  "select", RF_RD },
    { K_STATFS,  "statfs", RF_RD },
    { K_STATS,   "stats",  RF_RD },
    { K_TRUNC,   "trunc",  RF_FWD },
    { K_UPDATE,  "update", XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS | XRDCMS_RF_REPLIABLE },
    /* node -> manager status / heartbeat frames (initRouter server group) */
    { K_LOGIN,   "login",  XRDCMS_RF_SYNC },
    { K_AVAIL,   "avail",  XRDCMS_RF_SYNC },
    { K_DISC,    "disc",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_GONE,    "gone",   XRDCMS_RF_SYNC },
    { K_HAVE,    "have",   XRDCMS_RF_SYNC },
    { K_LOAD,    "load",   XRDCMS_RF_SYNC },
    { K_PING,    "ping",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_PONG,    "pong",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_SPACE,   "space",  XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_STATE,   "state",  XRDCMS_RF_SYNC },
    { K_STATUS,  "status", XRDCMS_RF_SYNC },
    { K_TRY,     "try",    XRDCMS_RF_SYNC },
    { K_USAGE,   "usage",  XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_XAUTH,   "xauth",  XRDCMS_RF_SYNC },
};

/* Node role: ops a data server executes when forwarded down from its manager. */
static const brix_cms_route_t node_routes[] = {
    { K_CHMOD,   "chmod",  RF_RD },
    { K_LOCATE,  "locate", RF_RD },
    { K_MKDIR,   "mkdir",  RF_RD },
    { K_MKPATH,  "mkpath", RF_RD },
    { K_MV,      "mv",     RF_RD },
    { K_PREPADD, "prepadd",XRDCMS_RF_SYNC | RF_RD },
    { K_PREPDEL, "prepdel",XRDCMS_RF_SYNC | RF_RD },
    { K_RM,      "rm",     RF_RD },
    { K_RMDIR,   "rmdir",  RF_RD },
    { K_SELECT,  "select", RF_RD },
    { K_STATFS,  "statfs", RF_RD },
    { K_STATS,   "stats",  RF_RD },
    { K_TRUNC,   "trunc",  RF_RD },
    { K_STATE,   "state",  XRDCMS_RF_SYNC },
    { K_PING,    "ping",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_DISC,    "disc",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_UPDATE,  "update", XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS | XRDCMS_RF_REPLIABLE },
};

/* Sub-manager <- meta-manager leg (initMANrouting/manVOps, Phase-61 W7): a
 * meta-manager may only ask for non-destructive service — stock cmsd
 * "prohibit[s] a meta-manager from requesting potentially destructive
 * actions".  Anything else is dropped by the caller (logged, conn kept). */
static const brix_cms_route_t subman_routes[] = {
    { K_DISC,    "disc",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_PING,    "ping",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_PREPADD, "prepadd",XRDCMS_RF_SYNC },
    { K_PREPDEL, "prepdel",XRDCMS_RF_SYNC | XRDCMS_RF_FORWARD },
    { K_SPACE,   "space",  XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_STATE,   "state",  XRDCMS_RF_SYNC },
    { K_STATS,   "stats",  XRDCMS_RF_NOARGS },
    { K_TRY,     "try",    XRDCMS_RF_SYNC },
    { K_USAGE,   "usage",  XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
};

/* Supervisor <- manager leg (initSUProuting/supVOps, Phase-61 W7): namespace
 * mutations carry FORWARD — a supervisor pushes them DOWN to its own data
 * nodes rather than executing locally. */
static const brix_cms_route_t super_routes[] = {
    { K_CHMOD,   "chmod",  XRDCMS_RF_FORWARD },
    { K_DISC,    "disc",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_MKDIR,   "mkdir",  XRDCMS_RF_FORWARD },
    { K_MKPATH,  "mkpath", XRDCMS_RF_FORWARD },
    { K_MV,      "mv",     XRDCMS_RF_FORWARD },
    { K_PING,    "ping",   XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_PREPADD, "prepadd",XRDCMS_RF_SYNC },
    { K_PREPDEL, "prepdel",XRDCMS_RF_SYNC | XRDCMS_RF_FORWARD },
    { K_RM,      "rm",     XRDCMS_RF_FORWARD },
    { K_RMDIR,   "rmdir",  XRDCMS_RF_FORWARD },
    { K_SPACE,   "space",  XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
    { K_STATE,   "state",  XRDCMS_RF_SYNC },
    { K_STATS,   "stats",  XRDCMS_RF_NOARGS },
    { K_TRUNC,   "trunc",  XRDCMS_RF_FORWARD },
    { K_TRY,     "try",    XRDCMS_RF_SYNC },
    { K_USAGE,   "usage",  XRDCMS_RF_SYNC | XRDCMS_RF_NOARGS },
};

static const brix_cms_route_t *
route_scan(const brix_cms_route_t *tbl, size_t n, unsigned char code)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (tbl[i].code == code) {
            return &tbl[i];
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

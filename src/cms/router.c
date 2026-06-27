/*
 * router.c — table-driven CMS opcode routing. See router.h.
 *
 * The two tables mirror XrdCmsRouting.cc: the manager table merges the redirector
 * routing (client-facing forwardable ops, initRDRrouting) with the server group
 * (node->manager status frames, initRouter); the node table is the set of ops a
 * data server executes when forwarded down from its manager. A data node is a
 * leaf here (no sub-manager cascade — an explicit non-goal), so forwarded ops
 * carry no FORWARD flag in the node table.
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
static const xrootd_cms_route_t manager_routes[] = {
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
static const xrootd_cms_route_t node_routes[] = {
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

static const xrootd_cms_route_t *
route_scan(const xrootd_cms_route_t *tbl, size_t n, unsigned char code)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (tbl[i].code == code) {
            return &tbl[i];
        }
    }
    return NULL;
}

const xrootd_cms_route_t *
xrootd_cms_route_lookup(xrootd_cms_role_t role, unsigned char code)
{
    if (role == XRDCMS_ROLE_NODE) {
        return route_scan(node_routes,
                          sizeof(node_routes) / sizeof(node_routes[0]), code);
    }
    return route_scan(manager_routes,
                      sizeof(manager_routes) / sizeof(manager_routes[0]), code);
}

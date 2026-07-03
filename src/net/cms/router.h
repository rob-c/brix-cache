#ifndef BRIX_CMS_ROUTER_H
#define BRIX_CMS_ROUTER_H

/*
 * router.h — table-driven CMS opcode routing, mirroring XrdCmsRouting.cc.
 *
 * WHAT: per-role descriptor tables mapping a kYR_* opcode to its name and wire
 *       routing flags. Both CMS halves dispatch through brix_cms_route_lookup:
 *       the manager (frames accepted up from data nodes + forwardable client ops)
 *       and the data node (forwarded ops accepted down from its manager).
 * WHY:  byte-exact parity with stock cmsd's routing — the FORWARD/REPLIABLE/
 *       DELAYABLE/SYNC/NOARGS flags drive whether the manager fans an op out to
 *       nodes and how replies are aggregated, exactly as initRDRrouting /
 *       initRouter / initMANrouting prescribe.
 * HOW:  pure C (no nginx headers) so the table is unit-testable standalone.
 */

/* Wire routing flags (subset of XrdCmsRouting bits relevant to dispatch). */
#define XRDCMS_RF_SYNC      0x01u   /* isSync: handled inline, reply now */
#define XRDCMS_RF_FORWARD   0x02u   /* Forward: manager fans op out to nodes */
#define XRDCMS_RF_REPLIABLE 0x04u   /* Repliable: originator expects a reply */
#define XRDCMS_RF_DELAYABLE 0x08u   /* Delayable: may answer kYR_wait */
#define XRDCMS_RF_NOARGS    0x10u   /* noArgs: header-only, empty payload */

typedef enum {
    XRDCMS_ROLE_MANAGER = 0,   /* this node accepts frames as a manager */
    XRDCMS_ROLE_NODE    = 1    /* this node accepts frames as a data server */
} brix_cms_role_t;

typedef struct {
    unsigned char code;        /* kYR_* opcode */
    const char   *name;        /* opcode name (for logs / conformance) */
    unsigned int  flags;       /* XRDCMS_RF_* */
} brix_cms_route_t;

/*
 * Return the route descriptor for `code` in `role`, or NULL if that role does
 * not accept the opcode (caller logs + drops, matching cmsd tolerance).
 */
const brix_cms_route_t *
brix_cms_route_lookup(brix_cms_role_t role, unsigned char code);

#endif /* BRIX_CMS_ROUTER_H */

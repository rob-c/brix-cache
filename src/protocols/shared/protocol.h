#ifndef BRIX_PROTOCOL_COMMON_H
#define BRIX_PROTOCOL_COMMON_H

/*
 * src/protocols/common — cross-protocol common code and the protocol-descriptor
 * registry (QUALITY_ROADMAP 2.1: "common Protocol Handler Interface").
 *
 * nginx hosts two module families with fundamentally different request models,
 * so the roadmap's generic open/read/write/close vtable does not fit: root:// is
 * a STREAM module (an event-driven opcode state machine) while s3 / webdav /
 * cvmfs are HTTP modules (method dispatch through nginx's phase handlers).  The
 * descriptor therefore captures what every protocol genuinely shares — a stable
 * wire name and its module family — and is the single seam the dispatcher and
 * observability layers can key off without inventing a false uniform vtable.
 * (Protocol-specific request handling stays in each protocol's own module; the
 * unified proto id/label table remains src/core/types/proto_list.h.)
 */

#include "core/ngx_brix_module.h"

typedef enum {
    BRIX_PROTO_FAMILY_STREAM = 0,   /* nginx stream module (root://)          */
    BRIX_PROTO_FAMILY_HTTP          /* nginx http module   (s3/webdav/cvmfs)  */
} brix_protocol_family_t;

typedef struct {
    const char             *name;      /* stable wire name: "root", "s3", ...   */
    brix_protocol_family_t  family;
    const char             *directive; /* config directive, e.g. "brix_webdav"  */
    /* HTTP family: is this protocol enabled in a location's module-conf array?
     * (reads the protocol's own loc-conf enable flag).  NULL for the stream
     * family, whose exclusivity is out of the http location walker's scope. */
    ngx_flag_t            (*loc_enabled)(void **loc_conf);
} brix_protocol_t;

/* Registry.  Registration is idempotent (by name); lookup returns NULL if absent. */
ngx_int_t              brix_protocol_register(const brix_protocol_t *p);
const brix_protocol_t *brix_protocol_find(const char *name);

/* Iterate the registered descriptors (consumed by the exclusivity walker). */
ngx_uint_t             brix_protocol_count_get(void);
const brix_protocol_t *brix_protocol_at(ngx_uint_t i);

/* Register the built-in protocols (root, s3, webdav, cvmfs).  Idempotent. */
void                   brix_protocol_register_all(void);

#endif /* BRIX_PROTOCOL_COMMON_H */

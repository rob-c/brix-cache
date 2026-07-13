#include "protocols/shared/protocol.h"
#include "protocols/webdav/webdav.h"
#include "protocols/s3/s3.h"
#include "protocols/cvmfs/cvmfs.h"

/* Per-protocol "enabled at this location?" hooks (HTTP family) — read each
 * module's own loc-conf enable flag via its ctx_index. */
static ngx_flag_t
proto_webdav_enabled(void **loc_conf)
{
    ngx_http_brix_webdav_loc_conf_t *w =
        loc_conf[ngx_http_brix_webdav_module.ctx_index];
    return w != NULL && w->common.enable == 1;
}
static ngx_flag_t
proto_s3_enabled(void **loc_conf)
{
    ngx_http_s3_loc_conf_t *s = loc_conf[ngx_http_brix_s3_module.ctx_index];
    return s != NULL && s->common.enable == 1;
}
static ngx_flag_t
proto_cvmfs_enabled(void **loc_conf)
{
    ngx_http_brix_cvmfs_loc_conf_t *c =
        loc_conf[ngx_http_brix_cvmfs_module.ctx_index];
    return c != NULL && c->cvmfs.enable == 1;
}

/*
 * protocol.c — the protocol-descriptor registry (see protocol.h).  A small
 * fixed-size table of pointers to statically-defined descriptors; registration
 * is idempotent so brix_protocol_register_all() may be called from more than one
 * init path without duplicating entries.
 */

#define BRIX_PROTOCOL_MAX 8

static const brix_protocol_t *brix_protocols[BRIX_PROTOCOL_MAX];
static ngx_uint_t             brix_protocol_count;

static const brix_protocol_t brix_proto_root   =
    { "root",   BRIX_PROTO_FAMILY_STREAM, "brix",        NULL };
static const brix_protocol_t brix_proto_s3     =
    { "s3",     BRIX_PROTO_FAMILY_HTTP,   "brix_s3",     proto_s3_enabled };
static const brix_protocol_t brix_proto_webdav =
    { "webdav", BRIX_PROTO_FAMILY_HTTP,   "brix_webdav", proto_webdav_enabled };
static const brix_protocol_t brix_proto_cvmfs  =
    { "cvmfs",  BRIX_PROTO_FAMILY_HTTP,   "brix_cvmfs",  proto_cvmfs_enabled };

ngx_int_t
brix_protocol_register(const brix_protocol_t *p)
{
    ngx_uint_t i;

    if (p == NULL || p->name == NULL) {
        return NGX_ERROR;
    }
    for (i = 0; i < brix_protocol_count; i++) {
        if (ngx_strcmp(brix_protocols[i]->name, p->name) == 0) {
            return NGX_OK;   /* already registered — idempotent */
        }
    }
    if (brix_protocol_count >= BRIX_PROTOCOL_MAX) {
        return NGX_ERROR;
    }
    brix_protocols[brix_protocol_count++] = p;
    return NGX_OK;
}

const brix_protocol_t *
brix_protocol_find(const char *name)
{
    ngx_uint_t i;

    if (name == NULL) {
        return NULL;
    }
    for (i = 0; i < brix_protocol_count; i++) {
        if (ngx_strcmp(brix_protocols[i]->name, name) == 0) {
            return brix_protocols[i];
        }
    }
    return NULL;
}

ngx_uint_t
brix_protocol_count_get(void)
{
    return brix_protocol_count;
}

const brix_protocol_t *
brix_protocol_at(ngx_uint_t i)
{
    return i < brix_protocol_count ? brix_protocols[i] : NULL;
}

void
brix_protocol_register_all(void)
{
    (void) brix_protocol_register(&brix_proto_root);
    (void) brix_protocol_register(&brix_proto_s3);
    (void) brix_protocol_register(&brix_proto_webdav);
    (void) brix_protocol_register(&brix_proto_cvmfs);
}

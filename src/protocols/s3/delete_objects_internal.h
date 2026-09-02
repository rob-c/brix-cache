#ifndef NGX_HTTP_BRIX_S3_DELETE_OBJECTS_INTERNAL_H
#define NGX_HTTP_BRIX_S3_DELETE_OBJECTS_INTERNAL_H

/*
 * Internal seam for the S3 DeleteObjects handler split across delete_objects.c
 * (body read, batch loop, response finalise) and delete_objects_xml.c (the
 * DeleteResult XML rendering + <Delete> DOM navigation helpers). Bundles the
 * shared per-key error pair type and declares every symbol DEFINED in
 * delete_objects_xml.c but REFERENCED from delete_objects.c.
 *
 * Includers must already have pulled in s3.h (for the nginx ngx_* types and
 * brix_xml_write_text_element) before this header; libxml2 headers are pulled
 * in here for the xmlNodePtr-taking navigation helpers.
 */

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * s3_del_err_t — the (Code, Message) S3 error pair emitted in a per-key
 * <Error> element. Bundling the two strings keeps the XML-append helper at or
 * below the five-parameter limit and travels as one value from the delete/auth
 * stages that decide the pair to the XML stage that renders it.
 */
typedef struct {
    const char *code;
    const char *message;
} s3_del_err_t;

/*
 * s3_del_ctx_t — the state the per-request batch stages share: the request
 * (metrics/pool/identity), the location config (root confinement + write
 * gate), the method's metrics slot, and the shared output-XML buffer plus its
 * running length. One value keeps the stage helpers at or below the
 * five-parameter limit and makes the data flow explicit.
 */
typedef struct {
    ngx_http_request_t      *r;
    ngx_http_s3_loc_conf_t  *cf;
    ngx_uint_t               method_slot;
    ngx_buf_t               *xml_buf;
    size_t                  *xml_len;
} s3_del_ctx_t;

/*
 * s3_del_item_t — one <Object> entry's journey through the two-phase batch
 * (phase-107 C4): collection resolves and confines every key BEFORE any
 * delete, then ONE brix_vfs_delete_many() call disposes the confinable subset,
 * then rendering emits per-key XML in the client's order.
 *
 *   key/key_len  pool copy of the client's key text (render needs it after
 *                the parsed document is freed)
 *   fs           confined absolute path (pool copy) — NULL when the key was
 *                pre-disposed at collection (bad key, escape, reserved-absent)
 *   err          collection-time verdict: .code != NULL renders as <Error>
 *                without ever reaching the VFS; both NULL with fs == NULL
 *                renders as <Deleted> (a RESERVED key reads exactly as an
 *                absent one, and DeleteObjects is idempotent)
 *   batch_err    the per-key errno brix_vfs_delete_many() wrote (0 = removed,
 *                ENOENT = idempotent-success, ECANCELED = never attempted)
 */
typedef struct {
    u_char       *key;
    size_t        key_len;
    char         *fs;
    s3_del_err_t  err;
    int           batch_err;
} s3_del_item_t;

/* Two-phase batch stages — defined in delete_objects_batch.c. */
ngx_int_t s3_delete_collect_one(s3_del_ctx_t *dc, xmlNodePtr obj,
    s3_del_item_t *it, int *malformed_500);
ngx_int_t s3_delete_execute(s3_del_ctx_t *dc, s3_del_item_t *items,
    size_t count);
ngx_int_t s3_delete_render(s3_del_ctx_t *dc, const s3_del_item_t *items,
    size_t count);

/* DeleteResult XML rendering + <Delete> DOM navigation — defined in
 * delete_objects_xml.c. */
ngx_int_t s3_delete_xml_append_raw(ngx_buf_t *xml_buf, size_t *xml_len,
    const char *text);

ngx_int_t s3_delete_xml_append_elem(ngx_buf_t *xml_buf, size_t *xml_len,
    const char *name, const u_char *value, size_t value_len);

ngx_int_t s3_delete_xml_append_deleted(ngx_buf_t *xml_buf, size_t *xml_len,
    const u_char *key, size_t key_len);

ngx_int_t s3_delete_xml_append_error(ngx_buf_t *xml_buf, size_t *xml_len,
    const u_char *key, size_t key_len, const s3_del_err_t *err);

ngx_flag_t s3_delete_xml_name_is(xmlNodePtr node, const char *name);

xmlNodePtr s3_delete_xml_find_child(xmlNodePtr node, const char *name);

#endif /* NGX_HTTP_BRIX_S3_DELETE_OBJECTS_INTERNAL_H */

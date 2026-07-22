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

/*
 * delete_objects_xml.c — DeleteResult XML rendering + <Delete> DOM navigation
 * helpers for the S3 DeleteObjects handler (POST /bucket/?delete).
 *
 * Split VERBATIM out of delete_objects.c (mechanical file-size split): the
 * fixed-buffer <Deleted>/<Error> append helpers and the libxml2 element
 * navigation helpers used by the body parser and batch loop. The shared
 * s3_del_err_t error pair and these functions' prototypes live in
 * delete_objects_internal.h.
 */

#include "s3.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <string.h>

#include "delete_objects_internal.h"

ngx_int_t
s3_delete_xml_append_raw(ngx_buf_t *xml_buf, size_t *xml_len, const char *text)
{
    size_t len;
    size_t cap;

    len = strlen(text);
    cap = (size_t) (xml_buf->end - xml_buf->start);
    if (*xml_len > cap || len > cap - *xml_len) {
        return NGX_ERROR;
    }

    ngx_memcpy(xml_buf->start + *xml_len, text, len);
    *xml_len += len;
    return NGX_OK;
}

ngx_int_t
s3_delete_xml_append_elem(ngx_buf_t *xml_buf, size_t *xml_len,
    const char *name, const u_char *value, size_t value_len)
{
    size_t room;
    size_t written;

    if (*xml_len > (size_t) (xml_buf->end - xml_buf->start)) {
        return NGX_ERROR;
    }

    room = (size_t) (xml_buf->end - xml_buf->start) - *xml_len;
    if (brix_xml_write_text_element(name, value, value_len,
            BRIX_XML_ESCAPE_APOS_ENTITY | BRIX_XML_ESCAPE_CONTROL_PERCENT,
            xml_buf->start + *xml_len, room, &written) != 0)
    {
        return NGX_ERROR;
    }

    *xml_len += written;
    return NGX_OK;
}

ngx_int_t
s3_delete_xml_append_deleted(ngx_buf_t *xml_buf, size_t *xml_len,
    const u_char *key, size_t key_len)
{
    return s3_delete_xml_append_raw(xml_buf, xml_len, "<Deleted>") == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Key", key, key_len)
              == NGX_OK
           && s3_delete_xml_append_raw(xml_buf, xml_len, "</Deleted>")
              == NGX_OK
           ? NGX_OK : NGX_ERROR;
}

/*
 * s3_delete_xml_append_error — append one per-key <Error> element (Key/Code/
 * Message) to the buffered DeleteResult XML.
 *
 * WHY: S3 DeleteObjects reports per-key failures inline in the batch result
 *   rather than aborting the whole request; each failed key contributes an
 *   <Error> block with its escaped key plus the S3 code/message pair.
 * HOW: Emit the open tag, the escaped Key/Code/Message text elements, then the
 *   close tag — short-circuiting to NGX_ERROR if any append overflows the
 *   pre-sized buffer.
 */
ngx_int_t
s3_delete_xml_append_error(ngx_buf_t *xml_buf, size_t *xml_len,
    const u_char *key, size_t key_len, const s3_del_err_t *err)
{
    return s3_delete_xml_append_raw(xml_buf, xml_len, "<Error>") == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Key", key, key_len)
              == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Code",
                                        (const u_char *) err->code,
                                        strlen(err->code)) == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Message",
                                        (const u_char *) err->message,
                                        strlen(err->message)) == NGX_OK
           && s3_delete_xml_append_raw(xml_buf, xml_len, "</Error>")
              == NGX_OK
           ? NGX_OK : NGX_ERROR;
}

ngx_flag_t
s3_delete_xml_name_is(xmlNodePtr node, const char *name)
{
    return node != NULL
           && node->type == XML_ELEMENT_NODE
           && xmlStrcmp(node->name, BAD_CAST name) == 0;
}

xmlNodePtr
s3_delete_xml_find_child(xmlNodePtr node, const char *name)
{
    xmlNodePtr cur;

    for (cur = node == NULL ? NULL : node->children; cur != NULL;
         cur = cur->next)
    {
        if (s3_delete_xml_name_is(cur, name)) {
            return cur;
        }
    }

    return NULL;
}

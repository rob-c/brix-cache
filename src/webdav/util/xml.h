#ifndef XROOTD_WEBDAV_UTIL_XML_H
#define XROOTD_WEBDAV_UTIL_XML_H

#include "../webdav.h"

/*
 * webdav_escape_xml_text — escape a string for safe inclusion in XML text response bodies.
 *
 * WHAT: Converts dangerous characters (& < > " ') to their XML entity equivalents and
 *       encodes control bytes (< 0x20, 0x7f) as %XX. Allocates result from the nginx
 *       request pool so it is cleaned up automatically when the request completes.
 *
 * WHY: WebDAV PROPFIND Multi-Status responses, LOCK response bodies, and HEAD property
 *      values embed raw filesystem paths, lock owner names, and metadata as XML text.
 *      Escaping prevents XML injection from filenames containing special characters.
 *
 * HOW: Delegates to xrootd_xml_escaped_len() + xrootd_xml_escape() from compat/xml.h
 *      with flag XROOTD_XML_ESCAPE_CONTROL_PERCENT. Pre-sizes buffer via escaped_len(),
 *      allocates from nginx pool, calls escape(), returns pointer on success or NULL
 *      on OOM/badarg.
 *
 * RETURN: Pointer to escaped string (allocated from pool) on success; NULL on failure.
 */
char *webdav_escape_xml_text(ngx_pool_t *pool, const char *src);

#endif /* XROOTD_WEBDAV_UTIL_XML_H */

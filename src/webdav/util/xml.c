/*
 * xml.c — XML text escaping helpers for WebDAV response bodies.
 *
 * WHAT: Provides `webdav_escape_xml_text()` — escapes a string for safe inclusion in
 *       XML text response bodies by converting dangerous characters to their XML entity
 *       equivalents (& → &amp;, < → &lt;, > → &gt;, " → &quot;, ' → &#39;). Control
 *       characters (< 0x20 or 0x7f) are percent-encoded as %XX instead of using XML
 *       entities because control chars don't have standard entity names. The result is
 *       allocated from the nginx request pool. Returns NULL on OOM or if pool/src are
 *       NULL. All callers use this for PROPFIND, LOCK, and HEAD response XML generation
 *       where filesystem paths or metadata may contain special characters.
 *
 * WHY: WebDAV response bodies (PROPFIND Multi-Status, LOCK responses, HEAD property
 *      values) embed raw filesystem paths, lock owner names, and metadata as XML text.
 *      Without escaping, a filename containing "&" or "<" would corrupt the XML structure
 *      — e.g. `<DisplayName>data&file</DisplayName>` becomes two elements instead of one.
 *      Control bytes in filenames (rare but possible from wire protocol) have no standard
 *      XML entity names; percent-encoding them avoids parser confusion.
 *
 * HOW: The function delegates to `xrootd_xml_escaped_len()` and `xrootd_xml_escape()`
 *      from src/compat/xml.h with the flag `XROOTD_XML_ESCAPE_CONTROL_PERCENT`. Steps:
 *        1. Guard against NULL pool or NULL src → return NULL immediately.
 *        2. Compute src_len via strlen() (src is a C string).
 *        3. Call xrootd_xml_escaped_len() to get the exact byte length of escaped output
 *           including NUL terminator space — avoids double-pass allocation.
 *        4. Allocate from nginx request pool via ngx_pnalloc() — ensures cleanup on
 *           request completion without explicit free calls.
 *        5. Guard against OOM (ngx_pnalloc returns NULL).
 *        6. Call xrootd_xml_escape() to produce the escaped buffer; guard against
 *           failure (-1 return = overflow or badarg).
 *        7. Return pointer to escaped buffer (cast from u_char*).
 *
 * DEPENDENCIES: src/compat/xml.h (xrootd_xml_escaped_len, xrootd_xml_escape), nginx pool API
 * SEE ALSO: webdav/propfind.c (PROPFIND XML generation), webdav/lock.c (LOCK responses)
 */

#include "xml.h"
#include "core/compat/xml.h"

#include <string.h>
#include "core/compat/alloc_guard.h"

/**
 * WHAT: Escape a string for safe inclusion in XML text response bodies.
 *
 * Converts dangerous characters to their XML entity equivalents: & to &amp;,
 * < to &lt;, > to &gt;, " to &quot;, and ' to &#39;. Control characters
 * (< 0x20 or 0x7f) are percent-encoded as %XX instead of using XML entities because
 * control chars don't have standard entity names and would confuse XML parsers. The
 * result is allocated from the nginx request pool after asking the shared
 * compat XML adapter for the exact escaped length. Returns NULL
 * on OOM or if pool/src are NULL. All callers use this for PROPFIND, LOCK, and HEAD
 * response XML generation where filesystem paths or metadata may contain special chars.
 */
char *
webdav_escape_xml_text(ngx_pool_t *pool, const char *src)
{
    u_char       *escaped;
    size_t        src_len;
    size_t        escaped_len;

    if (pool == NULL || src == NULL) {
        return NULL;
    }

    src_len = strlen(src);
    escaped_len = xrootd_xml_escaped_len((const u_char *) src, src_len,
                                         XROOTD_XML_ESCAPE_CONTROL_PERCENT);
    XROOTD_PNALLOC_OR_RETURN(escaped, pool, escaped_len + 1, NULL);

    if (xrootd_xml_escape((const u_char *) src, src_len,
                          XROOTD_XML_ESCAPE_CONTROL_PERCENT,
                          escaped, escaped_len + 1, NULL) != 0)
    {
        return NULL;
    }

    return (char *) escaped;
}

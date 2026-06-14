#include "xml.h"
#include "hex.h"

#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * xml.c — XML escaping, text-element generation, and lockinfo parsing.
 *
 * WHAT: Implements the functions declared in xml.h for escaping XML-special
 *       characters (& < > " '), generating wrapped text-elements,
 *       and parsing WebDAV <D:lockinfo> bodies. Pure C with no nginx deps.
 *
 * WHY: WebDAV LOCK/UNLOCK operations parse lockinfo XML to extract owner
 *      identity and scope (exclusive/shared). S3 error responses use
 *      text-element generation for structured XML output. All paths need
 *      consistent escaping to prevent XML injection into response bodies.
 *
 * HOW: Escaping functions iterate src byte-by-byte; special chars are replaced
 *      with entity strings (& → &amp;, < → &lt>, etc.). Control bytes (<0x20,
 *      0x7f) are encoded as %XX when the CONTROL_PERCENT flag is set. The
 *      lockinfo parser uses libxml2 when available (XROOTD_HAVE_LIBXML2),
 *      falling back to a hand-written strnstr-based scanner otherwise.
 */

#define XROOTD_XML_MAX_LOCKINFO_BODY 65536u

/*
 * xrootd_xml_escaped_len - exact escaped length of src (excluding NUL).
 *
 * WHAT: returns how many bytes xrootd_xml_escape() will emit for the same
 *       (src, len, flags), so callers can size the destination first.
 * WHY:  the two functions are a sizing/writing pair; if their per-byte costs
 *       ever disagree, escape() either truncates or overruns. Keep the switch
 *       arms here byte-for-byte in lockstep with escape().
 * HOW:  each special char costs its entity length (minus the source byte);
 *       with CONTROL_PERCENT a control byte costs 3 ("%XX"); everything else
 *       costs 1. APOS flag selects &apos; vs &#39; — same choice as escape().
 */
size_t
xrootd_xml_escaped_len(const unsigned char *src, size_t len, unsigned flags)
{
    size_t i, out;

    if (src == NULL && len != 0) {
        return 0;
    }

    out = 0;
    for (i = 0; i < len; i++) {
        switch (src[i]) {
        case '&':
            out += sizeof("&amp;") - 1;
            break;
        case '<':
            out += sizeof("&lt;") - 1;
            break;
        case '>':
            out += sizeof("&gt;") - 1;
            break;
        case '"':
            out += sizeof("&quot;") - 1;
            break;
        case '\'':
            out += (flags & XROOTD_XML_ESCAPE_APOS_ENTITY)
                   ? sizeof("&apos;") - 1 : sizeof("&#39;") - 1;
            break;
        default:
            if ((flags & XROOTD_XML_ESCAPE_CONTROL_PERCENT)
                && (src[i] < 0x20 || src[i] == 0x7f))
            {
                out += 3;
            } else {
                out++;
            }
            break;
        }
    }

    return out;
}

/*
 * xrootd_xml_escape - write src into dst with XML-special chars entity-encoded.
 *
 * WHAT: produces an escaped, NUL-terminated copy of src in dst; *written (if
 *       non-NULL) receives the length excluding the NUL. Returns 0 / -1.
 * WHY:  any wire-derived text placed in a response body must be escaped or it
 *       can break out of its element (XML injection). This is the single
 *       escaper all XML/S3 builders route through.
 * HOW:  pre-flight the exact size via escaped_len and bail if dst can't hold
 *       it plus the NUL (no partial writes). Then advance `out` per char:
 *       the memcpy(...)+N idiom copies an entity and bumps the cursor by its
 *       literal length. The arms must mirror escaped_len() exactly.
 */
int
xrootd_xml_escape(const unsigned char *src, size_t len, unsigned flags,
    unsigned char *dst, size_t dst_size, size_t *written)
{
    unsigned char *out, *end;
    size_t         i, need;

    if ((src == NULL && len != 0) || dst == NULL || dst_size == 0) {
        return -1;
    }

    /* Size-check up front so the loop below can write unconditionally. */
    need = xrootd_xml_escaped_len(src, len, flags);
    if (need + 1 > dst_size) {
        return -1;
    }

    out = dst;
    end = dst + dst_size;

    for (i = 0; i < len; i++) {
        switch (src[i]) {
        case '&':
            out = (unsigned char *) memcpy(out, "&amp;", 5) + 5;
            break;
        case '<':
            out = (unsigned char *) memcpy(out, "&lt;", 4) + 4;
            break;
        case '>':
            out = (unsigned char *) memcpy(out, "&gt;", 4) + 4;
            break;
        case '"':
            out = (unsigned char *) memcpy(out, "&quot;", 6) + 6;
            break;
        case '\'':
            if (flags & XROOTD_XML_ESCAPE_APOS_ENTITY) {
                out = (unsigned char *) memcpy(out, "&apos;", 6) + 6;
            } else {
                out = (unsigned char *) memcpy(out, "&#39;", 5) + 5;
            }
            break;
        default:
            /* Control bytes (< 0x20, plus DEL 0x7f) become "%XX" — high
             * nibble then low nibble — when the flag is set; this keeps raw
             * control chars out of the body. Otherwise emit the byte as-is. */
            if ((flags & XROOTD_XML_ESCAPE_CONTROL_PERCENT)
                && (src[i] < 0x20 || src[i] == 0x7f))
            {
                *out++ = '%';
                *out++ = xrootd_hex_nibble((unsigned char) (src[i] >> 4));
                *out++ = xrootd_hex_nibble((unsigned char) (src[i] & 0x0f));
            } else {
                *out++ = src[i];
            }
            break;
        }
    }

    /* Belt-and-suspenders: the pre-flight guarantees room, but re-check that
     * the NUL slot is still inside dst before writing the terminator. */
    if (out >= end) {
        return -1;
    }
    *out = '\0';

    if (written != NULL) {
        *written = (size_t) (out - dst);
    }

    return 0;
}

/*
 * xrootd_xml_element_name_valid - reject element names that aren't safe to
 * emit unescaped. WHY: the tag name is written verbatim (not escaped) by
 * write_text_element, so it is restricted to an allowlist of name chars to
 * prevent any '<', '>', or whitespace from forging markup.
 */
static int
xrootd_xml_element_name_valid(const char *name)
{
    const unsigned char *p;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }

    for (p = (const unsigned char *) name; *p != '\0'; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
            || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'
            || *p == '.' || *p == ':')
        {
            continue;
        }

        return 0;
    }

    return 1;
}

/*
 * xrootd_xml_text_element_len - byte length of "<name>escaped(text)</name>"
 * (excluding NUL), or 0 if the name is invalid. Sizing partner of
 * write_text_element: 2*name (open + close tag) + the 5 punctuation bytes of
 * "<></>" + the escaped text length.
 */
size_t
xrootd_xml_text_element_len(const char *name, const unsigned char *text,
    size_t text_len, unsigned flags)
{
    size_t name_len;

    if (!xrootd_xml_element_name_valid(name)
        || (text == NULL && text_len != 0))
    {
        return 0;
    }

    name_len = strlen(name);
    return 2 * name_len + sizeof("<></>") - 1
           + xrootd_xml_escaped_len(text, text_len, flags);
}

/*
 * xrootd_xml_write_text_element - emit "<name>escaped(text)</name>\0" to dst.
 *
 * WHAT: writes a complete text element; *written (if non-NULL) gets the length
 *       excluding the NUL. Returns 0 / -1.
 * WHY:  the one helper used to build leaf elements (S3 error fields, etc.);
 *       name is validated so it can be written unescaped, text is escaped so
 *       it can't break the element.
 * HOW:  pre-size with the same formula as text_element_len and bail if dst is
 *       too small. Then write '<', name, '>', the escaped body (delegated to
 *       xrootd_xml_escape, which also NUL-terminates into the remaining
 *       space), advance past it, then "</", name, ">", and the final NUL.
 */
int
xrootd_xml_write_text_element(const char *name, const unsigned char *text,
    size_t text_len, unsigned flags, unsigned char *dst, size_t dst_size,
    size_t *written)
{
    unsigned char *out;
    size_t         name_len, escaped_len, escaped_written, need;

    if (!xrootd_xml_element_name_valid(name) || dst == NULL || dst_size == 0
        || (text == NULL && text_len != 0))
    {
        return -1;
    }

    name_len = strlen(name);
    escaped_len = xrootd_xml_escaped_len(text, text_len, flags);
    need = 2 * name_len + sizeof("<></>") - 1 + escaped_len;
    if (need + 1 > dst_size) {
        return -1;
    }

    out = dst;
    *out++ = '<';
    out = (unsigned char *) memcpy(out, name, name_len) + name_len;
    *out++ = '>';

    if (xrootd_xml_escape(text, text_len, flags, out,
                          dst_size - (size_t) (out - dst),
                          &escaped_written) != 0)
    {
        return -1;
    }
    out += escaped_written;

    *out++ = '<';
    *out++ = '/';
    out = (unsigned char *) memcpy(out, name, name_len) + name_len;
    *out++ = '>';
    *out = '\0';

    if (written != NULL) {
        *written = (size_t) (out - dst);
    }

    return 0;
}

static int
xrootd_xml_name_is(const char *name, const char *want)
{
    return name != NULL && strcmp(name, want) == 0;
}


/* find_child: first DIRECT element child of node whose local name matches
 * (one level only — namespace prefix is ignored, libxml strips it from name). */
static xmlNodePtr
xrootd_xml_find_child(xmlNodePtr node, const char *name)
{
    xmlNodePtr cur;

    for (cur = node == NULL ? NULL : node->children; cur != NULL; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE
            && xrootd_xml_name_is((const char *) cur->name, name))
        {
            return cur;
        }
    }

    return NULL;
}

/* find_descendant: depth-first search over node and its siblings/children for
 * the first matching element name, at any depth (used to locate <href> wherever
 * the client nested it inside <owner>). */
static xmlNodePtr
xrootd_xml_find_descendant(xmlNodePtr node, const char *name)
{
    xmlNodePtr cur, found;

    if (node == NULL) {
        return NULL;
    }

    for (cur = node; cur != NULL; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE
            && xrootd_xml_name_is((const char *) cur->name, name))
        {
            return cur;
        }

        found = xrootd_xml_find_descendant(cur->children, name);
        if (found != NULL) {
            return found;
        }
    }

    return NULL;
}

/* copy_content: copy a node's flattened text content into a fixed dst buffer,
 * truncating to dst_len-1 and always NUL-terminating. Frees the libxml-owned
 * string. WHY ownership matters: xmlNodeGetContent allocates, so the xmlFree
 * here is required to avoid leaking on every lockinfo parse. */
static void
xrootd_xml_copy_content(xmlNodePtr node, char *dst, size_t dst_len)
{
    xmlChar *content;
    size_t   len;

    if (dst_len == 0 || node == NULL) {
        return;
    }

    content = xmlNodeGetContent(node);
    if (content == NULL) {
        return;
    }

    len = strlen((const char *) content);
    if (len >= dst_len) {
        len = dst_len - 1;
    }

    memcpy(dst, content, len);
    dst[len] = '\0';
    xmlFree(content);
}



/*
 * xrootd_xml_parse_lockinfo - extract owner + scope from a WebDAV LOCK body.
 *
 * WHAT: parses a <D:lockinfo> document, writing the lock owner (from
 *       <owner><href> if present, else <owner>) into owner[], and setting
 *       *exclusive to 0 only when <lockscope><shared> is present.
 * WHY:  drives the WebDAV lock table; the owner string and exclusivity decide
 *       who may later UNLOCK / overwrite.
 * HOW (and the security posture):
 *   - Outputs are initialised to SAFE DEFAULTS up front (empty owner,
 *     *exclusive=1) so any early-return / parse failure denies, never grants,
 *     a shared lock.
 *   - The body is size-capped (XROOTD_XML_MAX_LOCKINFO_BODY) before parsing.
 *   - libxml flags disable network access and external-entity expansion
 *     (NONET, and NO_XXE where available) — XXE/SSRF hardening for untrusted
 *     client XML. NOERROR/NOWARNING keep libxml from logging to stderr.
 */
int
xrootd_xml_parse_lockinfo(const char *xml, size_t xml_len,
    char *owner, size_t owner_len, int *exclusive)
{
    /* Default-deny: empty owner and exclusive=1 hold on every failure path. */
    if (owner_len > 0 && owner != NULL) {
        owner[0] = '\0';
    }
    if (exclusive != NULL) {
        *exclusive = 1;
    }

    /* Reject null outputs and oversized bodies before touching the parser. */
    if (xml == NULL || owner == NULL || owner_len == 0 || exclusive == NULL
        || xml_len > XROOTD_XML_MAX_LOCKINFO_BODY)
    {
        return -1;
    }

    {
        xmlDocPtr  doc;
        xmlNodePtr root, owner_node, href_node, scope_node;
        int        options;

        /* NONET + NO_XXE: no network fetches, no external entity expansion. */
        options = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
#if defined(XML_PARSE_NO_XXE)
        options |= XML_PARSE_NO_XXE;
#endif

        doc = xmlReadMemory(xml, (int) xml_len, "lockinfo.xml", NULL, options);
        if (doc == NULL) {
            return -1;
        }

        /* Require the document root to actually be <lockinfo>. */
        root = xmlDocGetRootElement(doc);
        if (root == NULL
            || !xrootd_xml_name_is((const char *) root->name, "lockinfo"))
        {
            xmlFreeDoc(doc);
            return -1;
        }

        /* Owner: prefer the <href> nested inside <owner> (RFC 4918's typical
         * form); fall back to the raw text of <owner> if there's no href. */
        owner_node = xrootd_xml_find_child(root, "owner");
        href_node = xrootd_xml_find_descendant(owner_node == NULL
                                               ? NULL : owner_node->children,
                                               "href");
        if (href_node != NULL) {
            xrootd_xml_copy_content(href_node, owner, owner_len);
        } else if (owner_node != NULL) {
            xrootd_xml_copy_content(owner_node, owner, owner_len);
        }

        /* Scope is exclusive unless <lockscope><shared> is explicitly given. */
        scope_node = xrootd_xml_find_child(root, "lockscope");
        if (xrootd_xml_find_child(scope_node, "shared") != NULL) {
            *exclusive = 0;
        }

        xmlFreeDoc(doc);
        return 0;
    }
}

const char *
xrootd_xml_backend_name(void)
{
    return "libxml2";
}

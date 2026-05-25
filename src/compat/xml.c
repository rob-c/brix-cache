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

int
xrootd_xml_escape(const unsigned char *src, size_t len, unsigned flags,
    unsigned char *dst, size_t dst_size, size_t *written)
{
    unsigned char *out, *end;
    size_t         i, need;

    if ((src == NULL && len != 0) || dst == NULL || dst_size == 0) {
        return -1;
    }

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

    if (out >= end) {
        return -1;
    }
    *out = '\0';

    if (written != NULL) {
        *written = (size_t) (out - dst);
    }

    return 0;
}

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



int
xrootd_xml_parse_lockinfo(const char *xml, size_t xml_len,
    char *owner, size_t owner_len, int *exclusive)
{
    if (owner_len > 0 && owner != NULL) {
        owner[0] = '\0';
    }
    if (exclusive != NULL) {
        *exclusive = 1;
    }

    if (xml == NULL || owner == NULL || owner_len == 0 || exclusive == NULL
        || xml_len > XROOTD_XML_MAX_LOCKINFO_BODY)
    {
        return -1;
    }

    {
        xmlDocPtr  doc;
        xmlNodePtr root, owner_node, href_node, scope_node;
        int        options;

        options = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
#if defined(XML_PARSE_NO_XXE)
        options |= XML_PARSE_NO_XXE;
#endif

        doc = xmlReadMemory(xml, (int) xml_len, "lockinfo.xml", NULL, options);
        if (doc == NULL) {
            return -1;
        }

        root = xmlDocGetRootElement(doc);
        if (root == NULL
            || !xrootd_xml_name_is((const char *) root->name, "lockinfo"))
        {
            xmlFreeDoc(doc);
            return -1;
        }

        owner_node = xrootd_xml_find_child(root, "owner");
        href_node = xrootd_xml_find_descendant(owner_node == NULL
                                               ? NULL : owner_node->children,
                                               "href");
        if (href_node != NULL) {
            xrootd_xml_copy_content(href_node, owner, owner_len);
        } else if (owner_node != NULL) {
            xrootd_xml_copy_content(owner_node, owner, owner_len);
        }

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

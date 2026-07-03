#ifndef BRIX_COMPAT_XML_H
#define BRIX_COMPAT_XML_H

#include <stddef.h>
/*
 * xml.h — XML escaping, text-element generation, and lockinfo parsing.
 *
 * WHAT: Declares functions for percent-escaping XML content, building
 *       <name>text</name> elements, and parsing WebDAV <D:lockinfo> bodies.
 *       Pure C; no nginx deps. Supports libxml2 or a built-in fallback parser.
 *
 * WHY: WebDAV LOCK/UNLOCK operations parse <lockinfo> XML from request bodies
 *      to extract owner and lock scope. S3 error responses and XrdHttp stats
 *      use text-element generation for structured XML output. All paths need
 *      consistent escaping to prevent injection attacks.
 *
 * HOW: When libxml2 is available (BRIX_HAVE_LIBXML2), xml_parse_lockinfo uses
 *      the real parser; otherwise falls back to a hand-written strnstr-based
 *      scanner. Escaping and text-element functions are always available.
 */

/*
 * Flags for brix_xml_escape / brix_xml_write_text_element.
 *
 * Combine with bitwise OR; each flag controls one escape behaviour.
 */
#define BRIX_XML_ESCAPE_APOS_ENTITY      0x0001u  /* encode ' as &apos; instead of &#39; */
#define BRIX_XML_ESCAPE_CONTROL_PERCENT 0x0002u  /* encode control chars (<0x20, 0x7f) as %XX */

/*
 * brix_xml_escaped_len — compute the byte length of src after XML escaping.
 *
 * WHAT: Scans src[0..len] and returns the total number of bytes that would be
 *       produced by brix_xml_escape(), including space for a NUL terminator.
 *
 * WHY: Callers need to know the output size before allocating a buffer —
 *      avoids double-pass allocation or overflow. Used by
 *      brix_xml_write_text_element() and WebDAV lock response building.
 *
 * HOW: Iterate src bytes; each special char (& < > " ') expands to an entity;
 *      control chars expand to %XX when flag is set; otherwise pass through.
 */
size_t brix_xml_escaped_len(const unsigned char *src, size_t len,
    unsigned flags);

/*
 * brix_xml_escape — escape XML-special characters in a byte buffer.
 *
 * WHAT: Scans src[0..len] and writes the escaped result to dst. Special chars
 *       (& < > " ') are replaced with XML entities; control bytes (<0x20, 0x7f)
 *       are encoded as %XX when BRIX_XML_ESCAPE_CONTROL_PERCENT is set.
 *
 * WHY: WebDAV lock owners, S3 error messages, and protocol metadata may contain
 *      XML-sensitive characters. Escaping prevents injection into response bodies.
 *
 * HOW: Iterate src byte-by-byte; switch on special chars → emit entity strings;
 *      control chars → emit %XX via brix_hex_nibble(); default → copy raw.
 *      Pre-checks size against escaped_len() to avoid overflow. Null-terminates dst.
 *
 * Parameters:
 *   src       — input bytes to escape
 *   len       — length of the input buffer (src may be NULL when len == 0)
 *   flags     — combination of BRIX_XML_ESCAPE_* flags (0 = default behaviour)
 *   dst       — output buffer for escaped result
 *   dst_size  — total size of the output buffer (must accommodate escaped_len + 1)
 *   written   — optional pointer to receive the actual byte count written (excl. NUL)
 *
 * Returns:
 *   0  — success; NUL terminator written at dst[written]
 *   -1 — overflow, badarg (dst NULL or dst_size == 0), or src NULL with len != 0
 */
int brix_xml_escape(const unsigned char *src, size_t len, unsigned flags,
    unsigned char *dst, size_t dst_size, size_t *written);

/*
 * brix_xml_text_element_len — compute byte length of a <name>text</name> element.
 *
 * WHAT: Returns the total bytes needed for an XML text-element wrapping text in
 *       a tag named name, including escaping overhead and NUL terminator space.
 *
 * WHY: Pre-sizes buffers before calling brix_xml_write_text_element(). Used by
 *      S3 error responses and WebDAV PROPFIND property values.
 *
 * HOW: Validates the element name (alphanumeric + _-.:), computes tag overhead
 *      (2 × name_len + 7 for <></>), adds escaped text length.
 */
size_t brix_xml_text_element_len(const char *name,
    const unsigned char *text, size_t text_len, unsigned flags);

/*
 * brix_xml_write_text_element — write an XML <name>escaped-text</name> element.
 *
 * WHAT: Writes a complete XML text-element to dst: opening tag, escaped text body,
 *       closing tag. Validates the element name and checks buffer capacity.
 *
 * WHY: S3 error responses (e.g., <Message>...</Message>) and WebDAV PROPFIND
 *      property values use this pattern. Produces well-formed XML suitable for
 *      HTTP response bodies.
 *
 * HOW: Validates name via brix_xml_element_name_valid(). Computes escaped_len()
 *      to check capacity. Writes <name>, calls brix_xml_escape() on text body,
 *      writes </name>. Null-terminates dst.
 *
 * Parameters:
 *   name       — element tag name (alphanumeric + _-.: only)
 *   text       — text content to escape and wrap
 *   text_len   — length of the text buffer (text may be NULL when text_len == 0)
 *   flags      — escaping flags for brix_xml_escape()
 *   dst        — output buffer for the complete element
 *   dst_size   — total size of the output buffer
 *   written    — optional pointer to receive byte count written (excl. NUL)
 *
 * Returns:
 *   0  — success; complete <name>text</name> written and null-terminated
 *   -1 — overflow, badarg, or invalid element name
 */
int brix_xml_write_text_element(const char *name,
    const unsigned char *text, size_t text_len, unsigned flags,
    unsigned char *dst, size_t dst_size, size_t *written);

/*
 * brix_xml_parse_lockinfo — parse WebDAV <lockinfo> XML body.
 *
 * WHAT: Extracts the lock owner and scope (exclusive vs shared) from a
 *       <D:lockinfo> XML document. Uses libxml2 when available; falls back
 *       to a built-in strnstr-based parser otherwise.
 *
 * WHY: WebDAV LOCK requests carry a <lockinfo> body containing the owner
 *      identity and lock scope. This function extracts those fields so the
 *      lock handler can store them in fd_table entry metadata.
 *
 * HOW: libxml2 path: parse with XML_PARSE_NONET|NOERROR|NOWARNING, find root
 *      <lockinfo> → child <owner> → descendant <href> (or direct owner content)
 *      → child <lockscope> → check for <shared/> tag. Fallback path: strnstr
 *      scan for D:owner / </D:owner> and D:lockscope / </D:lockscope> tags.
 *
 * Parameters:
 *   xml        — XML body bytes (may not exceed BRIX_XML_MAX_LOCKINFO_BODY)
 *   xml_len    — length of the XML buffer
 *   owner      — output buffer for extracted owner identity
 *   owner_len  — size of the owner output buffer
 *   exclusive  — output pointer: set to 1 if exclusive, 0 if shared scope
 *
 * Returns:
 *   0  — success; owner and exclusive populated
 *   -1 — badarg (NULL pointers, zero-length buffers), or XML exceeds max size
 */
int brix_xml_parse_lockinfo(const char *xml, size_t xml_len,
    char *owner, size_t owner_len, int *exclusive);

/*
 * brix_xml_backend_name — return the name of the active XML parsing backend.
 *
 * WHAT: Returns a static string identifying whether libxml2 or the built-in
 *       fallback parser is in use for this build.
 *
 * WHY: Diagnostics and access logs report which XML backend handled lockinfo
 *      parsing. Useful when troubleshooting XXE vulnerabilities (libxml2
 *      supports XML_PARSE_NO_XXE; fallback does not).
 */
const char *brix_xml_backend_name(void);
#endif /* BRIX_COMPAT_XML_H */

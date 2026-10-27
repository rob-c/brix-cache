/*
 * net_target_parse.c — URL grammar for outbound transfer targets.
 * Owns the zero-copy URL grammar and its sub-step helpers. See net_target.h
 * for the API; transport policy and effective ports live in net_target_policy.c.
 */

#include "net_target.h"
#include "net_target_internal.h"
#include "cstr.h"
#include "../types/tunables.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/*
 * net_url_span_t — authority view and shared parse-error sink.
 * WHAT: Names the zero-copy authority bounds and caller-owned error buffer.
 * WHY: Keeps the sub-parser interfaces explicit and within the parameter budget.
 * HOW: 1. Point both cursors into the URL. 2. Borrow the error buffer.
 */
typedef struct {
    const u_char *host_start;
    const u_char *host_end;
    char         *err;
    size_t        errsz;
} net_url_span_t;

/*
 * net_ascii_alpha — classify one byte as an ASCII letter.
 * WHAT: Returns non-zero exactly for A-Z and a-z.
 * WHY: URL grammar must not depend on the process locale.
 * HOW: 1. Fold ASCII case. 2. Test the contiguous lower-case range.
 */
static int
net_ascii_alpha(u_char value)
{
    unsigned folded = (unsigned) value | 0x20U;

    return folded - (unsigned) 'a' <= (unsigned) ('z' - 'a');
}

/*
 * net_ascii_digit — classify one byte as an ASCII decimal digit.
 * WHAT: Returns non-zero exactly for 0-9.
 * WHY: Numeric URL fields require locale-independent ASCII semantics.
 * HOW: 1. Offset from '0'. 2. Test the unsigned decimal range.
 */
static int
net_ascii_digit(u_char value)
{
    return (unsigned) (value - (u_char) '0') <= 9U;
}

/*
 * net_ascii_hex_digit — classify one byte as an ASCII hexadecimal digit.
 * WHAT: Returns non-zero exactly for 0-9, A-F and a-f.
 * WHY: Legacy numeric-host detection must recognize the whole bounded token.
 * HOW: 1. Accept decimal. 2. Fold case and test the a-f range.
 */
static int
net_ascii_hex_digit(u_char value)
{
    unsigned folded = (unsigned) value | 0x20U;

    return net_ascii_digit(value)
           || folded - (unsigned) 'a' <= (unsigned) ('f' - 'a');
}

/*
 * net_span_chars_valid — validate every byte with a pure classifier.
 * WHAT: Returns non-zero for a nonempty span whose bytes all satisfy valid().
 * WHY: Decimal and hexadecimal host components share identical bounded scans.
 * HOW: 1. Reject empty input. 2. Stop at the first rejected byte.
 */
static int
net_span_chars_valid(const u_char *begin, const u_char *end,
    int (*valid)(u_char))
{
    const u_char *cursor;

    if (begin == end) {
        return 0;
    }
    for (cursor = begin; cursor < end; cursor++) {
        if (!valid(*cursor)) {
            return 0;
        }
    }
    return 1;
}

/*
 * net_url_bytes_valid — reject URL bytes with parser-dependent meanings.
 * WHAT: Returns NGX_OK for printable, non-space ASCII without backslashes.
 * WHY: Transfer and policy parsers must retain one byte-for-byte interpretation.
 * HOW: 1. Scan the bounded URL. 2. Report the first unsafe class.
 */
static ngx_int_t
net_url_bytes_valid(const ngx_str_t *url, char *err, size_t errsz)
{
    size_t  i;

    for (i = 0; i < url->len; i++) {
        if (url->data[i] <= 0x20 || url->data[i] == 0x7f
            || url->data[i] == '\\')
        {
            snprintf(err, errsz, "URL contains an unsafe byte");
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/*
 * net_scheme_chars_valid — enforce the RFC 3986 scheme token grammar.
 * WHAT: Returns non-zero for ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
 * WHY: Separator discovery alone does not validate the scheme token.
 * HOW: 1. Require initial ALPHA. 2. Classify each remaining byte.
 */
static int
net_scheme_chars_valid(const u_char *begin, const u_char *end)
{
    const u_char *cursor;

    if (begin == end || !net_ascii_alpha(*begin)) {
        return 0;
    }

    for (cursor = begin + 1; cursor < end; cursor++) {
        if (!net_ascii_alpha(*cursor) && !net_ascii_digit(*cursor)
            && *cursor != '+' && *cursor != '-' && *cursor != '.')
        {
            return 0;
        }
    }
    return 1;
}

/*
 * net_parse_scheme — locate "://" and record the scheme slice.
 * WHAT: Records the scheme and returns the first authority byte, or NULL.
 * WHY: Keeps scheme grammar independent from authority grammar.
 * HOW: 1. Find "://". 2. Validate the token. 3. Return its zero-copy boundary.
 */
static const u_char *
net_parse_scheme(const ngx_str_t *url, brix_net_target_t *out,
    char *err, size_t errsz)
{
    const u_char *p   = url->data;
    const u_char *end = url->data + url->len;
    const u_char *scheme_end = NULL;
    const u_char *host_start;

    for (const u_char *q = p; q + 2 < end; q++) {
        if (q[0] == ':' && q[1] == '/' && q[2] == '/') {
            scheme_end = q;
            break;
        }
    }

    if (scheme_end == NULL) {
        snprintf(err, errsz, "URL missing '://' separator");
        return NULL;
    }

    out->scheme.data = (u_char *) p;
    out->scheme.len  = (size_t) (scheme_end - p);

    if (!net_scheme_chars_valid(p, scheme_end)) {
        snprintf(err, errsz, "URL has invalid scheme");
        return NULL;
    }

    host_start = scheme_end + 3;
    if (host_start >= end) {
        snprintf(err, errsz, "URL has no host after '://'");
        return NULL;
    }

    return host_start;
}

/*
 * net_parse_port_digits — parse a digits-only port field in [begin, end).
 * WHAT: Writes a port in 1..65535 and returns NGX_OK, or reports NGX_ERROR.
 * WHY: Bracketed and plain authorities must share one exact port grammar.
 * HOW: 1. Require digits. 2. Accumulate with a range clamp. 3. Refuse zero.
 */
static ngx_int_t
net_parse_port_digits(const u_char *begin, const u_char *end,
    uint16_t *out_port, char *err, size_t errsz)
{
    unsigned long p_val = 0;

    if (begin == end) {
        snprintf(err, errsz, "URL has empty port");
        return NGX_ERROR;
    }

    for (const u_char *d = begin; d < end; d++) {
        if (*d < '0' || *d > '9') {
            snprintf(err, errsz, "invalid port in URL");
            return NGX_ERROR;
        }
        p_val = p_val * 10 + (*d - '0');
        if (p_val > BRIX_MAX_PORT) {
            snprintf(err, errsz, "port out of range");
            return NGX_ERROR;
        }
    }

    if (p_val == 0) {
        snprintf(err, errsz, "port must be between 1 and 65535");
        return NGX_ERROR;
    }

    *out_port = (uint16_t) p_val;
    return NGX_OK;
}

/*
 * net_ipv6_literal_valid — validate the contents of a bracketed host.
 * WHAT: Returns non-zero only for bounded RFC IPv6 text accepted by inet_pton.
 * WHY: Brackets identify syntax; they do not prove the contents are an address.
 * HOW: 1. Copy the slice safely. 2. Parse it without name-service lookup.
 */
static int
net_ipv6_literal_valid(const u_char *begin, const u_char *end)
{
    struct in6_addr  address;
    char             text[INET6_ADDRSTRLEN];
    size_t           length = (size_t) (end - begin);

    if (brix_cbuf_copy(text, sizeof(text), begin, length) == NULL) {
        return 0;
    }
    return inet_pton(AF_INET6, text, &address) == 1;
}

/*
 * net_ipv4_numeric_component — classify one legacy numeric IPv4 component.
 * WHAT: Returns non-zero for a decimal or 0x-prefixed hexadecimal component.
 * WHY: Legacy numeric host syntax must be refused rather than mistaken for DNS.
 * HOW: 1. Detect the hex prefix. 2. Validate the complete bounded span.
 */
static int
net_ipv4_numeric_component(const u_char *begin, const u_char *end)
{
    if (end - begin > 2 && begin[0] == '0'
        && (begin[1] == 'x' || begin[1] == 'X'))
    {
        return net_span_chars_valid(begin + 2, end, net_ascii_hex_digit);
    }

    return net_span_chars_valid(begin, end, net_ascii_digit);
}

/*
 * net_ipv4_numeric_style — identify an all-numeric legacy IPv4 authority.
 * WHAT: Returns non-zero for one to four numeric components and optional root dot.
 * WHY: Such hostname-shaped inputs may be reinterpreted as legacy IPv4 numbers.
 * HOW: 1. Split on dots. 2. Validate every component. 3. Bound their count.
 */
static int
net_ipv4_numeric_style(const u_char *begin, const u_char *end)
{
    const u_char *component = begin;
    const u_char *cursor;
    ngx_uint_t    count = 0;

    for (cursor = begin; cursor <= end; cursor++) {
        if (cursor < end && *cursor != '.') {
            continue;
        }
        if (cursor == component) {
            return cursor == end && cursor > begin && cursor[-1] == '.'
                   && count > 0 && count <= 4;
        }
        if (++count > 4
            || !net_ipv4_numeric_component(component, cursor))
        {
            return 0;
        }
        if (cursor == end) {
            return 1;
        }
        component = cursor + 1;
    }
    return 0;
}

/*
 * net_ipv4_canonical_decimal — accept only canonical dotted-decimal IPv4.
 * WHAT: Returns non-zero for four decimal octets without ambiguous leading zeroes.
 * WHY: This spelling has one interpretation across parser, DNS seam and libcurl.
 * HOW: 1. Accumulate bounded octets. 2. Reject ambiguity. 3. Require four.
 */
static int
net_ipv4_canonical_decimal(const u_char *begin, const u_char *end)
{
    const u_char *component = begin;
    const u_char *cursor;
    ngx_uint_t    count = 0;
    unsigned      value = 0;

    for (cursor = begin; cursor <= end; cursor++) {
        if (cursor < end && *cursor != '.') {
            if (*cursor < '0' || *cursor > '9') {
                return 0;
            }
            value = value * 10U + (unsigned) (*cursor - '0');
            if (value > 255U) {
                return 0;
            }
            continue;
        }
        if (cursor == component
            || (cursor - component > 1 && *component == '0'))
        {
            return 0;
        }
        count++;
        if (cursor == end) {
            return count == 4;
        }
        component = cursor + 1;
        value = 0;
    }
    return 0;
}
/*
 * net_parse_bracketed_host — parse an IPv6 literal authority "[addr][:port]".
 * WHAT: Fills the literal host and optional port, or reports NGX_ERROR.
 * WHY: IPv6 address colons cannot be treated as plain-host port delimiters.
 * HOW: 1. Bound and validate ']'. 2. Parse only a following ':NNN' as port.
 */
static ngx_int_t
net_parse_bracketed_host(const net_url_span_t *span, brix_net_target_t *out)
{
    const u_char *bracket_end = span->host_start + 1;
    const u_char *colon;

    while (bracket_end < span->host_end && *bracket_end != ']') {
        bracket_end++;
    }

    if (bracket_end >= span->host_end) {
        snprintf(span->err, span->errsz, "IPv6 literal missing closing ']'");
        return NGX_ERROR;
    }

    if (!net_ipv6_literal_valid(span->host_start + 1, bracket_end)) {
        snprintf(span->err, span->errsz, "invalid IPv6 literal in URL");
        return NGX_ERROR;
    }

    out->host.data = (u_char *) (span->host_start + 1);
    out->host.len  = (size_t) (bracket_end - (span->host_start + 1));

    colon = bracket_end + 1;
    if (colon == span->host_end) {
        return NGX_OK;
    }
    if (*colon != ':') {
        snprintf(span->err, span->errsz,
                 "unexpected bytes after IPv6 literal");
        return NGX_ERROR;
    }
    if (net_parse_port_digits(colon + 1, span->host_end, &out->port,
                              span->err, span->errsz) != NGX_OK)
    {
        return NGX_ERROR;
    }
    out->has_port = 1;

    return NGX_OK;
}

/*
 * net_hostname_label_char_valid — classify one DNS-label byte.
 * WHAT: Returns non-zero for an ASCII alphanumeric byte or hyphen.
 * WHY: Host validation must be locale-independent and must not decode input.
 * HOW: 1. Test ASCII letters/digits. 2. Admit the DNS hyphen punctuation.
 */
static int
net_hostname_label_char_valid(u_char value)
{
    return net_ascii_alpha(value) || net_ascii_digit(value) || value == '-';
}

/*
 * net_hostname_label_valid — validate one bounded DNS label.
 * WHAT: Returns non-zero for a 1..63-byte label without edge hyphens.
 * WHY: Isolating label grammar keeps the hostname splitter branch-light.
 * HOW: 1. Check bounds and edges. 2. Validate every byte.
 */
static int
net_hostname_label_valid(const u_char *begin, const u_char *end)
{
    size_t length = (size_t) (end - begin);

    if (length == 0 || length > 63) {
        return 0;
    }
    if (*begin == '-' || end[-1] == '-') {
        return 0;
    }
    return net_span_chars_valid(begin, end, net_hostname_label_char_valid);
}

/*
 * net_plain_host_valid — validate a DNS hostname or IPv4 spelling.
 * WHAT: Returns non-zero for a bounded dot-separated ASCII hostname.
 * WHY: URL, DNS and transfer libraries must agree on the unmodified authority.
 * HOW: 1. Reject ambiguous numeric style. 2. Validate labels and optional root dot.
 */
static int
net_plain_host_valid(const u_char *begin, const u_char *end)
{
    const u_char *label_start = begin;
    const u_char *cursor;
    size_t        length = (size_t) (end - begin);

    if (length == 0 || length > 253) {
        return 0;
    }
    if (net_ipv4_numeric_style(begin, end)
        && !net_ipv4_canonical_decimal(begin, end))
    {
        return 0;
    }

    for (cursor = begin; cursor < end; cursor++) {
        if (*cursor != '.') {
            continue;
        }
        if (!net_hostname_label_valid(label_start, cursor)) {
            return 0;
        }
        label_start = cursor + 1;
    }

    if (label_start == end) {
        return end > begin + 1;
    }
    return net_hostname_label_valid(label_start, end);
}

/*
 * net_parse_plain_host — parse a hostname / IPv4 authority "host[:port]".
 * WHAT: Fills the host and optional port, or reports NGX_ERROR.
 * WHY: Multiple colons must reject bare IPv6 instead of truncating its host.
 * HOW: 1. Count colons. 2. Parse one final port. 3. Validate the host slice.
 */
static ngx_int_t
net_parse_plain_host(const net_url_span_t *span, brix_net_target_t *out)
{
    const u_char *colon = NULL;
    const u_char *host_end;
    ngx_uint_t    colon_count = 0;

    for (const u_char *q = span->host_start; q < span->host_end; q++) {
        if (*q == ':') {
            colon = q;
            colon_count++;
        }
    }

    if (colon_count > 1) {
        snprintf(span->err, span->errsz,
                 "IPv6 literals must use brackets");
        return NGX_ERROR;
    }

    if (colon == NULL) {
        out->host.data = (u_char *) span->host_start;
        out->host.len  = (size_t) (span->host_end - span->host_start);
        host_end = span->host_end;
    } else {
        if (net_parse_port_digits(colon + 1, span->host_end, &out->port,
                                  span->err, span->errsz) != NGX_OK)
        {
            return NGX_ERROR;
        }

        out->host.data = (u_char *) span->host_start;
        out->host.len  = (size_t) (colon - span->host_start);
        out->has_port  = 1;
        host_end = colon;
    }

    if (!net_plain_host_valid(span->host_start, host_end)) {
        snprintf(span->err, span->errsz, "invalid host in URL");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * net_parse_authority — parse the host[:port] authority after "://".
 * WHAT: Fills host and port through the bracketed or plain grammar.
 * WHY: One dispatch point keeps both authority grammars independent.
 * HOW: 1. Refuse userinfo. 2. Dispatch a leading '[' to the IPv6 parser.
 */
static ngx_int_t
net_parse_authority(const net_url_span_t *span, brix_net_target_t *out)
{
    const u_char *cursor;

    for (cursor = span->host_start; cursor < span->host_end; cursor++) {
        if (*cursor == '@') {
            snprintf(span->err, span->errsz,
                     "URL userinfo is not allowed");
            return NGX_ERROR;
        }
    }

    if (span->host_start < span->host_end && *span->host_start == '[') {
        return net_parse_bracketed_host(span, out);
    }

    return net_parse_plain_host(span, out);
}

/*
 * brix_net_target_parse — split "scheme://host[:port][/path]" into fields.
 * WHAT: Fills zero-copy scheme, host, port and path slices, or returns NGX_ERROR.
 * WHY: Remote targets must be decomposed before SSRF and DNS-pin policy checks.
 * HOW: 1. Validate bytes. 2. Parse scheme/authority. 3. Retain the path suffix.
 */
ngx_int_t
brix_net_target_parse(ngx_pool_t *pool,
    const ngx_str_t *url, brix_net_target_t *out,
    char *err, size_t errsz)
{
    const u_char   *end, *host_start, *host_end;
    net_url_span_t  span;

    (void) pool; /* zero-copy: all fields point into url->data */

    if (url == NULL || url->data == NULL || url->len == 0) {
        snprintf(err, errsz, "empty URL");
        return NGX_ERROR;
    }
    if (net_url_bytes_valid(url, err, errsz) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(*out));
    out->raw_url = *url;

    end = url->data + url->len;

    host_start = net_parse_scheme(url, out, err, errsz);
    if (host_start == NULL) {
        return NGX_ERROR;
    }

    /* Find end of authority — first path, query or fragment delimiter. */
    host_end = host_start;
    while (host_end < end && *host_end != '/'
           && *host_end != '?' && *host_end != '#')
    {
        host_end++;
    }

    /* path retains the first delimiter onward (may be empty). */
    out->path.data = (u_char *) host_end;
    out->path.len  = (size_t) (end - host_end);

    span.host_start = host_start;
    span.host_end   = host_end;
    span.err        = err;
    span.errsz      = errsz;

    if (net_parse_authority(&span, out) != NGX_OK) {
        return NGX_ERROR;
    }

    if (out->host.len == 0) {
        snprintf(err, errsz, "URL has empty host");
        return NGX_ERROR;
    }

    return NGX_OK;
}

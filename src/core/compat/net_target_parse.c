/*
 * net_target_parse.c — URL grammar for outbound transfer targets.
 *
 * See net_target.h for the public API.  Split verbatim from net_target.c:
 * this translation unit holds the zero-copy "scheme://host[:port][/path]"
 * parser and its per-grammar sub-step helpers.
 */

#include "net_target.h"
#include "net_target_internal.h"
#include "cstr.h"

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>


/*
 * net_url_span_t — the [start, end) authority substring of a URL and the
 * error sink shared across the parse sub-steps.
 *
 * WHAT: names the two cursors ("host_start" = first byte after "://",
 *       "host_end" = the first '/' or end-of-URL) plus the caller's err
 *       buffer, so a helper takes ONE struct instead of four positional args.
 * WHY:  the parse grammar walks a single authority section (host[:port]); the
 *       three host-form handlers all need the same span + err sink, and passing
 *       them as one struct keeps the sub-parsers under the param budget and
 *       makes the data flow explicit (no reaching back into the orchestrator).
 * HOW:  purely a view — no ownership; the cursors point into the caller's URL
 *       buffer exactly as the zero-copy parser requires.
 */
typedef struct {
    const u_char *host_start;
    const u_char *host_end;
    char         *err;
    size_t        errsz;
} net_url_span_t;

/*
 * net_parse_scheme — locate "://" and record the scheme slice.
 *
 * WHAT: on success sets out->scheme and returns the first byte after "://"
 *       (the host_start cursor); on a missing/empty scheme writes err and
 *       returns NULL.
 * WHY:  isolates the scheme grammar (the "://" scan + emptiness checks) from
 *       the authority grammar so each is independently readable.
 * HOW:  linear forward scan for the ':' '/' '/' triple; slices are zero-copy
 *       into url->data.
 */
static const u_char *
net_parse_scheme(const ngx_str_t *url, brix_net_target_t *out,
    char *err, size_t errsz)
{
    const u_char *p   = url->data;
    const u_char *end = url->data + url->len;
    const u_char *scheme_end = NULL;
    const u_char *host_start;

    /* Find "://" */
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

    if (out->scheme.len == 0) {
        snprintf(err, errsz, "URL has empty scheme");
        return NULL;
    }

    /* Skip "://" */
    host_start = scheme_end + 3;
    if (host_start >= end) {
        snprintf(err, errsz, "URL has no host after '://'");
        return NULL;
    }

    return host_start;
}

/*
 * net_parse_port_digits — parse a digits-only port field in [begin, end).
 *
 * WHAT: on success writes the value to *out_port and returns NGX_OK; on any
 *       non-digit byte or a value above 65535 writes err and returns NGX_ERROR.
 * WHY:  the bracketed-IPv6 and plain-host branches both parse a port with
 *       identical rules; one shared scanner keeps the grammar (and the exact
 *       "invalid port" / "port out of range" messages) in a single place.
 * HOW:  pure decimal accumulation with an in-loop range clamp; no I/O.
 */
static ngx_int_t
net_parse_port_digits(const u_char *begin, const u_char *end,
    uint16_t *out_port, char *err, size_t errsz)
{
    unsigned long p_val = 0;

    for (const u_char *d = begin; d < end; d++) {
        if (*d < '0' || *d > '9') {
            snprintf(err, errsz, "invalid port in URL");
            return NGX_ERROR;
        }
        p_val = p_val * 10 + (*d - '0');
        if (p_val > 65535) {
            snprintf(err, errsz, "port out of range");
            return NGX_ERROR;
        }
    }

    *out_port = (uint16_t) p_val;
    return NGX_OK;
}

/*
 * net_parse_bracketed_host — parse an IPv6 literal authority "[addr][:port]".
 *
 * WHAT: fills out->host with the address inside the brackets and, when a
 *       ":port" follows the ']', out->port/has_port; returns NGX_OK or writes
 *       err and returns NGX_ERROR.
 * WHY:  the bracketed form must be handled apart from the plain scan because
 *       the address itself contains colons — a bare ':' split would mistake
 *       them for a port delimiter.
 * HOW:  scan to the matching ']' bounding the literal, then treat only the
 *       ':NNN' that follows it (if any) as the port.
 */
static ngx_int_t
net_parse_bracketed_host(const net_url_span_t *span, brix_net_target_t *out)
{
    const u_char *bracket_end = span->host_start + 1;
    const u_char *colon;

    /* scan for the matching ']' bounding the literal */
    while (bracket_end < span->host_end && *bracket_end != ']') {
        bracket_end++;
    }

    if (bracket_end >= span->host_end) {
        snprintf(span->err, span->errsz, "IPv6 literal missing closing ']'");
        return NGX_ERROR;
    }

    out->host.data = (u_char *) (span->host_start + 1);
    out->host.len  = (size_t) (bracket_end - (span->host_start + 1));

    /* Optional :port after ] */
    colon = bracket_end + 1;
    if (colon < span->host_end && *colon == ':') {
        if (net_parse_port_digits(colon + 1, span->host_end, &out->port,
                                  span->err, span->errsz) != NGX_OK)
        {
            return NGX_ERROR;
        }
        out->has_port = 1;
    }

    return NGX_OK;
}

/*
 * net_parse_plain_host — parse a hostname / IPv4 authority "host[:port]".
 *
 * WHAT: fills out->host and, when a port is present, out->port/has_port;
 *       returns NGX_OK or writes err and returns NGX_ERROR.
 * WHY:  splits the port on the LAST ':' (not the first) deliberately: a bare
 *       unbracketed IPv6 literal has multiple colons and no port, so taking the
 *       final colon yields a port-parse that then fails the digits-only check
 *       and is rejected — rather than silently truncating the host.
 * HOW:  find the last ':' in the span; everything after it is the port field.
 */
static ngx_int_t
net_parse_plain_host(const net_url_span_t *span, brix_net_target_t *out)
{
    const u_char *colon = NULL;

    for (const u_char *q = span->host_start; q < span->host_end; q++) {
        if (*q == ':') {
            colon = q;
        }
    }

    if (colon == NULL) {
        out->host.data = (u_char *) span->host_start;
        out->host.len  = (size_t) (span->host_end - span->host_start);
        return NGX_OK;
    }

    /* Everything after last ":" is the port */
    if (net_parse_port_digits(colon + 1, span->host_end, &out->port,
                              span->err, span->errsz) != NGX_OK)
    {
        return NGX_ERROR;
    }

    out->host.data = (u_char *) span->host_start;
    out->host.len  = (size_t) (colon - span->host_start);
    out->has_port  = 1;

    return NGX_OK;
}

/*
 * net_parse_authority — parse the host[:port] authority after "://".
 *
 * WHAT: sets out->host/port/has_port from span, dispatching to the bracketed
 *       or plain handler; returns NGX_OK or writes err and returns NGX_ERROR.
 * WHY:  a single dispatch point keeps the orchestrator flat and makes the
 *       bracketed-vs-plain choice the only branch either handler has to know.
 * HOW:  a leading '[' selects the IPv6-literal grammar; anything else is a
 *       plain hostname / IPv4 authority.
 */
static ngx_int_t
net_parse_authority(const net_url_span_t *span, brix_net_target_t *out)
{
    if (span->host_start < span->host_end && *span->host_start == '[') {
        return net_parse_bracketed_host(span, out);
    }

    return net_parse_plain_host(span, out);
}

/*
 * brix_net_target_parse — split "scheme://host[:port][/path]" into fields.
 *
 * WHAT: fills *out with scheme/host/port/path slices for the given URL;
 *       returns NGX_OK or NGX_ERROR with a reason in err.
 * WHY:  HTTP-TPC / remote-copy targets arrive as opaque URL strings and must
 *       be decomposed before the host can be DNS-checked against SSRF policy.
 * HOW:  zero-copy single forward pass — scheme / authority / path grammars are
 *       each parsed by a dedicated helper, and every out->* ngx_str_t points
 *       back into url->data (no allocation), so the parsed target's lifetime is
 *       bound to the caller's url buffer.
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

    ngx_memzero(out, sizeof(*out));
    out->raw_url = *url;

    end = url->data + url->len;

    host_start = net_parse_scheme(url, out, err, errsz);
    if (host_start == NULL) {
        return NGX_ERROR;
    }

    /* Find end of host[:port] section — first "/" after "://" */
    host_end = host_start;
    while (host_end < end && *host_end != '/') {
        host_end++;
    }

    /* path is from first "/" onward (may be empty) */
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

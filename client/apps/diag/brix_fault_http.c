/*
 * brix_fault_http.c — pure HTTP/1.x request-smuggling surgery.
 * See brix_fault_http.h.
 */
#include "brix_fault_http.h"
#include "brix_fault_buf.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

int
fp_http_active(const fp_http_cfg *c)
{
    return c->add_cl || c->add_te || c->dup_cl || c->obfuscate_te ||
           c->naked_lf || c->inj_name_len > 0 || c->append_len > 0;
}

/* Case-insensitive: does the header line start with `name`? */
static int
hdr_is(const unsigned char *line, size_t len, const char *name)
{
    size_t nl = strlen(name);
    if (len < nl) {
        return 0;
    }
    for (size_t i = 0; i < nl; i++) {
        if (tolower(line[i]) != tolower((unsigned char) name[i])) {
            return 0;
        }
    }
    return 1;
}

/* Emit one header line followed by the configured line ending. */
static void
emit_line(unsigned char *out, size_t cap, size_t *o,
          const unsigned char *line, size_t len, int lf)
{
    fp_bufcat(out, cap, o, line, len);
    fp_buf_eol(out, cap, o, lf);
}

/* Emit a Transfer-Encoding header line with its name obfuscated per `mode`. */
static void
emit_te_obfuscated(unsigned char *out, size_t cap, size_t *o,
                   const unsigned char *line, size_t llen, int mode, int lf)
{
    const unsigned char *colon = memchr(line, ':', llen);
    if (!colon) {
        emit_line(out, cap, o, line, llen, lf);
        return;
    }
    size_t namelen = (size_t) (colon - line);
    size_t rest    = llen - namelen;              /* colon + value */
    if (mode == 1) {                              /* space before the colon */
        fp_bufcat(out, cap, o, line, namelen);
        fp_bufputc(out, cap, o, ' ');
        fp_bufcat(out, cap, o, colon, rest);
    } else if (mode == 2) {                        /* leading tab (line folding) */
        fp_bufputc(out, cap, o, '\t');
        fp_bufcat(out, cap, o, line, llen);
    } else {                                       /* '-' -> '_' inside the name */
        for (size_t k = 0; k < namelen; k++) {
            fp_bufputc(out, cap, o, line[k] == '-' ? '_' : line[k]);
        }
        fp_bufcat(out, cap, o, colon, rest);
    }
    fp_buf_eol(out, cap, o, lf);
}

/* Append the added/injected headers after the original header lines. */
static void
emit_added_headers(unsigned char *out, size_t cap, size_t *o,
                   const fp_http_cfg *c, fp_http_stats *st, int lf)
{
    char tmp[64];
    if (c->add_cl) {
        int m = snprintf(tmp, sizeof(tmp), "Content-Length: %ld", c->cl_val);
        emit_line(out, cap, o, (unsigned char *) tmp, (size_t) m, lf);
        st->headers_added++;
    }
    if (c->add_te) {
        emit_line(out, cap, o,
                  (const unsigned char *) "Transfer-Encoding: chunked", 26, lf);
        st->headers_added++;
    }
    if (c->dup_cl) {
        int m = snprintf(tmp, sizeof(tmp), "Content-Length: %ld", c->dup_cl_val);
        emit_line(out, cap, o, (unsigned char *) tmp, (size_t) m, lf);
        st->headers_added++;
    }
    if (c->inj_name_len > 0) {
        fp_bufcat(out, cap, o, c->inj_name, (size_t) c->inj_name_len);
        fp_bufcat(out, cap, o, ": ", 2);
        fp_bufcat(out, cap, o, c->inj_val, (size_t) c->inj_val_len);
        fp_buf_eol(out, cap, o, lf);
        st->headers_added++;
    }
}

size_t
fp_http_rewrite(const unsigned char *in, size_t n,
                unsigned char *out, size_t outcap,
                const fp_http_cfg *c, fp_http_stats *st, int *applied)
{
    *applied = 0;
    const unsigned char *end = NULL;
    for (size_t i = 0; i + 3 < n; i++) {
        if (in[i] == '\r' && in[i + 1] == '\n' &&
            in[i + 2] == '\r' && in[i + 3] == '\n') {
            end = in + i;
            break;
        }
    }
    if (!end) {
        return 0;                                  /* no header block here */
    }
    *applied = 1;
    st->msgs++;
    int    lf = c->naked_lf;
    size_t o = 0;
    size_t hlen = (size_t) (end - in);             /* header bytes, no terminator */

    size_t ls = 0;
    while (ls <= hlen) {
        size_t le = ls;
        while (le + 1 <= hlen && !(in[le] == '\r' && in[le + 1] == '\n')) {
            le++;
        }
        if (le > hlen) {
            le = hlen;
        }
        const unsigned char *line = in + ls;
        size_t               llen = le - ls;
        if (llen > 0) {
            if (c->obfuscate_te && hdr_is(line, llen, "transfer-encoding")) {
                emit_te_obfuscated(out, outcap, &o, line, llen, c->obfuscate_te, lf);
                st->te_obf++;
            } else {
                emit_line(out, outcap, &o, line, llen, lf);
            }
        }
        if (le >= hlen) {
            break;
        }
        ls = le + 2;
    }

    emit_added_headers(out, outcap, &o, c, st, lf);
    fp_buf_eol(out, outcap, &o, lf);               /* blank line: end of headers */
    if (lf) {
        st->lf_converted++;
    }

    const unsigned char *body = end + 4;           /* body follows CRLFCRLF */
    fp_bufcat(out, outcap, &o, body, (size_t) (in + n - body));

    if (c->append_len > 0) {
        fp_bufcat(out, outcap, &o, c->append, (size_t) c->append_len);
        st->appended++;
    }
    return o;
}

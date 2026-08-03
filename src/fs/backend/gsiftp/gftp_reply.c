/*
 * gftp_reply.c — see gftp_reply.h. Pure, allocation-free control-channel reply
 * parsing for the outbound gsiftp:// driver. No nginx or socket dependencies so
 * the whole file is unit-testable against a byte buffer.
 */

#include "gftp_reply.h"


/* Index of the byte after the next LF in buf[from..len), or -1 if none yet. */
static long
line_end(const char *buf, size_t len, size_t from)
{
    size_t i;
    for (i = from; i < len; i++) {
        if (buf[i] == '\n') {
            return (long) (i + 1);
        }
    }
    return -1;
}


/* Parse three leading decimal digits; -1 if any of the first three are not. */
static int
three_digit_code(const char *p, size_t len)
{
    int i, code = 0;
    if (len < 3) {
        return -1;
    }
    for (i = 0; i < 3; i++) {
        if (p[i] < '0' || p[i] > '9') {
            return -1;
        }
        code = code * 10 + (p[i] - '0');
    }
    return code;
}


/* Trim a trailing CR (and the LF is already excluded) from [start,end). */
static size_t
strip_eol(const char *buf, size_t start, size_t end)
{
    if (end > start && buf[end - 1] == '\n') { end--; }
    if (end > start && buf[end - 1] == '\r') { end--; }
    return end;
}


long
gftp_reply_scan(const char *buf, size_t len, gftp_reply_t *out)
{
    int    code;
    long   eol;
    size_t text_start, text_end, line_start;

    code = three_digit_code(buf, len);
    if (code < 0) {
        /* Fewer than three bytes is "incomplete", not malformed: the code
         * could still be arriving. A non-digit in a present byte is fatal. */
        if (len < 3) {
            return 0;
        }
        return -1;
    }

    if (buf[3] != ' ' && buf[3] != '-') {
        return -1;
    }

    eol = line_end(buf, len, 0);
    if (eol < 0) {
        return 0;                       /* first line not yet terminated */
    }

    if (buf[3] == ' ') {                /* single-line reply */
        text_start = 4;
        text_end   = strip_eol(buf, text_start, (size_t) eol);
        out->code      = code;
        out->multiline = 0;
        out->text      = buf + text_start;
        out->text_len  = text_end - text_start;
        return eol;
    }

    /* Multiline: consume lines until one begins with the same three digits
     * followed by a space (RFC 959 §4.2). Intermediate lines are ignored. */
    line_start = (size_t) eol;
    for ( ;; ) {
        long next = line_end(buf, len, line_start);
        if (next < 0) {
            return 0;                   /* terminator line not fully arrived */
        }
        if (next - (long) line_start >= 4
            && three_digit_code(buf + line_start, len - line_start) == code
            && buf[line_start + 3] == ' ')
        {
            text_start = line_start + 4;
            text_end   = strip_eol(buf, text_start, (size_t) next);
            out->code      = code;
            out->multiline = 1;
            out->text      = buf + text_start;
            out->text_len  = text_end - text_start;
            return next;
        }
        line_start = (size_t) next;
    }
}


/* Read a decimal 0..255 starting at *p (updated); -1 on non-digit or overflow. */
static int
octet(const char **p, const char *end)
{
    int v = 0, n = 0;
    while (*p < end && **p >= '0' && **p <= '9') {
        v = v * 10 + (**p - '0');
        if (v > 255) {
            return -1;
        }
        (*p)++;
        n++;
    }
    return n ? v : -1;
}


int
gftp_reply_parse_pasv(const char *text, size_t len, unsigned char ip[4],
    unsigned *port)
{
    const char *p   = text;
    const char *end = text + len;
    int         vals[6];
    int         i;

    /* Skip to the first digit (tolerates the "(" and any preamble). */
    while (p < end && (*p < '0' || *p > '9')) {
        p++;
    }
    for (i = 0; i < 6; i++) {
        int v = octet(&p, end);
        if (v < 0) {
            return -1;
        }
        vals[i] = v;
        if (i < 5) {
            if (p >= end || *p != ',') {
                return -1;
            }
            p++;
        }
    }
    ip[0] = (unsigned char) vals[0];
    ip[1] = (unsigned char) vals[1];
    ip[2] = (unsigned char) vals[2];
    ip[3] = (unsigned char) vals[3];
    *port = (unsigned) (vals[4] * 256 + vals[5]);
    return 0;
}


/* Consume the three empty net-prt / net-addr fields — "<d><d><d>" — that RFC
 * 2428 requires between the opening '(' and the port. 0 / -1. */
static int
gftp_epsv_skip_fields(const char **pp, const char *end, char d)
{
    const char *p = *pp;

    if (p + 3 > end || p[0] != d || p[1] != d || p[2] != d) {
        return -1;
    }
    *pp = p + 3;
    return 0;
}


/* Scan the unsigned decimal run at *pp (bounded by end), advancing *pp past it.
 * Returns the value, or -1 for no digits at all or a value past 65535 — the
 * bound is checked per digit, so a long run cannot overflow the accumulator. */
static long
gftp_epsv_scan_port(const char **pp, const char *end)
{
    const char *p = *pp;
    long        v = 0;
    int         n = 0;

    while (p < end && *p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        if (v > 65535) {
            return -1;
        }
        p++;
        n++;
    }
    *pp = p;
    return n == 0 ? -1 : v;
}


int
gftp_reply_parse_epsv(const char *text, size_t len, unsigned *port)
{
    const char *p   = text;
    const char *end = text + len;
    char        d;
    long        v;

    while (p < end && *p != '(') {
        p++;
    }
    if (p >= end) {
        return -1;
    }
    p++;                                /* past '(' */
    if (p >= end) {
        return -1;
    }
    d = *p;                             /* delimiter (RFC 2428: usually '|') */

    if (gftp_epsv_skip_fields(&p, end, d) != 0) {
        return -1;
    }
    v = gftp_epsv_scan_port(&p, end);
    if (v <= 0 || p >= end || *p != d) {
        return -1;
    }
    *port = (unsigned) v;
    return 0;
}

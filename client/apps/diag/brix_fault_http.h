/*
 * brix_fault_http.h — pure HTTP/1.x request-smuggling surgery for
 * brix-fault-proxy.
 *
 * HTTP/1.1 message framing is famously ambiguous when a chain of proxies and
 * origins disagree about where one request ends and the next begins.  This
 * module rewrites the header block of a message crossing the wire to manufacture
 * the classic desync primitives an attacker uses to smuggle a second request
 * past a front-end into a back-end:
 *
 *   - CL.TE / TE.CL: present BOTH a Content-Length and a Transfer-Encoding:
 *     chunked header, so a front-end honouring one and a back-end the other
 *     disagree on the body boundary.
 *   - duplicate Content-Length with a different value (ambiguous length).
 *   - Transfer-Encoding header-name obfuscation (space-before-colon, leading
 *     tab, underscore) that a lax parser still honours but a strict one drops.
 *   - naked-LF line endings (bare \n instead of \r\n) — another parser
 *     differential.
 *   - inject an arbitrary header, and append a fully-formed smuggled request
 *     after the body.
 *
 * Pure functions over caller buffers (no globals, no I/O).  Operates on whatever
 * header block is present in the read buffer; if no CRLFCRLF terminator is in the
 * buffer the message is passed through untouched (*applied = 0).
 */
#ifndef BRIX_FAULT_HTTP_H
#define BRIX_FAULT_HTTP_H

#include <stddef.h>

/* Per-direction HTTP smuggling config; all-zero = inert (safe to zero-init). */
typedef struct {
    int  add_cl;         /* add "Content-Length: <cl_val>" (CL side of CL.TE)   */
    long cl_val;
    int  add_te;         /* add "Transfer-Encoding: chunked" (TE side of TE.CL) */
    int  dup_cl;         /* add a SECOND Content-Length header = dup_cl_val      */
    long dup_cl_val;
    int  obfuscate_te;   /* mangle an existing TE header name: 1 space-pre-colon,
                          * 2 leading tab, 3 '-'->'_' in the name                */
    int  naked_lf;       /* rewrite header-block CRLF -> bare LF                 */
    unsigned char inj_name[64];  int inj_name_len;   /* inject-header name  */
    unsigned char inj_val[192];  int inj_val_len;    /* inject-header value */
    unsigned char append[512];   int append_len;     /* bytes smuggled after msg */
} fp_http_cfg;

/* Tallies (added, not reset). */
typedef struct {
    unsigned long msgs;          /* header blocks rewritten */
    unsigned long headers_added; /* headers injected/added */
    unsigned long te_obf;        /* Transfer-Encoding names obfuscated */
    unsigned long lf_converted;  /* messages emitted with naked LF */
    unsigned long appended;      /* smuggled trailers appended */
} fp_http_stats;

/* True if any op in *c is active. */
int fp_http_active(const fp_http_cfg *c);

/* Rewrite the HTTP message in `in[0..n)` into `out` (capacity `outcap`) per *c.
 * Sets *applied=1 and returns the produced length when a header block was found
 * and rewritten; sets *applied=0 and returns 0 when there is no CRLFCRLF in the
 * buffer (caller forwards the original bytes unchanged). */
size_t fp_http_rewrite(const unsigned char *in, size_t n,
                       unsigned char *out, size_t outcap,
                       const fp_http_cfg *c, fp_http_stats *st, int *applied);

#endif /* BRIX_FAULT_HTTP_H */

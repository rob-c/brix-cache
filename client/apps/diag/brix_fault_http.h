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
    /* DPI header-size hold: mimic a deep-packet-inspection middlebox that stalls
     * a request once its header block crosses a byte threshold (e.g. a fat
     * client-cert PEM in an XrdHttp request header). Timing effect only — applied
     * by the relay pump, not by fp_http_rewrite(), so it is NOT part of
     * fp_http_active(). */
    int  hold_thresh;    /* hold when the header block is >= this many bytes (0=off) */
    int  hold_ms;        /* how long to stall the connection thread                  */
    int  hold_partial;   /* 1: release the first hold_thresh bytes, then hold the
                          *    remainder; 0: hold the whole segment                  */
    /* body-hold: the store-and-forward sibling of header-hold — stall once the
     * BODY (bytes after CRLFCRLF, or a bodyless continuation segment) reaches a
     * threshold.  Also a timing effect, also excluded from fp_http_active(). */
    int  body_hold_thresh;
    int  body_hold_ms;
    int  body_hold_partial;
    unsigned char strip_name[64];  int strip_len;  /* drop header lines named this */
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

/* Size of the HTTP header block in `in[0..n)`: the byte offset of the CRLFCRLF
 * that terminates the headers.  Returns `n` when the buffer holds no complete
 * header block (the terminator has not arrived yet). */
size_t fp_http_header_len(const unsigned char *in, size_t n);

/* True if the DPI header-size hold is armed. */
int fp_http_hold_active(const fp_http_cfg *c);

/* True if the DPI body-size hold is armed. */
int fp_http_body_hold_active(const fp_http_cfg *c);

/* Body-size sibling of fp_http_hold_decide(): measures the bytes AFTER the
 * header terminator (or the whole segment when it carries no header block, i.e.
 * a body continuation) and decides the store-and-forward stall the same way. */
int fp_http_body_hold_decide(const fp_http_cfg *c, const unsigned char *in,
                             size_t n, size_t *release);

/* Decide the DPI hold for the bytes in `in[0..n)`.  Returns 1 and sets
 * *release when the buffer carries a COMPLETE header block whose size is
 * >= c->hold_thresh: *release is the number of leading bytes to forward before
 * the stall (0 for a whole-message hold, min(hold_thresh, n) for a partial one).
 * Returns 0 (and leaves *release untouched) when the hold is disarmed, no
 * complete header block is present, or the header is under the threshold — so a
 * body-only segment never trips the hold. */
int fp_http_hold_decide(const fp_http_cfg *c, const unsigned char *in, size_t n,
                        size_t *release);

#endif /* BRIX_FAULT_HTTP_H */

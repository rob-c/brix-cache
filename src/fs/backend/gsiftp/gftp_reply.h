#ifndef BRIX_GSIFTP_REPLY_H
#define BRIX_GSIFTP_REPLY_H

/*
 * gftp_reply.h — client-role FTP control-channel reply parser (RFC 959 §4.2,
 * RFC 2428 §3) for the outbound gsiftp:// storage driver.
 *
 * WHAT: turn raw control-channel bytes into a single completed reply (3-digit
 * code + final-line text), and decode the two address-bearing replies a client
 * must interpret to open a data channel — 227 (PASV, IPv4) and 229 (EPSV).
 *
 * WHY: phase-82 is the inbound gateway and only ever *emits* replies; a client
 * must *parse* them, and nothing in the tree did until now. The 227/229 address
 * decoders are the SSRF-critical seam: a hostile origin can nominate an
 * arbitrary data-channel address, so these functions bounds-check every octet
 * and reject malformed input — the caller then screens the extracted address
 * through net_target.h before dialling. Keeping the parse pure (plain buffers,
 * no nginx types, no sockets) makes it exhaustively unit-testable off any
 * server and lets both the blocking driver and any future event client share
 * one implementation that cannot drift.
 *
 * HOW: `gftp_reply_scan` consumes one complete reply from a receive buffer,
 * handling the multiline `ddd-...\r\n ... \r\nddd ` continuation form; it never
 * reads past `len` and returns 0 when more bytes are needed (the caller reads
 * more and rescans). The address decoders operate on the final line's text.
 */

#include <stddef.h>

typedef struct {
    int          code;         /* 3-digit reply code (e.g. 227), 100..599      */
    int          multiline;    /* nonzero if a `ddd-` continuation was consumed */
    const char  *text;         /* final line's text (after "ddd " / "ddd-")     */
    size_t       text_len;     /* its length, excluding the CR/LF terminator    */
} gftp_reply_t;

/*
 * Scan buf[0..len) for exactly one complete FTP reply.
 *   > 0 : bytes consumed; *out is filled (advance the buffer by the return value)
 *     0 : incomplete — no full reply yet, read more bytes and rescan
 *    -1 : malformed — first three bytes are not digits, or the code/separator
 *         framing is invalid (the caller must fail the control channel)
 */
long gftp_reply_scan(const char *buf, size_t len, gftp_reply_t *out);

/*
 * Decode a 227 "Entering Passive Mode (h1,h2,h3,h4,p1,p2)" reply text into a
 * four-byte IPv4 address and a port. Returns 0 on success, -1 if the six
 * comma-separated octets are absent, out of the 0..255 range, or overflow.
 * The address is NOT screened here — the caller applies the SSRF policy.
 */
int gftp_reply_parse_pasv(const char *text, size_t len,
    unsigned char ip[4], unsigned *port);

/*
 * Decode a 229 "Entering Extended Passive Mode (|||port|)" reply text (RFC 2428)
 * into a port; the address is inherited from the control connection. Returns 0
 * on success, -1 on a malformed delimiter run or an out-of-range port.
 */
int gftp_reply_parse_epsv(const char *text, size_t len, unsigned *port);

#endif /* BRIX_GSIFTP_REPLY_H */

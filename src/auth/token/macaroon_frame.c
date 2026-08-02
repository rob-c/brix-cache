/*
 * macaroon_frame.c — pure macaroon packet-length framing (see macaroon_frame.h).
 *
 * brix_macaroon_packet_len() was carved out of macaroon_parse.c so the macaroon
 * framing walk can be fuzzed standalone (hyper-hardening C-1 target 4);
 * behaviour is byte-identical and macaroon_parse.c now calls it. The pure
 * brix_macaroon_scan_frames() re-expresses the exact framing bounds enforced by
 * macaroon_parse_core()'s packet loop, with no HMAC/claims side effects, so a
 * harness can drive the length-prefix arithmetic on hostile input.
 *
 * Depends only on the shared hex nibble decoder (core/compat/hex.h) — libc-only.
 */
#include "macaroon_frame.h"

#include "core/compat/hex.h"

int
brix_macaroon_packet_len(const unsigned char *p)
/* WHAT: parse a 4-character hex-encoded packet length from macaroon binary data.
 * WHY:  macaroon packets are prefixed with a hex-encoded length field; this
 *       converts the first 4 hex characters into an integer for bounds checking
 *       before reading packet data.
 * HOW:  brix_hex_from_char() on each of p[0..3]; reject if any nibble is invalid
 *       (<0); combine via (v0<<12)|(v1<<8)|(v2<<4)|v3; return value or -1. */
{
    int v0, v1, v2, v3;
    v0 = brix_hex_from_char(p[0]);
    v1 = brix_hex_from_char(p[1]);
    v2 = brix_hex_from_char(p[2]);
    v3 = brix_hex_from_char(p[3]);
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) return -1;
    return (v0 << 12) | (v1 << 8) | (v2 << 4) | v3;
}

int
brix_macaroon_scan_frames(const unsigned char *bin, size_t len)
/* WHAT: walk the macaroon binary as length-prefixed packets, enforcing the
 *       per-packet framing bounds and counting well-framed packets.
 * WHY:  the length-prefix walk is the pre-auth framing surface; expressing it
 *       purely (no HMAC/claims) makes the `plen < 4 || p + plen > end` bound
 *       machine-checkable under ASan+UBSan on arbitrary bytes.
 * HOW:  loop while at least 4 header bytes remain; decode plen; reject on an
 *       out-of-range length prefix; strip an optional trailing '\n' from the
 *       body span (as the parser does) without dereferencing past the packet;
 *       advance by plen; return the packet count or -1 on the first bad frame. */
{
    const unsigned char *p   = bin;
    const unsigned char *end = bin + len;
    int                  count = 0;

    while (p + 4 <= end) {
        int    plen = brix_macaroon_packet_len(p);
        size_t dlen;

        if (plen < 4 || p + plen > end) {
            return -1;
        }

        /* Body span is [p+4, p+plen); the parser strips one trailing '\n'. This
         * touches only bytes already proven in-bounds by the check above. */
        dlen = (size_t) (plen - 4);
        if (dlen > 0 && p[4 + dlen - 1] == '\n') {
            dlen--;
        }
        (void) dlen;

        p += plen;
        count++;
    }

    return count;
}

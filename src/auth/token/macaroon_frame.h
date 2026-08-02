/*
 * macaroon_frame.h — pure macaroon packet-length framing.
 *
 * WHAT: brix_macaroon_packet_len() decodes the 4-hex-char packet length prefix;
 *       brix_macaroon_scan_frames() walks a whole macaroon binary as the
 *       sequence of length-prefixed packets, enforcing only the framing bounds
 *       (the `plen < 4 || p + plen > end` reject that guards every packet).
 * WHY:  a macaroon is attacker-controlled bytes parsed BEFORE the HMAC chain is
 *       verified (the packets must be walked to reach the signature packet).
 *       The length-prefix walk is the classic framing-overflow surface
 *       (hyper-hardening C-1 target 4). Carving the bounds into a pure,
 *       nginx-free TU lets a libFuzzer harness drive it on hostile input without
 *       the HMAC/claims machinery (which is nginx/OpenSSL-coupled).
 * HOW:  pure — reads bytes only; no allocation, no globals, no I/O. The full
 *       chain reconstruction still lives in macaroon_parse.c, which reuses
 *       brix_macaroon_packet_len from here so the length decode is single-source.
 */
#ifndef BRIX_MACAROON_FRAME_H
#define BRIX_MACAROON_FRAME_H

#include <stddef.h>

/*
 * Parse a 4-character hex-encoded packet length (p[0..3]) into an int.
 * Returns the value (0..0xffff) or -1 if any of the four chars is not hex.
 * The caller must guarantee p points at 4 readable bytes.
 */
int brix_macaroon_packet_len(const unsigned char *p);

/*
 * Walk `bin`[0..len) as length-prefixed packets, applying only the framing
 * bounds each packet must satisfy (length >= 4 and the packet fits the buffer).
 * Returns the number of well-framed packets consumed, or -1 on the first
 * malformed length prefix (mirrors macaroon_parse_core's framing reject). Pure.
 */
int brix_macaroon_scan_frames(const unsigned char *bin, size_t len);

#endif /* BRIX_MACAROON_FRAME_H */

/*
 * sss_framing.h — pure SSS outer-header framing predicate.
 *
 * WHAT: brix_sss_header_framing_ok() — validates the untrusted SSS datagram
 *       outer header (magic, encoding marker, key-name-size field, header
 *       length + NUL termination) against the received length, computing the
 *       header length as a side output.
 * WHY:  the SSS credential frame is attacker-controlled bytes parsed BEFORE any
 *       key lookup or decrypt (pre-auth, remote-reachable — hyper-hardening C-1
 *       target 3, where the phase-79 bug lived). Carving the framing bounds into
 *       a pure, nginx-free translation unit lets a libFuzzer harness drive it on
 *       hostile input with no socket/ctx/registry dependency (the rest of
 *       auth_request.c is deeply nginx-coupled and cannot be harnessed whole).
 * HOW:  reads only the payload bytes and the datagram length; no allocation, no
 *       globals, no I/O. Uses `unsigned char` (== nginx's u_char) so the header
 *       stays ngx-free while remaining call-compatible with the module.
 */
#ifndef BRIX_SSS_FRAMING_H
#define BRIX_SSS_FRAMING_H

#include <stddef.h>

/*
 * Validate the SSS outer-header framing.
 *
 * Returns 1 when every check passes (and writes the computed outer-header length
 * — BRIX_SSS_HDR_LEN + key-name-size — via *hdr_len), else 0. Pure predicate.
 */
int brix_sss_header_framing_ok(const unsigned char *payload, size_t dlen,
                               size_t *hdr_len);

#endif /* BRIX_SSS_FRAMING_H */

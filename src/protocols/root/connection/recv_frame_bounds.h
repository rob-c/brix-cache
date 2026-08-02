/*
 * recv_frame_bounds.h — pure XRootD request-framing bounds.
 *
 * WHAT: brix_max_payload_for_request() is the per-opcode payload-size cap table;
 *       brix_root_frame_dlen_ok() decodes a 24-byte ClientRequestHdr and applies
 *       that cap to its dlen field — the "reject an oversized dlen BEFORE any
 *       allocation" invariant, made callable on raw bytes.
 * WHY:  the request header is the first attacker-controlled bytes off the root://
 *       wire; the dlen cap is the bound that stops a hostile length from driving
 *       an allocation (hyper-hardening C-2). Carving it into a pure, nginx-free
 *       TU makes the invariant executable under a libFuzzer harness rather than
 *       review-only — recv_process.c (the framing state machine) is far too
 *       nginx-coupled to harness whole.
 * HOW:  pure — integer arithmetic over wire constants only; no allocation, no
 *       ctx, no I/O. recv_process.c reuses brix_max_payload_for_request from here
 *       so the cap table is single-source.
 */
#ifndef BRIX_RECV_FRAME_BOUNDS_H
#define BRIX_RECV_FRAME_BOUNDS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Per-opcode maximum payload (dlen) accepted for `reqid`, checked before any
 * allocation so an oversized dlen is rejected without allocating.
 */
uint32_t brix_max_payload_for_request(uint16_t reqid);

/*
 * Decode the fixed 24-byte ClientRequestHdr (streamid[2]@0, requestid@2 BE16,
 * body[16]@4, dlen@20 BE32) from `hdr`[0..len) and test dlen against the
 * per-opcode cap. Writes reqid/dlen via the out params when they are non-NULL.
 * Returns 1 when the frame carries a full header and dlen is within the cap,
 * 0 when the header is short OR dlen exceeds the cap (the reject the state
 * machine performs before allocating a payload buffer). Pure.
 */
int brix_root_frame_dlen_ok(const unsigned char *hdr, size_t len,
                            uint16_t *reqid_out, uint32_t *dlen_out);

#endif /* BRIX_RECV_FRAME_BOUNDS_H */

/* tests/fuzz/fuzz_root_frame.c — libFuzzer target for the root:// request framing.
 *
 * WHAT: Feeds arbitrary bytes through brix_root_frame_dlen_ok() — the decoder
 *       that reads a 24-byte XRootD ClientRequestHdr (requestid @2, dlen @20) and
 *       tests dlen against the per-opcode payload cap — under ASan + UBSan. This
 *       is the structure-aware framing harness of hyper-hardening C-2: arbitrary
 *       {opcode + dlen + body} PDUs driven at the dispatcher's first gate.
 *
 * WHY:  The request header is the first attacker-controlled bytes off the wire.
 *       The invariant under test — "no path allocates a payload buffer before the
 *       per-opcode dlen cap is checked" — is exactly brix_root_frame_dlen_ok:
 *       recv_process.c calls brix_max_payload_for_request (the shared cap table)
 *       and rejects an oversized dlen before allocation. Fuzzing every
 *       reqid/dlen combination proves the cap arithmetic never overflows and no
 *       opcode slips a hostile length past the gate (src/protocols/root/
 *       connection/recv_frame_bounds.c).
 *
 * HOW:  Links the pure recv_frame_bounds.c TU (nginx-free: wire opcode/flag/
 *       tunable constants only). The fuzzer both drives raw bytes and, when it
 *       has a full header, cross-checks that a within-cap dlen is accepted and an
 *       over-cap dlen is rejected, so a regression in the cap comparison is a hard
 *       failure, not just a silent pass. Recipe in fuzz_all.py.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "protocols/root/connection/recv_frame_bounds.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint16_t reqid = 0;
    uint32_t dlen  = 0;
    int      ok;

    if (size == 0) {
        return 0;
    }

    /* Primary leg: arbitrary bytes as a candidate header. Short frames must be
     * rejected (return 0) without touching the missing bytes. */
    ok = brix_root_frame_dlen_ok((const unsigned char *) data, size,
                                 &reqid, &dlen);

    /* Structural cross-check: with a full header, the accept/reject verdict must
     * agree with a hand-recomputed cap comparison. abort() (→ libFuzzer crash)
     * on disagreement makes a cap-arithmetic regression a hard failure. */
    if (size >= 24) {
        uint32_t cap      = brix_max_payload_for_request(reqid);
        int      expected = (dlen <= cap) ? 1 : 0;
        if (ok != expected) {
            abort();
        }
    }
    return 0;
}

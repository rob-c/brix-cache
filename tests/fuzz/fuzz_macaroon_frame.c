/* tests/fuzz/fuzz_macaroon_frame.c — libFuzzer target for macaroon packet framing.
 *
 * WHAT: Feeds arbitrary bytes through brix_macaroon_scan_frames() — the
 *       libmacaroons v1 binary packet walk that reads each 4-hex-char length
 *       prefix and steps over the packet body — under ASan + UBSan. Also spot-
 *       checks the underlying brix_macaroon_packet_len() length decoder.
 *
 * WHY:  A macaroon arrives base64-decoded as a sequence of length-prefixed
 *       packets; brix_macaroon_scan_frames (src/auth/token/macaroon_frame.c)
 *       is the framing loop that bounds every prefix against the buffer end
 *       BEFORE the caveat/signature verification runs — the pre-auth structural
 *       decode named in hyper-hardening C-1 (remaining target: macaroon). A
 *       prefix that claims more bytes than remain, or a zero/short prefix, must be
 *       rejected without over-reading. The loop is a faithful re-expression of
 *       macaroon_parse_core's own bounds, carved pure so it is fuzzable.
 *
 * HOW:  Links the pure macaroon_frame.c TU (nginx-free: only core/compat/hex.h).
 *       len is the real buffer length so ASan bounds every read. Recipe in
 *       fuzz_all.py.
 */
#include <stddef.h>
#include <stdint.h>

#include "auth/token/macaroon_frame.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) {
        return 0;
    }

    /* Whole-binary framing walk: the prefix-vs-remaining bound is the hot path. */
    (void) brix_macaroon_scan_frames((const unsigned char *) data, size);

    /* Direct length-decoder leg: needs 4 hex chars; exercises the nibble parse
     * and its rejection of non-hex prefixes independently of the walk. */
    if (size >= 4) {
        (void) brix_macaroon_packet_len((const unsigned char *) data);
    }
    return 0;
}

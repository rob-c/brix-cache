/* tests/fuzz/fuzz_sss_frame.c — libFuzzer target for the SSS datagram framing.
 *
 * WHAT: Feeds arbitrary bytes through brix_sss_header_framing_ok() — the
 *       XrdSecsss datagram header validator that walks the untrusted
 *       {version, len, ...} framing and reports how many bytes the fixed header
 *       occupies — under ASan + UBSan.
 *
 * WHY:  brix_sss_header_framing_ok (src/auth/sss/sss_framing.c) is the first
 *       structural gate on an SSS credential datagram, BEFORE the shared-secret
 *       MAC is verified (hyper-hardening C-1 remaining target: SSS frames). If it
 *       mis-sizes the header, the downstream MAC/identity parse reads out of
 *       bounds on a pre-auth packet. The function is a byte-identical carve of the
 *       former static header check, so the fuzzer exercises exactly the production
 *       walk.
 *
 * HOW:  Links the pure sss_framing.c TU (nginx-free: only wire constants from
 *       sss.h + tunables.h). dlen is the real buffer length (the honest wire
 *       contract — cur_dlen equals the bytes actually received), so ASan bounds
 *       every read the framing walk performs. Recipe in fuzz_all.py.
 */
#include <stddef.h>
#include <stdint.h>

#include "auth/sss/sss_framing.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t hdr_len = 0;

    if (size == 0) {
        return 0;
    }

    /* dlen == the real buffer length: the parser must bound its header walk
     * against dlen and never read past `data[size)`. */
    (void) brix_sss_header_framing_ok((const unsigned char *) data, size,
                                      &hdr_len);
    return 0;
}

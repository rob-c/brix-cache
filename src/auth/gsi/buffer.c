#include "gsi_internal.h"
#include "gsi_core.h"

/*
 * WHAT: Binary XrdSutBuffer parser — scans payload for a bucket of specified type by iterating over big-endian [type: uint32, len: uint32, data: len bytes] entries terminated by kXRS_none. Validates minimum frame size (8 bytes), uses ngx_strnlen() safety guard on protocol name null-termination to prevent out-of-frame reads from missing terminator, skips past protocol+step fields, iterates buckets reading type+len then checking match against target_type before advancing cursor by bucket_len.
 * WHY: GSI wire messages use nested bucket structures requiring precise extraction of DH public keys (kXRS_puk), encrypted cert chains (kXRS_main), cipher negotiation lists (kXRS_cipher_alg), and certificate data (kXRS_x509). ngx_strnlen() prevents protocol name missing null terminator from causing out-of-bounds reads in untrusted binary frames.
 * */
/*
 * WHAT: Implements gsi_find_bucket() — binary parser for XrdSutBuffer wire format used in all GSI authentication messages. Scans payload for a bucket of specified type by iterating over big-endian [type: uint32, len: uint32, data: len bytes] entries terminated by kXRS_none (0x8001). Handles protocol name null-termination with ngx_strnlen() safety guard against missing terminator causing out-of-frame reads.
 *
 * WHY: GSI wire messages use nested bucket structures — outer envelope wraps inner encrypted payloads. Every GSI handler must locate specific buckets (kXRS_puk, kXRS_main, kXRS_x509, kXRS_cipher_alg) to extract DH public keys, encrypted cert chains, cipher negotiation lists, and certificate data. The parser must handle untrusted binary frames safely — protocol string missing null terminator must not cause out-of-bounds reads.
 *
 * HOW: gsi_find_bucket() → validate plen >= 8 (minimum frame size), ngx_strnlen() on protocol name +1 guard against missing NUL, skip past protocol+step fields (8 bytes total), iterate over buckets reading [type BE][len BE][data] per iteration, break on kXRS_none terminator, return 0 with data_out/len_out on match, -1 on not found or truncated bucket. */
/*
 * Scan a binary XrdSutBuffer for a bucket of a given type.
 *
 * XrdSutBuffer binary wire layout (all multi-byte fields are big-endian):
 *
 *   [protocol_name\0]   null-terminated string, e.g. "gsi\0" (4 bytes)
 *   [step : uint32 BE]  e.g. kXGC_certreq=1000, kXGS_cert=2001
 *   zero or more buckets:
 *     [type : uint32 BE]
 *     [len  : uint32 BE]
 *     [data : len bytes]
 *   [kXRS_none : uint32 BE]  terminator
 */

int
gsi_find_bucket(const u_char *payload, size_t plen, uint32_t target_type,
    const u_char **data_out, size_t *len_out)
{
    /* The scan now lives in the shared gsi_core.c (single source for both the
     * module and the native client). u_char and uint8_t are the same type. */
    return brix_gsi_find_bucket(payload, plen, target_type,
                                  data_out, len_out);
}

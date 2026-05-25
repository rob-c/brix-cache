#include "gsi_internal.h"

/* ---- Function: gsi_find_bucket() ----
 * WHAT: Binary XrdSutBuffer parser — scans payload for a bucket of specified type by iterating over big-endian [type: uint32, len: uint32, data: len bytes] entries terminated by kXRS_none. Validates minimum frame size (8 bytes), uses ngx_strnlen() safety guard on protocol name null-termination to prevent out-of-frame reads from missing terminator, skips past protocol+step fields, iterates buckets reading type+len then checking match against target_type before advancing cursor by bucket_len.
 * WHY: GSI wire messages use nested bucket structures requiring precise extraction of DH public keys (kXRS_puk), encrypted cert chains (kXRS_main), cipher negotiation lists (kXRS_cipher_alg), and certificate data (kXRS_x509). ngx_strnlen() prevents protocol name missing null terminator from causing out-of-bounds reads in untrusted binary frames.
 * */
/* ------------------------------------------------------------------ */
/* GSI Buffer — XrdSutBucket Binary Parser                              */
/* ------------------------------------------------------------------ */
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
    const u_char *cursor;
    const u_char *payload_end;
    size_t        protocol_name_len;

    if (plen < 8) {
        return -1;
    }

    cursor = payload;
    payload_end = payload + plen;

    /*
     * The protocol string is NUL-terminated but arrives inside an untrusted
     * binary frame.  ngx_strnlen() keeps a missing terminator from turning the
     * scan into an out-of-frame read.
     */
    protocol_name_len = ngx_strnlen((u_char *) cursor, plen) + 1;
    if (protocol_name_len >= plen) {
        return -1;
    }
    cursor += protocol_name_len;

    if (cursor + 4 > payload_end) {
        return -1;
    }
    cursor += 4;

    while (cursor + 8 <= payload_end) {
        uint32_t bucket_type;
        uint32_t bucket_len;

        ngx_memcpy(&bucket_type, cursor, 4);
        bucket_type = ntohl(bucket_type);
        ngx_memcpy(&bucket_len, cursor + 4, 4);
        bucket_len = ntohl(bucket_len);
        cursor += 8;

        if (bucket_type == (uint32_t) kXRS_none) {
            break;
        }

        if ((size_t) (payload_end - cursor) < bucket_len) {
            return -1;
        }

        if (bucket_type == target_type) {
            *data_out = cursor;
            *len_out = bucket_len;
            return 0;
        }

        cursor += bucket_len;
    }

    return -1;
}

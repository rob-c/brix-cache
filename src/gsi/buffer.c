#include "gsi_internal.h"

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

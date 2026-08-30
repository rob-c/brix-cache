/*
 * sd_remote_checksum.c — checksum offload for the remote-origin (s3://) driver.
 *
 * WHAT: The `query_checksum` vtable slot. Answers a checksum request from the
 *       digest the S3 origin ALREADY stores for the object, read off one signed
 *       HEAD, instead of reading the object's bytes back to hash them.
 *
 * WHY:  Without it, a checksum against an s3:// export is a full-object Range-GET
 *       walk across the network — for a WLCG dataset that is the whole transfer,
 *       paid a second time for a value the store computed at upload. This is the
 *       s3 sibling of the root:// kXR_Qcksum and the http RFC-3230 offloads; the
 *       byte-reading compute in core/compat/integrity_info.c stays the fallback.
 *
 * HOW:  S3 exposes two independent surfaces, and they are not interchangeable:
 *         - the additional-checksum headers (`x-amz-checksum-<algo>`), present
 *           only when the uploader supplied one, base64-encoded, and returned
 *           only when the request asks (`x-amz-checksum-mode: ENABLED`);
 *         - the `ETag`, which is an md5 of the object — but ONLY for a
 *           single-part upload. A multipart ETag is an md5 OF THE PART DIGESTS
 *           with a `-<parts>` suffix and is not the object's md5 at all, so it is
 *           refused rather than handed on.
 *       The value is normalised to lowercase hex through the shared digest
 *       grammar (core/compat/digest_header.c) — the same normalisation the http
 *       offload and the WebDAV PUT verifier use, so an S3-sourced digest and an
 *       origin-sourced one cannot be spelled differently.
 *
 * A decline is never a failure: per the slot contract the caller falls back to
 * reading the bytes, so an object uploaded without a checksum, an algorithm S3
 * does not compute, or a multipart ETag simply costs one HEAD.
 */

#include "sd_remote_internal.h"

#include "core/compat/digest_header.h"

#include <errno.h>
#include <string.h>

/* Longest value read off the wire: a base64 sha-256 is 44 bytes, a quoted
 * multipart ETag with a large part count is under 60. 128 leaves room for an
 * origin that pads or quotes generously; anything longer is not a digest this
 * driver can use and the grammar refuses it. */
#define SD_REMOTE_CK_RAW_MAX  128

/* Canonical brix algorithm → the S3 response header carrying it, and how that
 * header encodes its value. Only algorithms S3 itself computes appear here: an
 * algorithm absent from the table declines BEFORE any I/O, exactly as the http
 * offload declines an algorithm with no registered RFC-3230 token. */
static const struct {
    const char *algo;
    const char *hdr;
    int         b64;
} sd_remote_ck_map[] = {
    { "crc32",     "x-amz-checksum-crc32",     1 },
    { "crc32c",    "x-amz-checksum-crc32c",    1 },
    { "crc64nvme", "x-amz-checksum-crc64nvme", 1 },
    { "sha1",      "x-amz-checksum-sha1",      1 },
    { "sha256",    "x-amz-checksum-sha256",    1 },
    { "md5",       "ETag",                     0 },
};

/*
 * WHAT: Reduce a raw `ETag` value to the object's md5 hex, or refuse it.
 * WHY:  An ETag is an md5 of the OBJECT only when the object was uploaded in one
 *       part. AWS spells a multipart ETag "<hex>-<nparts>" — an md5 of the
 *       concatenated part digests, which matches nothing a client can compute —
 *       and server-side-encrypted objects (SSE-KMS/SSE-C) have an ETag that is
 *       not an md5 at all. Handing either back as "the md5" is worse than
 *       declining, because the caller presents it as authoritative.
 * HOW:  Strip the surrounding quotes, then refuse anything but a bare 32-char
 *       run — the '-' of a multipart tag and the width of anything else both
 *       fail that test, so no separate multipart special-case is needed.
 */
static int
sd_remote_etag_md5(char *val)
{
    size_t len = strlen(val);
    size_t i;

    if (len >= 2 && val[0] == '"' && val[len - 1] == '"') {
        memmove(val, val + 1, len - 2);
        val[len - 2] = '\0';
        len -= 2;
    }
    if (len != 32) {
        return -1;            /* multipart ("-<n>"), SSE, or not an md5 at all */
    }
    for (i = 0; i < len; i++) {
        if (!((val[i] >= '0' && val[i] <= '9')
              || (val[i] >= 'a' && val[i] <= 'f')
              || (val[i] >= 'A' && val[i] <= 'F')))
        {
            return -1;
        }
    }
    return 0;
}

/* Index of the table row for `algo`, or -1 when S3 computes no such digest. */
static int
sd_remote_ck_slot(const char *algo)
{
    size_t i;

    for (i = 0; i < sizeof(sd_remote_ck_map) / sizeof(sd_remote_ck_map[0]); i++) {
        if (strcmp(algo, sd_remote_ck_map[i].algo) == 0) {
            return (int) i;
        }
    }
    return -1;
}

ngx_int_t
sd_remote_query_checksum(brix_sd_obj_t *obj, const char *algo, char *hex_out,
    size_t hex_sz)
{
    sd_remote_obj_state *st;
    sd_s3_meta_buf       mb;
    char                 raw[SD_REMOTE_CK_RAW_MAX];
    char                 hex[BRIX_DIGEST_HEX_MAX];
    char                 errbuf[256];
    ssize_t              n;
    int                  slot;

    if (obj == NULL || obj->state == NULL || algo == NULL || hex_out == NULL
        || hex_sz == 0)
    {
        return NGX_DECLINED;
    }
    slot = sd_remote_ck_slot(algo);
    if (slot < 0) {
        return NGX_DECLINED;   /* S3 stores no such digest — never ask */
    }
    st = obj->state;
    if (st->s3 == NULL) {
        return NGX_DECLINED;
    }

    mb.buf = raw;
    mb.cap = sizeof(raw);
    n = sd_s3_get_checksum(st->s3, sd_remote_ck_map[slot].hdr, &mb, errbuf,
                           sizeof(errbuf));
    if (n < 0) {
        return NGX_ERROR;      /* transport/HTTP fault → compute the bytes */
    }
    if (n == 0) {
        return NGX_DECLINED;   /* uploaded without this checksum */
    }
    if (sd_remote_ck_map[slot].b64 == 0 && sd_remote_etag_md5(raw) != 0) {
        return NGX_DECLINED;
    }
    if (brix_digest_value_hex((u_char *) raw, ngx_strlen(raw),
                              sd_remote_ck_map[slot].b64, hex, sizeof(hex))
        != NGX_OK)
    {
        return NGX_DECLINED;   /* unusable value: refuse it whole */
    }
    brix_digest_hex_pad(algo, hex, sizeof(hex));
    if (ngx_strlen(hex) + 1 > hex_sz) {
        return NGX_DECLINED;
    }
    ngx_cpystrn((u_char *) hex_out, (u_char *) hex, hex_sz);
    return NGX_OK;
}

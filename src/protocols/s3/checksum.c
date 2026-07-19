/*
 * checksum.c — S3 additional-algorithm checksums (phase-43 W1).
 *
 * WHAT: Generalizes S3 full-object integrity beyond CRC-64/NVME to the full AWS
 *   set — CRC32, CRC32C, SHA-1, SHA-256, CRC-64/NVME — for both the upload
 *   verify+echo path (PUT / UploadPart) and the GET/HEAD echo path.
 *
 * WHY: Modern AWS SDKs negotiate a request checksum by default and send
 *   x-amz-checksum-<algo> (and/or x-amz-sdk-checksum-algorithm).  Before this
 *   workstream only crc64nvme was verified; a client that selected crc32 or
 *   sha256 had its integrity header silently ignored — a data-integrity gap.
 *
 * HOW: One descriptor table maps each AWS algorithm token to the integrity-layer
 *   algorithm name and the wire header.  s3_checksum_b64() computes (or
 *   cache-reads) the checksum via the shared integrity engine — which already
 *   owns every algorithm and the xattr cache — and re-encodes the hex digest as
 *   AWS's base64-of-raw-bytes wire form at the edge (INVARIANT #9: encode at the
 *   edge, never in the kernel).  s3_put_checksum_apply() picks the client's
 *   algorithm, rejects conflicting/ambiguous selections (400 InvalidRequest),
 *   verifies a supplied value (400 BadDigest on mismatch — object removed) and
 *   echoes the result; with no client checksum it preserves the historical
 *   crc64nvme default.
 */

#include "s3.h"
#include "core/http/http_headers.h"
#include "core/http/http_query.h"
#include "core/compat/integrity_info.h"
#include "core/compat/hex.h"
#include "fs/vfs/vfs.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* AWS algorithm token → integrity-engine name + wire header. */
typedef struct {
    const char *token;     /* lowercase AWS token: "crc32", "sha256", ...   */
    const char *alg_name;  /* integrity-engine algorithm name                */
    const char *header;    /* x-amz-checksum-<token> response/request header */
} s3_cksum_desc_t;

static const s3_cksum_desc_t s3_cksum_table[] = {
    { "crc32",     "crc32",     "x-amz-checksum-crc32"     },
    { "crc32c",    "crc32c",    "x-amz-checksum-crc32c"    },
    { "crc64nvme", "crc64nvme", "x-amz-checksum-crc64nvme" },
    { "sha1",      "sha1",      "x-amz-checksum-sha1"      },
    { "sha256",    "sha256",    "x-amz-checksum-sha256"    },
};

#define S3_CKSUM_TABLE_N \
    (sizeof(s3_cksum_table) / sizeof(s3_cksum_table[0]))

/* Default algorithm when the client requested no checksum (AWS SDK default). */
#define S3_CKSUM_DEFAULT_IDX  2   /* crc64nvme */

/*
 * s3_cksum_vfs_unlink — remove the just-committed object via the VFS unlink
 * surface when a client integrity check fails (mismatch / ambiguous / trailer
 * with an unsupported algorithm).  Replicates the reference ctx helper
 * (object.c s3_vfs_ctx) and routes the delete through the VFS (OP_DELETE metric
 * + access-log + write gate) instead of the bare confined-canon unlink, while
 * delegating the same confined syscall underneath.  Best-effort — the caller's
 * result code is already decided.
 */
static void
s3_cksum_vfs_unlink(ngx_http_request_t *r, const char *fs_path,
    const char *root_canon)
{
    ngx_http_s3_loc_conf_t *cf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    ngx_http_s3_req_ctx_t  *s3ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    brix_vfs_ctx_t        vctx;
    int                     is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    /* root_canon is passed by the caller; it equals cf->common.root_canon. */
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        root_canon, cf->cache_root_canon, cf->common.allow_write, is_tls,
        (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);

    (void) brix_vfs_unlink(&vctx);
}

/*
 * s3_cksum_vfs_open — confined read-open of fs_path through the VFS (same ctx
 * construction as s3_cksum_vfs_unlink). The returned handle's fd backs the
 * checksum kernel; the caller releases it with brix_vfs_close. NULL on error.
 */
static brix_vfs_file_t *
s3_cksum_vfs_open(ngx_http_request_t *r, const char *fs_path,
    const char *root_canon)
{
    ngx_http_s3_loc_conf_t *cf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    ngx_http_s3_req_ctx_t  *s3ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    brix_vfs_ctx_t        vctx;
    int                     is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        root_canon, cf->cache_root_canon, cf->common.allow_write, is_tls,
        (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);

    return brix_vfs_open(&vctx, BRIX_VFS_O_READ, NULL);
}

/*
 * s3_checksum_b64 — base64 wire value of one algorithm for an open fd.
 *
 * Pulls the lowercase hex digest from the shared integrity engine (xattr cache
 * when present), converts it to raw bytes, and base64-encodes them — the AWS
 * x-amz-checksum-* wire form.  cache_only=1 returns NGX_DECLINED on a cache miss
 * rather than paying a full-file read (GET/HEAD echo path).
 *
 * Returns NGX_OK (out filled), NGX_DECLINED (cache_only miss), or NGX_ERROR.
 */
ngx_int_t
s3_checksum_b64(ngx_http_request_t *r, int fd, const char *path,
    const char *alg_name, ngx_flag_t cache_only, char *out, size_t outsz)
{
    brix_integrity_info_t info;
    brix_integrity_opts_t iopts;
    unsigned char           bytes[64];
    size_t                  hexlen, nbytes, i;
    ngx_str_t               src, dst;
    ngx_int_t               rc;

    ngx_memzero(&iopts, sizeof(iopts));
    iopts.allow_xattr_cache    = 1;
    iopts.update_xattr_cache   = cache_only ? 0 : 1;
    iopts.require_regular_file = 1;
    iopts.no_compute           = cache_only ? 1 : 0;

    rc = brix_integrity_get_fd(r->connection->log, fd, NULL, path, alg_name,
                                 &iopts, &info);
    if (rc != NGX_OK) {
        return rc;
    }

    hexlen = ngx_strlen(info.hex);
    if (hexlen == 0 || (hexlen % 2) != 0 || (hexlen / 2) > sizeof(bytes)) {
        return NGX_ERROR;
    }
    nbytes = hexlen / 2;
    for (i = 0; i < nbytes; i++) {
        int hi = brix_hex_from_char((unsigned char) info.hex[2 * i]);
        int lo = brix_hex_from_char((unsigned char) info.hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return NGX_ERROR;
        }
        bytes[i] = (unsigned char) ((hi << 4) | lo);
    }

    if (outsz < (size_t) ngx_base64_encoded_length(nbytes) + 1) {
        return NGX_ERROR;
    }
    src.data = bytes;
    src.len  = nbytes;
    dst.data = (u_char *) out;
    ngx_encode_base64(&dst, &src);
    out[dst.len] = '\0';
    return NGX_OK;
}

/* Find a descriptor by lowercase/uppercase AWS token, else NULL. */
static const s3_cksum_desc_t *
s3_cksum_by_token(const char *tok, size_t len)
{
    ngx_uint_t i;

    for (i = 0; i < S3_CKSUM_TABLE_N; i++) {
        if (ngx_strlen(s3_cksum_table[i].token) == len
            && ngx_strncasecmp((u_char *) s3_cksum_table[i].token,
                               (u_char *) tok, len) == 0)
        {
            return &s3_cksum_table[i];
        }
    }
    return NULL;
}

/*
 * s3_put_select_algo — decide which checksum algorithm a PUT requested.
 *
 * Scans the x-amz-checksum-<algo> value headers and the
 * x-amz-sdk-checksum-algorithm / x-amz-checksum-algorithm declaration.  Sets
 * *want_value to the supplied value header (NULL if only a declaration / none).
 *
 * Returns the chosen descriptor, or NULL for "no checksum requested"
 * (caller applies the crc64nvme default).  Sets *conflict=1 when the selection
 * is ambiguous (two different value headers, or a value header disagreeing with
 * the declared algorithm) — the caller answers 400 InvalidRequest.
 */
static const s3_cksum_desc_t *
s3_put_select_algo(ngx_http_request_t *r, ngx_table_elt_t **want_value,
    int *conflict)
{
    const s3_cksum_desc_t *chosen = NULL;
    ngx_table_elt_t       *value_hdr = NULL;
    ngx_table_elt_t       *decl;
    ngx_uint_t             i, value_count = 0;

    *conflict = 0;
    *want_value = NULL;

    for (i = 0; i < S3_CKSUM_TABLE_N; i++) {
        ngx_table_elt_t *h = brix_http_find_header(
            r, s3_cksum_table[i].header,
            ngx_strlen(s3_cksum_table[i].header));
        if (h != NULL && h->value.len > 0) {
            value_count++;
            chosen = &s3_cksum_table[i];
            value_hdr = h;
        }
    }

    if (value_count > 1) {
        *conflict = 1;
        return NULL;
    }

    /* x-amz-sdk-checksum-algorithm (preferred) or x-amz-checksum-algorithm. */
    decl = brix_http_find_header(r, "x-amz-sdk-checksum-algorithm",
                                   sizeof("x-amz-sdk-checksum-algorithm") - 1);
    if (decl == NULL) {
        decl = brix_http_find_header(r, "x-amz-checksum-algorithm",
                                       sizeof("x-amz-checksum-algorithm") - 1);
    }
    if (decl != NULL && decl->value.len > 0) {
        const s3_cksum_desc_t *d =
            s3_cksum_by_token((const char *) decl->value.data, decl->value.len);
        if (d == NULL) {
            *conflict = 1;            /* declared an algorithm we don't support */
            return NULL;
        }
        if (chosen != NULL && chosen != d) {
            *conflict = 1;            /* value header disagrees with declaration */
            return NULL;
        }
        chosen = d;                  /* declaration alone selects the algorithm */
    }

    *want_value = value_hdr;
    return chosen;
}

/*
 * s3_put_checksum_apply — verify a client-supplied full-object checksum (any
 * supported algorithm) and echo it; replaces the crc64nvme-only path.
 *
 * Returns S3_CKSUM_OK (verified or echoed), S3_CKSUM_MISMATCH (supplied value
 * did not match — object removed; caller answers 400 BadDigest),
 * S3_CKSUM_CONFLICT (ambiguous selection — caller answers 400 InvalidRequest),
 * or S3_CKSUM_ERROR (our own compute failed — caller proceeds without a header).
 */
s3_cksum_result_t
s3_put_checksum_apply(ngx_http_request_t *r, const char *fs_path,
    const char *root_canon)
{
    const s3_cksum_desc_t *desc;
    ngx_table_elt_t       *want_value;
    int                    conflict;
    brix_vfs_file_t     *fh;
    char                   b64[S3_CHECKSUM_B64_MAX];
    ngx_int_t              rc;

    desc = s3_put_select_algo(r, &want_value, &conflict);
    if (conflict) {
        /* The object was already committed; remove it — a malformed integrity
         * request must not leave an object behind (AWS rejects pre-store). */
        s3_cksum_vfs_unlink(r, fs_path, root_canon);
        return S3_CKSUM_CONFLICT;
    }
    if (desc == NULL) {
        desc = &s3_cksum_table[S3_CKSUM_DEFAULT_IDX];   /* crc64nvme default */
    }

    fh = s3_cksum_vfs_open(r, fs_path, root_canon);
    if (fh == NULL) {
        return S3_CKSUM_ERROR;
    }
    rc = s3_checksum_b64(r, brix_vfs_file_fd(fh), fs_path, desc->alg_name,
                         0 /* compute+cache */, b64, sizeof(b64));
    brix_vfs_close(fh, r->connection->log);
    if (rc != NGX_OK) {
        return S3_CKSUM_ERROR;
    }

    if (want_value != NULL) {
        size_t blen = ngx_strlen(b64);
        if (want_value->value.len != blen
            || ngx_strncmp(want_value->value.data, (u_char *) b64, blen) != 0)
        {
            s3_cksum_vfs_unlink(r, fs_path, root_canon);
            return S3_CKSUM_MISMATCH;
        }
    }

    (void) s3_set_header(r, desc->header, b64);
    (void) s3_set_header(r, S3_HDR_CHECKSUM_TYPE, "FULL_OBJECT");
    return S3_CKSUM_OK;
}

/*
 * s3_content_md5_verify — classic Content-MD5 (RFC 1864) ingest integrity.
 *
 * WHAT: When a PutObject carries Content-MD5 (base64 of the object's 128-bit MD5),
 *   S3's contract requires the server verify the stored object against it and
 *   answer 400 BadDigest on mismatch (400 InvalidDigest when the header is
 *   malformed).  Runs post-commit over the just-published object, the same
 *   read-back + unlink-on-mismatch model as s3_put_checksum_apply.
 *
 * WHY: brix authenticates SigV4 with a hard-coded UNSIGNED-PAYLOAD canonical
 *   request (auth_sigv4_verify_crypto.c) — the body is never folded into the
 *   signature — and the x-amz-checksum-* form is the only integrity header that
 *   was verified.  A client that asserted the historically dominant Content-MD5
 *   (boto3/aws-cli/many HEP tools) had it silently ignored, so a body a hostile
 *   middlebox flipped past the TCP checksum was committed and served as good.
 *   A real (non-UNSIGNED) x-amz-content-sha256 stays out of scope: brix signs
 *   UNSIGNED-PAYLOAD and the dominant XrdClS3 client never sends a payload hash.
 *
 * Returns:
 *   S3_CKSUM_OK       — verified, or no Content-MD5 present (nothing to check)
 *   S3_CKSUM_MISMATCH — value did not match the stored bytes (object removed)
 *   S3_CKSUM_CONFLICT — malformed Content-MD5 (not base64 / not 16 bytes; removed)
 *   S3_CKSUM_ERROR    — our own compute failed (object stands, unverified)
 */
s3_cksum_result_t
s3_content_md5_verify(ngx_http_request_t *r, const char *fs_path,
    const char *root_canon)
{
    ngx_table_elt_t       *hdr;
    ngx_table_elt_t       *ce;
    ngx_str_t              src, dst;
    u_char                 raw[24];   /* MD5 is 16; base64-decoded upper bound   */
    u_char                 exp_hex[32];
    brix_vfs_file_t       *fh;
    brix_integrity_info_t  info;
    brix_integrity_opts_t  o;
    ngx_int_t              rc;

    hdr = brix_http_find_header(r, "Content-MD5", sizeof("Content-MD5") - 1);
    if (hdr == NULL || hdr->value.len == 0) {
        return S3_CKSUM_OK;                 /* no assertion to verify */
    }

    /* A decoded body cannot match an MD5 the client took over the encoded bytes —
     * skip, matching the verify-on-write / WebDAV-ingest limitation. */
    ce = brix_http_find_header(r, "Content-Encoding",
                               sizeof("Content-Encoding") - 1);
    if (ce != NULL && ce->value.len > 0) {
        return S3_CKSUM_OK;
    }

    /* base64 → exactly 16 raw MD5 bytes; anything else is a malformed header.  A
     * malformed integrity assertion must not leave the object behind (AWS rejects
     * pre-store; we are post-commit, so remove it), mirroring the ambiguous
     * x-amz-checksum selection path. */
    src = hdr->value;
    if (ngx_base64_decoded_length(src.len) > sizeof(raw)) {
        s3_cksum_vfs_unlink(r, fs_path, root_canon);
        return S3_CKSUM_CONFLICT;           /* absurdly long — not a Content-MD5 */
    }
    dst.data = raw;
    if (ngx_decode_base64(&dst, &src) != NGX_OK || dst.len != 16) {
        s3_cksum_vfs_unlink(r, fs_path, root_canon);
        return S3_CKSUM_CONFLICT;
    }
    (void) ngx_hex_dump(exp_hex, raw, 16);  /* 32 lowercase hex chars */

    fh = s3_cksum_vfs_open(r, fs_path, root_canon);
    if (fh == NULL) {
        return S3_CKSUM_ERROR;
    }
    ngx_memzero(&o, sizeof(o));
    o.require_regular_file = 1;             /* hash the stored bytes fresh */
    rc = brix_integrity_get_fd(r->connection->log, brix_vfs_file_fd(fh), NULL,
                               fs_path, "md5", &o, &info);
    brix_vfs_close(fh, r->connection->log);
    if (rc != NGX_OK) {
        return S3_CKSUM_ERROR;              /* object stands, unverified */
    }

    if (ngx_strlen(info.hex) != sizeof(exp_hex)
        || ngx_strncasecmp((u_char *) info.hex, exp_hex, sizeof(exp_hex)) != 0)
    {
        s3_cksum_vfs_unlink(r, fs_path, root_canon);
        return S3_CKSUM_MISMATCH;
    }
    return S3_CKSUM_OK;
}

/*
 * s3_put_trailer_checksum_apply — verify+echo a checksum carried in an
 * aws-chunked trailer (phase-43 W0).  Unlike the header path, the algorithm and
 * value come from the decoded stream's trailer line rather than a request
 * header.  Same result contract as s3_put_checksum_apply.
 */
s3_cksum_result_t
s3_put_trailer_checksum_apply(ngx_http_request_t *r, const char *fs_path,
    const char *root_canon, const char *algo_token, const char *value)
{
    const s3_cksum_desc_t *desc;
    brix_vfs_file_t     *fh;
    char                   b64[S3_CHECKSUM_B64_MAX];
    ngx_int_t              rc;

    desc = s3_cksum_by_token(algo_token, ngx_strlen(algo_token));
    if (desc == NULL) {
        /* Trailer named an algorithm we do not support — reject the upload. */
        s3_cksum_vfs_unlink(r, fs_path, root_canon);
        return S3_CKSUM_CONFLICT;
    }

    fh = s3_cksum_vfs_open(r, fs_path, root_canon);
    if (fh == NULL) {
        return S3_CKSUM_ERROR;
    }
    rc = s3_checksum_b64(r, brix_vfs_file_fd(fh), fs_path, desc->alg_name, 0,
                         b64, sizeof(b64));
    brix_vfs_close(fh, r->connection->log);
    if (rc != NGX_OK) {
        return S3_CKSUM_ERROR;
    }

    if (value != NULL && value[0] != '\0') {
        size_t blen = ngx_strlen(b64);
        if (ngx_strlen(value) != blen
            || ngx_strncmp((u_char *) value, (u_char *) b64, blen) != 0)
        {
            s3_cksum_vfs_unlink(r, fs_path, root_canon);
            return S3_CKSUM_MISMATCH;
        }
    }

    (void) s3_set_header(r, desc->header, b64);
    (void) s3_set_header(r, S3_HDR_CHECKSUM_TYPE, "FULL_OBJECT");
    return S3_CKSUM_OK;
}

/*
 * s3_echo_object_checksums — GET/HEAD response checksum echo.
 *
 * Always echoes a cached crc64nvme (historical behavior — never recomputes on
 * read).  When the request carries x-amz-checksum-mode: ENABLED, additionally
 * echoes every other algorithm that is present in the xattr cache, matching AWS
 * which returns stored additional checksums only when the client opts in.
 */
void
s3_echo_object_checksums(ngx_http_request_t *r, int fd, const char *path)
{
    ngx_table_elt_t *mode;
    int              mode_enabled;
    int              emitted_type = 0;
    ngx_uint_t       i;
    char             b64[S3_CHECKSUM_B64_MAX];

    mode = brix_http_find_header(r, "x-amz-checksum-mode",
                                   sizeof("x-amz-checksum-mode") - 1);
    mode_enabled = (mode != NULL && mode->value.len == sizeof("ENABLED") - 1
                    && ngx_strncasecmp(mode->value.data,
                                       (u_char *) "ENABLED",
                                       sizeof("ENABLED") - 1) == 0);

    for (i = 0; i < S3_CKSUM_TABLE_N; i++) {
        /* Without checksum-mode, only the crc64nvme default is echoed. */
        if (!mode_enabled && i != S3_CKSUM_DEFAULT_IDX) {
            continue;
        }
        if (s3_checksum_b64(r, fd, path, s3_cksum_table[i].alg_name,
                            1 /* cache-only */, b64, sizeof(b64)) == NGX_OK)
        {
            (void) s3_set_header(r, s3_cksum_table[i].header, b64);
            if (!emitted_type) {
                (void) s3_set_header(r, S3_HDR_CHECKSUM_TYPE, "FULL_OBJECT");
                emitted_type = 1;
            }
        }
    }
}

/*
 * tpc_verify.c - HTTP-TPC pull completion gate (size + checksum).
 *
 * WHAT: webdav_tpc_verify_pulled() runs after the last byte of a COPY pull has
 *       landed in the staged temp and before it is committed.  It re-probes the
 *       source with one HEAD (carrying Want-Digest when a checksum algorithm is
 *       configured), then compares the source's declared Content-Length against
 *       the bytes on disk and, when asked, recomputes the returned RFC-3230
 *       Digest over the staged temp.  Any disagreement fails the pull.
 *
 * WHY:  the pull's only in-band completion signal is "curl stopped without an
 *       error", which a chunked source that dies mid-body, a truncating
 *       middlebox, or a corrupting one can all produce.  The native root:// TPC
 *       has carried both gates for this reason (brix_tpc_require_source_size /
 *       brix_tpc_verify_checksum, src/tpc/outbound/source_stream.c); the HTTP
 *       plane had neither, so the truncation and bit-flip classes proven on the
 *       native plane were unimplemented here.  Semantics are deliberately the
 *       same as the native pair so an operator reasons about one contract.
 *
 * HOW:  both halves are off by default, so an existing deployment sees no new
 *       refusal.  Whenever either is on the size comparison runs (it is free
 *       once the HEAD is paid for); tpc_require_source_size decides only what a
 *       source that declares NO length means.  The checksum half is fail-closed
 *       exactly like the native one: no Digest, an unparseable one, an algorithm
 *       brix cannot compute, or a mismatch all refuse.  Every refusal returns
 *       NGX_HTTP_BAD_GATEWAY, which the three pull tiers already treat as a
 *       failed transfer — the staged temp is aborted, never committed.  The gate
 *       is hooked into webdav_tpc_run_curl_pull() and the multi-stream driver,
 *       so all three tiers (sync, thread, marker) pass through it.
 */

#include "tpc_curl_internal.h"

#include "fs/vfs/vfs.h"             /* confined open of the staged temp */
#include "core/compat/checksum.h"   /* brix_checksum_hex_name_fd */

#include <strings.h>

/* Longest "alg=value" a source can hand back and still be usable: an algorithm
 * name plus a SHA-512 hex digest fits in well under half of this. */
#define WEBDAV_TPC_DIGEST_MAX  256

/*
 * tpc_verify_src_t — what the completion HEAD learned about the source.
 * `size` is -1 when the source declared no Content-Length (a chunked origin);
 * `digest` is the first RFC-3230 "alg=value" pair of its Digest: header, or "".
 */
typedef struct {
    off_t  size;
    char   digest[WEBDAV_TPC_DIGEST_MAX];
} tpc_verify_src_t;


/*
 * tpc_verify_header_cb — libcurl header sink that keeps only Digest:.
 * Stores the trimmed value (first one wins, over-long ones are dropped so the
 * checksum half fails closed rather than comparing a truncated digest) and
 * always reports the full byte count so curl never treats this as a write error.
 */
static size_t
tpc_verify_header_cb(char *buf, size_t size, size_t nitems, void *userdata)
{
    tpc_verify_src_t *src = userdata;
    size_t            total = size * nitems;
    size_t            len = total;
    const char       *v = buf;
    static const char key[] = "digest:";
    const size_t      klen = sizeof(key) - 1;

    if (len <= klen || src->digest[0] != '\0'
        || ngx_strncasecmp((u_char *) buf, (u_char *) key, klen) != 0)
    {
        return total;
    }

    v += klen;
    len -= klen;
    while (len > 0 && (*v == ' ' || *v == '\t')) {
        v++;
        len--;
    }
    while (len > 0 && (v[len - 1] == '\r' || v[len - 1] == '\n'
                       || v[len - 1] == ' ' || v[len - 1] == '\t'))
    {
        len--;
    }
    if (len > 0 && len < sizeof(src->digest)) {
        ngx_memcpy(src->digest, v, len);
        src->digest[len] = '\0';
    }
    return total;
}


/*
 * tpc_verify_want_digest — append "Want-Digest: <alg>" to the probe's header
 * list and re-install it.  No-op when the checksum half is off.  Returns NGX_OK,
 * or NGX_ERROR on slist OOM (the caller frees the partial list).
 */
static ngx_int_t
tpc_verify_want_digest(CURL *curl, ngx_http_brix_webdav_loc_conf_t *conf,
    struct curl_slist **hdrs)
{
    char               want[64];
    struct curl_slist *next;

    if (conf->tpc_verify_digest.len == 0) {
        return NGX_OK;
    }
    ngx_snprintf((u_char *) want, sizeof(want), "Want-Digest: %V%Z",
                 &conf->tpc_verify_digest);
    next = curl_slist_append(*hdrs, want);
    if (next == NULL) {
        return NGX_ERROR;
    }
    *hdrs = next;
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *hdrs);
    return NGX_OK;
}


/*
 * tpc_verify_probe_source — one HEAD of the source over the same secured handle
 * configuration the pull itself used (TLS pin, rebind guard, client credential,
 * transfer headers), capturing Content-Length and Digest:.
 * NGX_OK with *out filled, or NGX_ERROR when the probe could not be made.
 */
static ngx_int_t
tpc_verify_probe_source(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *url,
    ngx_array_t *transfer_headers, const char *user_cert, const char *user_key,
    tpc_verify_src_t *out)
{
    CURL              *curl;
    struct curl_slist *hdrs = NULL;
    struct curl_slist *resolve = NULL;
    CURLcode           res;
    curl_off_t         cl = -1;

    ngx_memzero(out, sizeof(*out));
    out->size = -1;

    curl = curl_easy_init();
    if (curl == NULL) {
        return NGX_ERROR;
    }
    if (tpc_curl_apply_conf(curl, conf, url, transfer_headers, log,
                            user_cert, user_key, &hdrs, &resolve) < 0
        || tpc_verify_want_digest(curl, conf, &hdrs) != NGX_OK)
    {
        return webdav_tpc_curl_finish(NGX_ERROR, curl, hdrs, resolve, NULL);
    }

    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, tpc_verify_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, out);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_webdav: HTTP-TPC completion probe failed: %s",
                      curl_easy_strerror(res));
        return webdav_tpc_curl_finish(NGX_ERROR, curl, hdrs, resolve, NULL);
    }

    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
    out->size = (cl >= 0) ? (off_t) cl : -1;
    return webdav_tpc_curl_finish(NGX_OK, curl, hdrs, resolve, NULL);
}


/*
 * tpc_verify_size — compare what arrived against what the source declared.
 * A declared length that disagrees with the staged temp is unambiguous
 * truncation (or over-read) and always refuses; an undeclared length refuses
 * only under brix_webdav_tpc_require_source_size.
 */
static ngx_int_t
tpc_verify_size(ngx_log_t *log, ngx_http_brix_webdav_loc_conf_t *conf,
    const tpc_verify_src_t *src, int fd)
{
    struct stat st;

    if (src->size < 0) {
        if (!conf->tpc_require_source_size) {
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_webdav: HTTP-TPC pull refused: source declared no "
                      "size and brix_webdav_tpc_require_source_size is on");
        return NGX_HTTP_BAD_GATEWAY;
    }
    if (fstat(fd, &st) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_webdav: HTTP-TPC pull refused: cannot stat the "
                      "staged temp for the size gate");
        return NGX_HTTP_BAD_GATEWAY;
    }
    if (st.st_size != src->size) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_webdav: HTTP-TPC pull truncated: wrote %O of %O "
                      "source bytes", st.st_size, src->size);
        return NGX_HTTP_BAD_GATEWAY;
    }
    return NGX_OK;
}


/*
 * tpc_verify_split — split an RFC-3230 Digest value into algorithm and value.
 * Accepts the first pair of a comma-separated list ("adler32=1f2e,md5=..." →
 * "adler32" + "1f2e").  NGX_ERROR when there is no '=' or either half does not
 * fit, which the caller turns into a refusal.
 */
static ngx_int_t
tpc_verify_split(const char *digest, char *alg, size_t algsz,
    char *val, size_t valsz)
{
    const char *eq = strchr(digest, '=');
    size_t      alen;
    size_t      vlen;

    if (eq == NULL) {
        return NGX_ERROR;
    }
    alen = (size_t) (eq - digest);
    vlen = strcspn(eq + 1, ",");
    if (alen == 0 || alen >= algsz || vlen == 0 || vlen >= valsz) {
        return NGX_ERROR;
    }
    ngx_memcpy(alg, digest, alen);
    alg[alen] = '\0';
    ngx_memcpy(val, eq + 1, vlen);
    val[vlen] = '\0';
    return NGX_OK;
}


/*
 * tpc_verify_checksum — recompute the source's digest over the staged temp.
 * Fail-closed on every uncertainty, matching tpc_verify_source_checksum() on the
 * native plane: no Digest returned, an unparseable one, an algorithm brix cannot
 * compute, or a value mismatch all refuse the pull.
 */
static ngx_int_t
tpc_verify_checksum(ngx_log_t *log, ngx_http_brix_webdav_loc_conf_t *conf,
    const tpc_verify_src_t *src, int fd, const char *tmp_path)
{
    char alg[32];
    char src_hex[2 * EVP_MAX_MD_SIZE + 1];
    char local_hex[2 * EVP_MAX_MD_SIZE + 1];
    char normalized[32];

    if (conf->tpc_verify_digest.len == 0) {
        return NGX_OK;
    }
    if (src->digest[0] == '\0') {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_webdav: HTTP-TPC pull refused: source supplied no "
                      "Digest for Want-Digest: %V", &conf->tpc_verify_digest);
        return NGX_HTTP_BAD_GATEWAY;
    }
    if (tpc_verify_split(src->digest, alg, sizeof(alg),
                         src_hex, sizeof(src_hex)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_webdav: HTTP-TPC pull refused: malformed source "
                      "Digest header");
        return NGX_HTTP_BAD_GATEWAY;
    }
    if (brix_checksum_hex_name_fd(alg, fd, tmp_path, log, local_hex,
                                  sizeof(local_hex), normalized,
                                  sizeof(normalized)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_webdav: HTTP-TPC pull refused: cannot compute "
                      "\"%s\" on the staged temp", alg);
        return NGX_HTTP_BAD_GATEWAY;
    }
    if (strcasecmp(local_hex, src_hex) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_webdav: HTTP-TPC checksum mismatch: source %s=%s "
                      "destination=%s", alg, src_hex, local_hex);
        return NGX_HTTP_BAD_GATEWAY;
    }
    return NGX_OK;
}


ngx_int_t
webdav_tpc_verify_pulled(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *source_url,
    const char *tmp_path, ngx_array_t *transfer_headers,
    const char *user_cert, const char *user_key)
{
    tpc_verify_src_t src;
    ngx_int_t        rc;
    int              fd;

    if (!conf->tpc_require_source_size && conf->tpc_verify_digest.len == 0) {
        return NGX_OK;
    }

    if (tpc_verify_probe_source(log, conf, source_url, transfer_headers,
                                user_cert, user_key, &src) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_webdav: HTTP-TPC pull refused: the completion gate "
                      "could not re-probe the source");
        return NGX_HTTP_BAD_GATEWAY;
    }

    /* Confined read-open of the staged temp — the same seam the pull wrote it
     * through, so the gate cannot be pointed at a planted symlink target. */
    fd = brix_vfs_open_fd(log, conf->common.root_canon, tmp_path,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_webdav: HTTP-TPC pull refused: cannot re-open the "
                      "staged temp for the completion gate");
        return NGX_HTTP_BAD_GATEWAY;
    }

    rc = tpc_verify_size(log, conf, &src, fd);
    if (rc == NGX_OK) {
        rc = tpc_verify_checksum(log, conf, &src, fd, tmp_path);
    }
    (void) close(fd);
    return rc;
}

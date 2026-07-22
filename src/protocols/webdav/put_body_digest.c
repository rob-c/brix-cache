/*
 * put_body_digest.c - WebDAV PUT ingest-digest verification (split from
 * put_body.c).
 *
 * Client->server body integrity for the PUT body-write phase: parsing an
 * RFC-3230 Digest: / legacy Content-MD5: header, and recomputing that digest
 * over the fully-staged bytes before the commit publishes them (§8.3-adjacent).
 * The write dispatch, thread offload, and checksum-on-ingest persistence stay
 * in put_body.c.
 */

#include "webdav.h"
#include "core/http/etag.h"
#include "core/http/http_body.h"
#include "core/compat/integrity_info.h"
#include "core/http/http_conditionals.h"
#include "core/compat/range.h"
#include "core/compat/staged_file.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "fs/xfer/xfer.h"   /* brix_xfer_finish — unified transfer ledger */
#include "auth/impersonate/lifecycle.h"
#include "fs/path/path.h"
#include "core/compat/cstr.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "put_internal.h"

/* ---- ingest-digest verification (client->server body integrity) ----------- */

typedef enum {
    WEBDAV_DIGEST_NONE = 0,   /* no usable ingest digest header present         */
    WEBDAV_DIGEST_FOUND,      /* a supported alg + value parsed (alg/exp filled)*/
    WEBDAV_DIGEST_BAD         /* a supported alg named, but its value is garbage*/
} webdav_digest_kind_t;

/* RFC-3230 Digest tokens / Content-MD5 we can recompute. `b64` = the value is
 * base64 (md5/sha per RFC 3230 + RFC 1864); otherwise it is lowercase hex (the
 * WLCG/dCache convention for adler32/crc32). */
static const struct {
    const char *tok; size_t toklen; const char *alg; int b64;
} webdav_digest_tokens[] = {
    { "md5",     3, "md5",     1 },
    { "sha-256", 7, "sha256",  1 },
    { "sha256",  6, "sha256",  1 },
    { "adler32", 7, "adler32", 0 },
    { "crc32c",  6, "crc32c",  0 },
    { "crc32",   5, "crc32",   0 },
};

/* Two hex checksums are equal ignoring case and leading-zero padding (a client
 * may send an un-padded adler32 while our compute zero-pads to the alg width). */
static int
webdav_hex_norm_equal(const char *a, const char *b)
{
    while (*a == '0') { a++; }
    while (*b == '0') { b++; }
    for (; *a != '\0' && *b != '\0'; a++, b++) {
        if (ngx_tolower((u_char) *a) != ngx_tolower((u_char) *b)) {
            return 0;
        }
    }
    return *a == '\0' && *b == '\0';
}

/* Normalise a digest header value into lowercase hex in out[]. A base64 value is
 * decoded then hex-encoded; a hex value is copied lowercased. */
static ngx_int_t
webdav_digest_value_hex(ngx_http_request_t *r, const u_char *val, size_t vlen,
    int is_b64, char *out, size_t outsz)
{
    if (vlen == 0) {
        return NGX_ERROR;
    }
    if (is_b64) {
        ngx_str_t src, dst;
        src.data = (u_char *) val;
        src.len  = vlen;
        dst.len  = ngx_base64_decoded_length(vlen);
        dst.data = ngx_pnalloc(r->pool, dst.len ? dst.len : 1);
        if (dst.data == NULL || ngx_decode_base64(&dst, &src) != NGX_OK) {
            return NGX_ERROR;
        }
        if (dst.len == 0 || dst.len * 2 + 1 > outsz) {
            return NGX_ERROR;
        }
        ngx_hex_dump((u_char *) out, dst.data, dst.len);
        out[dst.len * 2] = '\0';
        return NGX_OK;
    }
    if (vlen + 1 > outsz) {
        return NGX_ERROR;
    }
    {
        size_t i;
        for (i = 0; i < vlen; i++) {
            u_char c = val[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                  || (c >= 'A' && c <= 'F')))
            {
                return NGX_ERROR;   /* not a hex digit — malformed */
            }
            out[i] = (char) ngx_tolower(c);
        }
        out[vlen] = '\0';
    }
    return NGX_OK;
}

/* Strip leading and trailing linear whitespace from a [*s, *s+*len) slice. */
static void
webdav_tok_trim(u_char **s, size_t *len)
{
    u_char *p = *s;
    size_t  n = *len;
    while (n > 0 && (*p == ' ' || *p == '\t')) { p++; n--; }
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t')) { n--; }
    *s = p;
    *len = n;
}

/* Match a trimmed Digest token=value pair against the supported-alg table.
 * Returns 1 if the token names a supported alg — *out is then FOUND (with *alg
 * and exp_hex filled) or BAD (value not valid hex) — else 0 to keep scanning. */
static int
webdav_digest_match(ngx_http_request_t *r, u_char *tok, size_t tlen,
    u_char *v, size_t vlen, const char **alg, char *exp_hex, size_t exp_sz,
    webdav_digest_kind_t *out)
{
    size_t ntok = sizeof(webdav_digest_tokens)
                  / sizeof(webdav_digest_tokens[0]);
    size_t i;

    for (i = 0; i < ntok; i++) {
        if (tlen == webdav_digest_tokens[i].toklen
            && ngx_strncasecmp(tok,
                   (u_char *) webdav_digest_tokens[i].tok, tlen) == 0)
        {
            if (webdav_digest_value_hex(r, v, vlen,
                    webdav_digest_tokens[i].b64, exp_hex, exp_sz) != NGX_OK)
            {
                *out = WEBDAV_DIGEST_BAD;
            } else {
                *alg = webdav_digest_tokens[i].alg;
                *out = WEBDAV_DIGEST_FOUND;
            }
            return 1;
        }
    }
    return 0;
}

/* Scan a Digest: header value (comma-separated alg=value pairs) for the first
 * supported alg.  Returns 1 with *out set (FOUND/BAD) once a token matches, or 0
 * if no listed token is supported (caller falls through to Content-MD5). */
static int
webdav_digest_scan(ngx_http_request_t *r, ngx_table_elt_t *h,
    const char **alg, char *exp_hex, size_t exp_sz, webdav_digest_kind_t *out)
{
    u_char *p = h->value.data, *end = p + h->value.len;

    while (p < end) {
        u_char *comma = ngx_strlchr(p, end, ',');
        u_char *iend  = comma ? comma : end;
        u_char *eq    = ngx_strlchr(p, iend, '=');
        if (eq != NULL) {
            u_char *tok = p, *v = eq + 1;
            size_t  tlen = eq - p, vlen = iend - (eq + 1);
            webdav_tok_trim(&tok, &tlen);
            webdav_tok_trim(&v, &vlen);
            if (webdav_digest_match(r, tok, tlen, v, vlen, alg,
                    exp_hex, exp_sz, out))
            {
                return 1;
            }
        }
        p = comma ? comma + 1 : end;
    }
    return 0;
}

/* Pick the first supported digest from Digest: (RFC 3230) then Content-MD5:. On
 * WEBDAV_DIGEST_FOUND, *alg points at a static alg name and exp_hex holds the
 * client-asserted value as lowercase hex. Unsupported Digest tokens are skipped
 * (best-effort interop), so a Digest that names only algs we cannot compute reads
 * as NONE — require_digest then decides whether that is acceptable. */
static webdav_digest_kind_t
webdav_digest_select(ngx_http_request_t *r, const char **alg,
    char *exp_hex, size_t exp_sz)
{
    ngx_table_elt_t      *h;
    webdav_digest_kind_t  kind;

    h = brix_http_find_header(r, "Digest", sizeof("Digest") - 1);
    if (h != NULL && h->value.len > 0
        && webdav_digest_scan(r, h, alg, exp_hex, exp_sz, &kind))
    {
        return kind;
    }

    h = brix_http_find_header(r, "Content-MD5", sizeof("Content-MD5") - 1);
    if (h != NULL && h->value.len > 0) {
        if (webdav_digest_value_hex(r, h->value.data, h->value.len, 1,
                exp_hex, exp_sz) != NGX_OK)
        {
            return WEBDAV_DIGEST_BAD;
        }
        *alg = "md5";
        return WEBDAV_DIGEST_FOUND;
    }

    return WEBDAV_DIGEST_NONE;
}

/*
 * webdav_put_verify_ingest_digest — verify a client-asserted body digest over
 * the fully-staged bytes, BEFORE the commit publishes them.
 *
 * A PUT may carry an end-to-end digest the client computed over what it sent
 * (RFC-3230 `Digest:` — the WLCG/XrdHttp convention — or legacy `Content-MD5:`).
 * The writer otherwise streams and commits whatever lands, so a byte flipped in
 * flight past the TCP checksum is stored silently.  When a usable digest is
 * present we recompute it over the staged temp fd and refuse the commit (400) on
 * mismatch — the client told us what it sent, so we can and must check it.  With
 * brix_webdav_require_digest on, a PUT that carries no usable digest is also
 * refused, for deployments that decline writes they cannot verify.
 *
 * Returns NGX_OK to proceed to commit, or an HTTP status (>=400) to reject.
 *
 * Scope: the staged POSIX temp fd (brix_vfs_writer_fd).  Coded bodies
 * (Content-Encoding) are skipped — the stored plaintext would not match a digest
 * over the encoded stream, matching the verify-on-write contract.  A driver
 * object target (S3) exposes no fd here and is verified on its own ingest path.
 * The recompute is synchronous on the event thread (like §8.3 checksum-on-write);
 * it only runs when a digest is asserted or required.
 */
ngx_int_t
webdav_put_verify_ingest_digest(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, brix_vfs_writer_t *writer,
    const char *path)
{
    char                    exp_hex[129];
    const char             *alg = NULL;
    webdav_digest_kind_t    kind;
    ngx_fd_t                fd;
    ngx_table_elt_t        *ce;
    brix_integrity_info_t   info;
    brix_integrity_opts_t   o;

    /* A coded body is stored decoded; a digest over the encoded stream cannot be
     * checked against it — skip (same limitation as verify-on-write). */
    ce = brix_http_find_header(r, "Content-Encoding", sizeof("Content-Encoding") - 1);
    if (ce != NULL && ce->value.len > 0) {
        return NGX_OK;
    }

    kind = webdav_digest_select(r, &alg, exp_hex, sizeof(exp_hex));
    if (kind == WEBDAV_DIGEST_BAD) {
        return NGX_HTTP_BAD_REQUEST;                 /* known alg, bad value */
    }
    if (kind == WEBDAV_DIGEST_NONE) {
        return conf->require_digest ? NGX_HTTP_BAD_REQUEST : NGX_OK;
    }

    fd = brix_vfs_writer_fd(writer);
    if (fd == NGX_INVALID_FILE) {
        /* Driver-backed object target — no local fd to hash here. */
        return conf->require_digest ? NGX_HTTP_BAD_REQUEST : NGX_OK;
    }

    ngx_memzero(&o, sizeof(o));
    o.require_regular_file = 1;   /* hash the staged bytes fresh (no xattr cache) */
    {
        char    procpath[32];
        ngx_int_t irc;
        int     rfd;

        /* The staged temp is opened write-only (staged_open_posix, O_WRONLY), and
         * has no final path yet (pre-commit), so it cannot be pread directly nor
         * reopened by name.  Re-open the same open file description read-only via
         * /proc/self/fd/<fd> — valid on Linux for an unlinked/O_TMPFILE staged
         * temp — and hash the already-written bytes over the read handle. */
        (void) ngx_snprintf((u_char *) procpath, sizeof(procpath),
                            "/proc/self/fd/%d%Z", (int) fd);
        rfd = open(procpath, O_RDONLY | O_CLOEXEC);  /* vfs-seam-allow: read-back of staged PUT bytes for pre-commit ingest-digest verify (no final path yet) */
        if (rfd < 0) {
            /* Cannot obtain a readable view of what we must verify: fail closed. */
            return NGX_HTTP_BAD_REQUEST;
        }
        irc = brix_integrity_get_fd(r->connection->log, rfd, NULL, path,
                                    alg, &o, &info);
        (void) close(rfd);
        if (irc != NGX_OK) {
            /* Cannot compute the digest we were asked to verify: fail closed. */
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    if (!webdav_hex_norm_equal(exp_hex, info.hex)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "brix_webdav: PUT ingest %s digest mismatch (asserted=%s got=%s)",
            alg, exp_hex, info.hex);
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, 0,
            "brix_webdav: ingest digest mismatch rejects PUT for: \"%s\"", path);
        return NGX_HTTP_BAD_REQUEST;
    }
    return NGX_OK;
}

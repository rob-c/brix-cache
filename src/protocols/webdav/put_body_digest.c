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
#include "core/compat/digest_header.h"   /* the shared RFC-3230 Digest grammar */
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

/* Pick the first supported digest from Digest: (RFC 3230) then Content-MD5:. On
 * BRIX_DIGEST_FOUND, *alg points at a static alg name and exp_hex holds the
 * client-asserted value as lowercase hex. Unsupported Digest tokens are skipped
 * (best-effort interop), so a Digest that names only algs we cannot compute reads
 * as NONE — require_digest then decides whether that is acceptable.
 *
 * The grammar itself (token table, base64-vs-hex encoding per algorithm, the
 * comma-separated scan) lives in core/compat/digest_header.c, shared with the
 * outbound direction — the sd_http checksum-offload slot parses the SAME header
 * off an origin's reply, and a client and an origin must not be understood by
 * two different parsers. */
static brix_digest_kind_t
webdav_digest_select(ngx_http_request_t *r, const char **alg,
    char *exp_hex, size_t exp_sz)
{
    ngx_table_elt_t    *h;
    brix_digest_kind_t  kind;

    h = brix_http_find_header(r, "Digest", sizeof("Digest") - 1);
    if (h != NULL && h->value.len > 0) {
        kind = brix_digest_header_scan(h->value.data, h->value.len, NULL,
                                       alg, exp_hex, exp_sz);
        if (kind != BRIX_DIGEST_NONE) {
            return kind;
        }
    }

    h = brix_http_find_header(r, "Content-MD5", sizeof("Content-MD5") - 1);
    if (h != NULL && h->value.len > 0) {
        if (brix_digest_value_hex(h->value.data, h->value.len, 1,
                exp_hex, exp_sz) != NGX_OK)
        {
            return BRIX_DIGEST_BAD;
        }
        *alg = "md5";
        return BRIX_DIGEST_FOUND;
    }

    return BRIX_DIGEST_NONE;
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
    brix_digest_kind_t      kind;
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
    if (kind == BRIX_DIGEST_BAD) {
        return NGX_HTTP_BAD_REQUEST;                 /* known alg, bad value */
    }
    if (kind == BRIX_DIGEST_NONE) {
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

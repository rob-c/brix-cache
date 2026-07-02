/*
 * verify.c — checksum-on-fill integrity (see verify.h for the design contract).
 *
 * Transport-agnostic: it is handed the origin's advertised digest (from a
 * kXR_Qcksum reply, an HTTP Digest header, or a Pelican namespace record) and a
 * staged ".part" file, and decides commit-or-discard under the configured
 * policy.  All work runs in a fill thread-pool worker (blocking pread of the
 * part file); no event-loop calls.
 */

#include "verify.h"

#include "core/compat/checksum.h"
#include "protocols/cvmfs/classify.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>


/* xrootd_cache_hex_ieq — case-insensitive equality of two hex digests * Origins vary in hex case (XRootD lowercases; some HTTP Digest headers upper).
 * Returns 1 when equal ignoring case, 0 otherwise. Lengths must match too. */
static int
xrootd_cache_hex_ieq(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);

    if (la != lb) {
        return 0;
    }
    return strncasecmp(a, b, la) == 0;
}


xrootd_cache_verify_result_e
xrootd_cache_verify_part(xrootd_cache_fill_t *t, const char *part_path,
    const xrootd_cache_digest_t *origin, xrootd_cache_verify_mode_e mode,
    char *out_alg, char *out_hex)
{
    ngx_log_t  *log = (t->c != NULL) ? t->c->log : NULL;
    char        hex[129];
    char        norm[32];
    ngx_int_t   rc;
    int         fd;

    if (mode == XROOTD_CACHE_VERIFY_OFF) {
        return XROOTD_CACHE_VERIFY_UNVERIFIED;
    }

    /* No origin digest available. */
    if (origin == NULL || origin->alg[0] == '\0' || origin->hex[0] == '\0') {
        if (mode == XROOTD_CACHE_VERIFY_REQUIRE) {
            xrootd_cache_set_error(t, kXR_ChkSumErr, 0,
                "cache verify: origin provided no checksum (require mode)");
            return XROOTD_CACHE_VERIFY_ERROR;
        }
        return XROOTD_CACHE_VERIFY_UNVERIFIED;
    }

    fd = open(part_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        xrootd_cache_set_syserror(t, kXR_IOError,
            "cache verify: part file open failed");
        return XROOTD_CACHE_VERIFY_ERROR;
    }

    /* Compute the SAME algorithm the origin advertised over the staged bytes. */
    rc = xrootd_checksum_hex_name_fd(origin->alg, fd, part_path, log,
                                     hex, sizeof(hex), norm, sizeof(norm));
    close(fd);

    if (rc == NGX_DECLINED) {
        /* We do not implement the origin's algorithm — cannot verify. */
        if (mode == XROOTD_CACHE_VERIFY_REQUIRE) {
            char msg[96];
            (void) snprintf(msg, sizeof(msg),
                "cache verify: unsupported origin checksum algorithm \"%.15s\"",
                origin->alg);
            xrootd_cache_set_error(t, kXR_ChkSumErr, 0, msg);
            return XROOTD_CACHE_VERIFY_ERROR;
        }
        if (log != NULL) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                "xrootd: cache verify: origin checksum \"%s\" not supported "
                "locally; committing \"%s\" unverified",
                origin->alg, part_path);
        }
        return XROOTD_CACHE_VERIFY_UNVERIFIED;
    }

    if (rc != NGX_OK) {
        xrootd_cache_set_syserror(t, kXR_IOError,
            "cache verify: local checksum computation failed");
        return XROOTD_CACHE_VERIFY_ERROR;
    }

    if (!xrootd_cache_hex_ieq(hex, origin->hex)) {
        char msg[256];
        (void) snprintf(msg, sizeof(msg),
            "cache verify: %s mismatch (origin=%.64s computed=%.64s)",
            norm[0] ? norm : origin->alg, origin->hex, hex);
        xrootd_cache_set_error(t, kXR_ChkSumErr, 0, msg);
        if (log != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "xrootd: cache verify FAILED for \"%s\": %s — discarding fill",
                part_path, msg);
        }
        return XROOTD_CACHE_VERIFY_MISMATCH;
    }

    if (out_alg != NULL) {
        const char *a = norm[0] ? norm : origin->alg;
        size_t      n = ngx_min(strlen(a), 15u);
        ngx_memcpy(out_alg, a, n);
        out_alg[n] = '\0';
    }
    if (out_hex != NULL) {
        size_t n = ngx_min(strlen(hex), 128u);
        ngx_memcpy(out_hex, hex, n);
        out_hex[n] = '\0';
    }
    return XROOTD_CACHE_VERIFY_VERIFIED;
}


/* Phase-68 CVMFS-CAS self-verification — see verify.h. The expected digest is
 * the CAS hex embedded in the key itself (raw served bytes = sha1(name)). */
xrootd_cache_verify_result_e
xrootd_cache_verify_cvmfs_cas(const char *part_path, const char *key,
    ngx_log_t *log, char *out_alg, char *out_hex)
{
    cvmfs_url_info_t  info;
    char              hex[129];
    char              norm[32];
    ngx_int_t         rc;
    int               fd;

    if (cvmfs_classify_url(key, strlen(key), &info) != 0
        || info.cls != CVMFS_URL_CAS)
    {
        return XROOTD_CACHE_VERIFY_UNVERIFIED;   /* not content-addressed */
    }
    if (info.cas_hex_len != 40) {
        /* Only the sha1 (40-hex) convention is verifiable today; longer
         * hashes would need the repo's hash-algorithm advertisement. */
        return XROOTD_CACHE_VERIFY_UNVERIFIED;
    }

    fd = open(part_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY); /* vfs-seam-allow: cache-store staging file, svc-owned domain */
    if (fd < 0) {
        return XROOTD_CACHE_VERIFY_ERROR;
    }
    rc = xrootd_checksum_hex_name_fd("sha1", fd, part_path, log,
                                     hex, sizeof(hex), norm, sizeof(norm));
    close(fd); /* vfs-seam-allow: cache-store staging file, svc-owned domain */
    if (rc != NGX_OK) {
        return XROOTD_CACHE_VERIFY_ERROR;
    }

    if (!xrootd_cache_hex_ieq(hex, info.cas_hex)) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "xrootd: cvmfs-cas verify FAILED for \"%s\" "
                "(name=%.40s computed=%.40s)\n"
                "  cause: origin transfer failed CAS verification — network "
                "corruption between cache and Stratum-1\n"
                "  fix:   check WAN path / middleboxes; object was "
                "quarantined, client will retry",
                key, info.cas_hex, hex);
        }
        return XROOTD_CACHE_VERIFY_MISMATCH;
    }

    if (out_alg != NULL) {
        ngx_memcpy(out_alg, "sha1", sizeof("sha1"));
    }
    if (out_hex != NULL) {
        ngx_memcpy(out_hex, hex, 41);
    }
    return XROOTD_CACHE_VERIFY_VERIFIED;
}

/* Quarantine (or drop) a failed part — see verify.h. */
void
xrootd_cache_quarantine_part(const char *part_path,
    const char *quarantine_dir, ngx_log_t *log)
{
    char        dst[PATH_MAX];
    const char *base;
    int         n;

    if (quarantine_dir == NULL || quarantine_dir[0] == '\0') {
        unlink(part_path); /* vfs-seam-allow: cache-store staging file, svc-owned domain */
        return;
    }
    base = strrchr(part_path, '/');
    base = (base != NULL) ? base + 1 : part_path;
    n = snprintf(dst, sizeof(dst), "%s/%s.%ld", quarantine_dir, base,
                 (long) time(NULL));
    if (n < 0 || (size_t) n >= sizeof(dst)
        || rename(part_path, dst) != 0) /* vfs-seam-allow: cache-store staging file, svc-owned domain */
    {
        unlink(part_path); /* vfs-seam-allow: cache-store staging file, svc-owned domain */
        return;
    }
    if (log != NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: cvmfs-cas: corrupt fill quarantined at \"%s\"", dst);
    }
}

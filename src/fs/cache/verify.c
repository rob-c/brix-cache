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


/* brix_cache_hex_ieq — case-insensitive equality of two hex digests * Origins vary in hex case (XRootD lowercases; some HTTP Digest headers upper).
 * Returns 1 when equal ignoring case, 0 otherwise. Lengths must match too. */
static int
brix_cache_hex_ieq(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);

    if (la != lb) {
        return 0;
    }
    return strncasecmp(a, b, la) == 0;
}


/* brix_cache_verify_no_origin — policy verdict when the origin gave no digest.
 *
 * WHAT: Returns BRIX_CACHE_VERIFY_ERROR (after recording a kXR_ChkSumErr on t)
 * under REQUIRE mode, otherwise BRIX_CACHE_VERIFY_UNVERIFIED. Security-neutral:
 * no bytes are hashed here — this is the "nothing to compare against" branch.
 *
 * WHY: Isolates the missing-origin-digest policy fork so the orchestrator stays
 * a flat sequence; the REQUIRE-vs-permissive decision lives in one place.
 *
 * HOW:
 *   1. REQUIRE mode → set the error on t and return ERROR.
 *   2. Any other mode → return UNVERIFIED (commit without a checksum).
 */
static brix_cache_verify_result_e
brix_cache_verify_no_origin(brix_cache_fill_t *t, brix_cache_verify_mode_e mode)
{
    if (mode == BRIX_CACHE_VERIFY_REQUIRE) {
        brix_cache_set_error(t, kXR_ChkSumErr, 0,
            "cache verify: origin provided no checksum (require mode)");
        return BRIX_CACHE_VERIFY_ERROR;
    }
    return BRIX_CACHE_VERIFY_UNVERIFIED;
}


/* brix_cache_verify_unsupported — policy verdict for an unimplemented algorithm.
 *
 * WHAT: Called when brix_checksum_hex_name_fd returned NGX_DECLINED (we do not
 * implement the origin's algorithm). Returns BRIX_CACHE_VERIFY_ERROR (recording
 * a kXR_ChkSumErr) under REQUIRE mode, else logs an INFO note and returns
 * BRIX_CACHE_VERIFY_UNVERIFIED. No comparison is performed — verification was
 * impossible, never bypassed.
 *
 * WHY: Keeps the "cannot verify this algorithm" fork out of the orchestrator so
 * its control flow (and thus its complexity) is dominated by the real verify path.
 *
 * HOW:
 *   1. REQUIRE mode → format the unsupported-algorithm message, set it on t,
 *      return ERROR.
 *   2. Otherwise → if a log is present, emit the "committing unverified" INFO
 *      line, then return UNVERIFIED.
 */
static brix_cache_verify_result_e
brix_cache_verify_unsupported(brix_cache_fill_t *t,
    const brix_cache_digest_t *origin, brix_cache_verify_mode_e mode,
    ngx_log_t *log, const char *part_path)
{
    if (mode == BRIX_CACHE_VERIFY_REQUIRE) {
        char msg[96];
        (void) snprintf(msg, sizeof(msg),
            "cache verify: unsupported origin checksum algorithm \"%.15s\"",
            origin->alg);
        brix_cache_set_error(t, kXR_ChkSumErr, 0, msg);
        return BRIX_CACHE_VERIFY_ERROR;
    }
    if (log != NULL) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
            "brix: cache verify: origin checksum \"%s\" not supported "
            "locally; committing \"%s\" unverified",
            origin->alg, part_path);
    }
    return BRIX_CACHE_VERIFY_UNVERIFIED;
}


/* brix_cache_verify_report_mismatch — record and log a digest mismatch.
 *
 * WHAT: Formats the "<alg> mismatch (origin=… computed=…)" message, sets it as
 * a kXR_ChkSumErr on t, and (when a log is present) emits the ERR "discarding
 * fill" line. Side-effect only; the caller returns BRIX_CACHE_VERIFY_MISMATCH.
 *
 * WHY: The mismatch branch is the security-critical failure path; concentrating
 * its exact error text and logging here keeps that wording byte-for-byte stable
 * and out of the orchestrator's branch budget.
 *
 * HOW:
 *   1. snprintf the mismatch detail using alg_used (already resolved to the
 *      normalized name or the origin's advertised name) and both digests.
 *   2. brix_cache_set_error on t with kXR_ChkSumErr.
 *   3. If log is non-NULL, log the failure at ERR level.
 */
static void
brix_cache_verify_report_mismatch(brix_cache_fill_t *t, ngx_log_t *log,
    const char *part_path, const char *alg_used,
    const brix_cache_digest_t *origin, const char *hex)
{
    char msg[256];

    (void) snprintf(msg, sizeof(msg),
        "cache verify: %s mismatch (origin=%.64s computed=%.64s)",
        alg_used, origin->hex, hex);
    brix_cache_set_error(t, kXR_ChkSumErr, 0, msg);
    if (log != NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix: cache verify FAILED for \"%s\": %s — discarding fill",
            part_path, msg);
    }
}


/* brix_cache_verify_emit — copy the verified algorithm and digest to outputs.
 *
 * WHAT: When out_alg / out_hex are non-NULL, writes the truncated, NUL-terminated
 * algorithm name (<=15 chars) and hex digest (<=128 chars) into them. No-op for
 * any output pointer that is NULL.
 *
 * WHY: Only reached on the verified-match path; extracting it keeps the two
 * optional-output branches out of the orchestrator and mirrors the exact
 * truncation limits the callers of brix_cache_verify_part rely on.
 *
 * HOW:
 *   1. If out_alg is set, memcpy min(strlen(alg_used),15) bytes and NUL-terminate.
 *   2. If out_hex is set, memcpy min(strlen(hex),128) bytes and NUL-terminate.
 */
static void
brix_cache_verify_emit(char *out_alg, char *out_hex, const char *alg_used,
    const char *hex)
{
    if (out_alg != NULL) {
        size_t n = ngx_min(strlen(alg_used), 15u);
        ngx_memcpy(out_alg, alg_used, n);
        out_alg[n] = '\0';
    }
    if (out_hex != NULL) {
        size_t n = ngx_min(strlen(hex), 128u);
        ngx_memcpy(out_hex, hex, n);
        out_hex[n] = '\0';
    }
}


brix_cache_verify_result_e
brix_cache_verify_part(brix_cache_fill_t *t, const char *part_path,
    const brix_cache_digest_t *origin, brix_cache_verify_mode_e mode,
    char *out_alg, char *out_hex)
{
    ngx_log_t   *log = (t->c != NULL) ? t->c->log : NULL;
    const char  *alg_used;
    char         hex[129];
    char         norm[32];
    ngx_int_t    rc;
    int          fd;

    if (mode == BRIX_CACHE_VERIFY_OFF) {
        return BRIX_CACHE_VERIFY_UNVERIFIED;
    }

    /* No origin digest available. */
    if (origin == NULL || origin->alg[0] == '\0' || origin->hex[0] == '\0') {
        return brix_cache_verify_no_origin(t, mode);
    }

    fd = open(part_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        brix_cache_set_syserror(t, kXR_IOError,
            "cache verify: part file open failed");
        return BRIX_CACHE_VERIFY_ERROR;
    }

    /* Compute the SAME algorithm the origin advertised over the staged bytes. */
    rc = brix_checksum_hex_name_fd(origin->alg, fd, part_path, log,
                                     hex, sizeof(hex), norm, sizeof(norm));
    close(fd);

    if (rc == NGX_DECLINED) {
        /* We do not implement the origin's algorithm — cannot verify. */
        return brix_cache_verify_unsupported(t, origin, mode, log, part_path);
    }

    if (rc != NGX_OK) {
        brix_cache_set_syserror(t, kXR_IOError,
            "cache verify: local checksum computation failed");
        return BRIX_CACHE_VERIFY_ERROR;
    }

    alg_used = norm[0] ? norm : origin->alg;

    if (!brix_cache_hex_ieq(hex, origin->hex)) {
        brix_cache_verify_report_mismatch(t, log, part_path, alg_used,
            origin, hex);
        return BRIX_CACHE_VERIFY_MISMATCH;
    }

    brix_cache_verify_emit(out_alg, out_hex, alg_used, hex);
    return BRIX_CACHE_VERIFY_VERIFIED;
}


/* Phase-68 CVMFS-CAS self-verification — see verify.h. The expected digest is
 * the CAS hex embedded in the key itself (raw served bytes = sha1(name)). */
brix_cache_verify_result_e
brix_cache_verify_cvmfs_cas(const char *part_path, const char *key,
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
        return BRIX_CACHE_VERIFY_UNVERIFIED;   /* not content-addressed */
    }
    if (info.cas_hex_len != 40) {
        /* Only the sha1 (40-hex) convention is verifiable today; longer
         * hashes would need the repo's hash-algorithm advertisement. */
        return BRIX_CACHE_VERIFY_UNVERIFIED;
    }

    fd = open(part_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY); /* vfs-seam-allow: cache-store staging file, svc-owned domain */
    if (fd < 0) {
        return BRIX_CACHE_VERIFY_ERROR;
    }
    rc = brix_checksum_hex_name_fd("sha1", fd, part_path, log,
                                     hex, sizeof(hex), norm, sizeof(norm));
    close(fd); /* vfs-seam-allow: cache-store staging file, svc-owned domain */
    if (rc != NGX_OK) {
        return BRIX_CACHE_VERIFY_ERROR;
    }

    if (!brix_cache_hex_ieq(hex, info.cas_hex)) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "brix: cvmfs-cas verify FAILED for \"%s\" "
                "(name=%.40s computed=%.40s)\n"
                "  cause: origin transfer failed CAS verification — network "
                "corruption between cache and Stratum-1\n"
                "  fix:   check WAN path / middleboxes; object was "
                "quarantined, client will retry",
                key, info.cas_hex, hex);
        }
        return BRIX_CACHE_VERIFY_MISMATCH;
    }

    if (out_alg != NULL) {
        ngx_memcpy(out_alg, "sha1", sizeof("sha1"));
    }
    if (out_hex != NULL) {
        ngx_memcpy(out_hex, hex, 41);
    }
    return BRIX_CACHE_VERIFY_VERIFIED;
}

/* Quarantine (or drop) a failed part — see verify.h. */
void
brix_cache_quarantine_part(const char *part_path,
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
            "brix: cvmfs-cas: corrupt fill quarantined at \"%s\"", dst);
    }
}

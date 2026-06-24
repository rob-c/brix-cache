/*
 * tmp_path.c — uniform temporary-file path construction for all subsystems.
 *
 * All three subsystems that write data atomically (WebDAV COPY, WebDAV TPC
 * pull, S3 PUT) previously used ad-hoc suffix formats.  Centralising the
 * format means:
 *
 *   - operators can clean orphaned temp files with a single glob:
 *       find /export -name "*.xrd-tmp.*" -mtime +1 -delete
 *   - the uniqueness strategy (pid + ngx_random()) is consistent everywhere
 *   - a future "scan for stale tmps" monitor only needs one pattern
 */

#include "tmp_path.h"
#include "crypto.h"
#include "hex.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * WHAT: Construct a unique temporary file path based on a base (final) path.
 *
 * WHY: Atomic writes need a temp file that won't collide with existing files or concurrent
 *      writers. The format <base>.xrd-tmp.<pid>.<random> guarantees uniqueness across processes
 *      and retries, while the .xrd-tmp. prefix lets operators glob-clean orphaned temps.
 *
 * HOW: snprintf combines base_path + ".xrd-tmp." + getpid() + ngx_random(). Returns NGX_OK
 *      on success, NGX_ERROR if truncation occurs (n >= out_sz or n < 0). Caller uses this
 *      path with O_EXCL open to guarantee no collision.
 *
 * Parameters:
 *   base_path — the final destination path (used as prefix for temp name)
 *   out — output buffer to receive the constructed tmp path
 *   out_sz — size of out buffer
 */
ngx_int_t
xrootd_make_tmp_path(const char *base_path, char *out, size_t out_sz)
{
    int n;

    n = snprintf(out, out_sz, "%s.xrd-tmp.%ld.%u",
                 base_path, (long) getpid(), (unsigned) ngx_random());
    if (n < 0 || (size_t) n >= out_sz) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Construct the DETERMINISTIC resume-staging path for an upload, keyed to
 *       the authenticated principal AND the final path.
 *
 * WHY:  Upload resume across an nginx restart needs a reconnecting client's
 *       re-open of the same final path (by the same identity) to land on the
 *       SAME staging file so the already-written bytes survive and the transfer
 *       continues from its offset.  A random per-open temp (xrootd_make_tmp_path)
 *       cannot satisfy that — the second open would never find the first temp.
 *       Hashing the principal into the name also isolates users: a different
 *       identity derives a different staging file and can never reclaim another's
 *       partial (and the server only ever derives the name from the AUTHENTICATED
 *       identity, never from client-supplied data).
 *
 * HOW:  out = "<base>.xrdresume.<hex16(SHA-256(principal "\0" base))>.part".
 *       The base prefix keeps the staging file adjacent to the destination so the
 *       commit rename(2) stays same-filesystem/atomic; the 16-byte (128-bit) hash
 *       prefix makes cross-(identity,path) collisions negligible.  The
 *       ".xrdresume." infix lets operators glob-clean stale partials:
 *           find /export -name "*.xrdresume.*.part" -mtime +1 -delete
 *
 * Parameters:
 *   base_path — final destination absolute path
 *   principal — authenticated identity (DN / token subject); "" or NULL for an
 *               anonymous endpoint (all anonymous uploads to a path then share,
 *               consistent with that endpoint having no per-user isolation)
 *   out/out_sz — output buffer
 *
 * Returns NGX_OK, or NGX_ERROR on hash failure or truncation.
 */
ngx_int_t
xrootd_make_resume_path(const char *base_path, const char *principal,
                        const char *stage_dir, char *out, size_t out_sz)
{
    uint8_t  digest[32];
    char     hexbuf[33];
    u_char   concat[768 + PATH_MAX];
    size_t   wlen, blen, clen;
    int      n;
    const char *who = (principal != NULL && principal[0] != '\0')
                      ? principal : "anonymous";

    /* Hash principal || '\0' || base_path (the NUL keeps the two fields
     * unambiguous so distinct (who, base) pairs cannot alias). */
    wlen = strnlen(who, 767);
    blen = strnlen(base_path, PATH_MAX - 1);
    clen = 0;
    ngx_memcpy(concat, who, wlen);            clen += wlen;
    concat[clen++] = '\0';
    ngx_memcpy(concat + clen, base_path, blen); clen += blen;

    /* xrootd_sha256 follows the OpenSSL convention: 1 = success, 0 = failure. */
    if (xrootd_sha256(concat, clen, digest) != 1) {
        return NGX_ERROR;
    }

    xrootd_hex_encode(digest, 16, hexbuf);   /* 16 bytes -> 32 hex chars + NUL */

    if (stage_dir != NULL && stage_dir[0] != '\0') {
        /* Stage on the configured fast device.  The basename is the
         * server-generated hash (no client-controlled component), so the flat
         * stage dir holds every in-progress upload without collision and the
         * commit later moves it onto the storage. */
        n = snprintf(out, out_sz, "%s/%s.xrdresume.part", stage_dir, hexbuf);
    } else {
        /* Stage adjacent to the destination (same filesystem → atomic rename). */
        n = snprintf(out, out_sz, "%s.xrdresume.%s.part", base_path, hexbuf);
    }
    if (n < 0 || (size_t) n >= out_sz) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

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

#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
brix_make_tmp_path(const char *base_path, char *out, size_t out_sz)
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
 * brix_tmp_is_temp_name — does this directory-entry name belong to a staged
 * atomic-write temp ("<base>.xrd-tmp.<pid>.<random>")? Enumerators that walk a
 * store tree (the OCI tag/referrers listers) call this to skip a crash-orphaned
 * temp so it is never surfaced as an object in the window before worker-0's
 * brix_tmp_reap_all() removes it. The marker is the same infix the writer and
 * the reaper agree on, kept in one place here.
 */
int
brix_tmp_is_temp_name(const char *name)
{
    return name != NULL && strstr(name, ".xrd-tmp.") != NULL;
}

/*
 * WHAT: Construct the DETERMINISTIC resume-staging path for an upload, keyed to
 *       the authenticated principal AND the final path.
 *
 * WHY:  Upload resume across an nginx restart needs a reconnecting client's
 *       re-open of the same final path (by the same identity) to land on the
 *       SAME staging file so the already-written bytes survive and the transfer
 *       continues from its offset.  A random per-open temp (brix_make_tmp_path)
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
brix_make_resume_path(const char *base_path, const char *principal,
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

    /* brix_sha256 follows the OpenSSL convention: 1 = success, 0 = failure. */
    if (brix_sha256(concat, clen, digest) != 1) {
        return NGX_ERROR;
    }

    brix_hex_encode(digest, 16, hexbuf);   /* 16 bytes -> 32 hex chars + NUL */

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

/* ---- orphaned atomic-write temp reaper (phase-64 SP4) ---------------------
 * A non-staged (direct) write streams the body to a "<final>.xrd-tmp.<pid>.<rand>"
 * temp and renames it onto the final path on commit. A crash/kill mid-write leaves
 * that temp orphaned in the export tree. Unlike a STAGED write (recoverable via the
 * stage_engine reconcile), a broken direct write is simply discarded - so on
 * startup we REAP these orphans. The owning pid is in the name: a temp whose pid is
 * still alive is an IN-FLIGHT write of a draining worker (a reload) and is KEPT;
 * only dead-owner (or malformed) temps are removed - safe under reload. */

#define BRIX_TMP_REAP_MAX  64
static char       s_tmp_reap_roots[BRIX_TMP_REAP_MAX][PATH_MAX];
static ngx_uint_t s_tmp_reap_count;
static ngx_uint_t s_tmp_reaped;   /* nftw has no ctx; worker-0 startup is single-threaded */

/* ofs.persist policy (§1.9). AUTO/0 = historical behaviour. The nftw callback
 * has no context arg, and worker-0 startup is single-threaded, so the mode, the
 * hold seconds, and the walk's captured "now" ride file-static state — set once
 * by brix_tmp_reap_set_policy() at config time and by brix_tmp_reap_all() at the
 * top of the walk. */
static int    s_tmp_reap_mode = BRIX_POSC_PERSIST_AUTO;
static time_t s_tmp_reap_hold;    /* grace seconds; 0 = reap immediately */
static time_t s_tmp_reap_now;     /* walk start time, for the hold-age gate */

void
brix_tmp_reap_set_policy(int mode, time_t hold_sec)
{
    if (mode != BRIX_POSC_PERSIST_AUTO
        && mode != BRIX_POSC_PERSIST_MANUAL
        && mode != BRIX_POSC_PERSIST_OFF)
    {
        return;                                 /* ignore an out-of-range mode */
    }
    s_tmp_reap_mode = mode;
    s_tmp_reap_hold = hold_sec > 0 ? hold_sec : 0;
}

void
brix_tmp_reap_register(const char *export_root)
{
    ngx_uint_t i;

    if (export_root == NULL || export_root[0] == '\0'
        || strlen(export_root) >= PATH_MAX)
    {
        return;
    }
    /* Never reap "/" — a cache node anchored at the root namespace (no brix_root)
     * yields root_canon "/", but nftw-walking the whole host filesystem (and
     * unlinking matching temps anywhere) is catastrophic. A pure cache node has no
     * local export-tree temps to reap (its in-flight writes live in the store
     * tier), so there is nothing to walk here. */
    if (export_root[0] == '/' && export_root[1] == '\0') {
        return;
    }
    for (i = 0; i < s_tmp_reap_count; i++) {
        if (strcmp(s_tmp_reap_roots[i], export_root) == 0) {
            return;                             /* dedup across server blocks */
        }
    }
    if (s_tmp_reap_count >= BRIX_TMP_REAP_MAX) {
        return;
    }
    memcpy(s_tmp_reap_roots[s_tmp_reap_count], export_root,
           strlen(export_root) + 1);
    s_tmp_reap_count++;
}

/* nftw visitor: unlink a "*.xrd-tmp.<pid>.*" file whose owner pid is dead. */
static int
brix_tmp_reap_cb(const char *fpath, const struct stat *sb, int typeflag,
    struct FTW *ftwbuf)
{
    const char *base;
    const char *mark;
    long        pid;
    char       *end;

    (void) ftwbuf;
    if (typeflag != FTW_F) {
        return 0;
    }
    base = strrchr(fpath, '/');
    base = (base != NULL) ? base + 1 : fpath;
    mark = strstr(base, ".xrd-tmp.");
    if (mark == NULL) {
        return 0;
    }
    pid = strtol(mark + sizeof(".xrd-tmp.") - 1, &end, 10);
    if (pid > 0 && end != mark + sizeof(".xrd-tmp.") - 1) {
        /* A live owner = an in-flight write (a draining worker during reload). A
         * dead owner (ESRCH) = an orphan. EPERM (foreign owner) = keep, be safe. */
        if (kill((pid_t) pid, 0) == 0 || errno == EPERM) {
            return 0;
        }
    }
    /* ofs.persist hold (§1.9): under a grace period a dead-owner orphan is kept
     * until it has been idle at least s_tmp_reap_hold seconds, so a temp whose
     * writer is about to reconnect-and-resume is not reaped mid-recovery. A temp
     * with a future mtime (clock skew) is treated as fresh — kept, never reaped. */
    if (s_tmp_reap_hold > 0
        && (s_tmp_reap_now < sb->st_mtime
            || s_tmp_reap_now - sb->st_mtime < s_tmp_reap_hold))
    {
        return 0;
    }
    if (unlink(fpath) == 0) {
        s_tmp_reaped++;
    }
    return 0;
}

ngx_uint_t
brix_tmp_reap_all(ngx_log_t *log)
{
    ngx_uint_t i;

    /* ofs.persist manual/off (§1.9): leave every crash orphan in place for an
     * operator to inspect or recover — the reap is the ONLY thing this policy
     * disables (live-owner in-flight writes were always kept anyway). */
    if (s_tmp_reap_mode != BRIX_POSC_PERSIST_AUTO) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "brix: posc persist=%s — orphaned upload-temp reaping disabled; "
                "crash orphans are kept for manual recovery",
                s_tmp_reap_mode == BRIX_POSC_PERSIST_MANUAL ? "manual" : "off");
        }
        return 0;
    }

    s_tmp_reaped = 0;
    s_tmp_reap_now = time(NULL);            /* one clock read per walk (hold gate) */
    for (i = 0; i < s_tmp_reap_count; i++) {
        (void) nftw(s_tmp_reap_roots[i], brix_tmp_reap_cb, 16, FTW_PHYS);
    }
    if (s_tmp_reaped > 0 && log != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: reaped %ui orphaned upload temp(s) from interrupted "
            "non-staged write(s)", s_tmp_reaped);
    }
    return s_tmp_reaped;
}

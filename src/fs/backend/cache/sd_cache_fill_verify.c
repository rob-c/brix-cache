/*
 * sd_cache_fill_verify.c — the integrity-verify phase of the read-through cache
 *       fill spine.
 *
 * WHAT: Digest- and signature-verifies the staged bytes of a fill BEFORE the
 *       commit publishes them, and emits the guard-core tamper audit line +
 *       quarantine on a reject. Split from sd_cache_fill.c for the file-size
 *       cap; the acquire/pump/commit phases and the sd_cache_fill orchestrator
 *       stay there, the cold-tier demote copy lives in sd_cache_fill_demote.c.
 *
 * WHY:  Isolating the verify gate keeps the CAS / manifest-signature /
 *       origin-digest reject logic (and its tamper-signal + WAN-accounting
 *       side effects) reviewable apart from the byte-pump machinery.
 *
 * HOW:  cache_fill_verify (the phase entrypoint, non-static — driven by
 *       sd_cache_fill_attempt) dispatches to cvmfs-cas, the manifest signature
 *       chain (sd_cache_manifest.c), and the best-effort/require origin-digest
 *       compare. A reject quarantines the part, raises signal=cvmfs_tamper and
 *       fails the fill; the per-attempt state travels in sd_cache_fill_state_t
 *       (sd_cache_fill_internal.h).
 */
#include "sd_cache.h"
#include "sd_cache_internal.h"    /* sd_cache_inst_state + SD_CACHE_ST/SRC */
#include "sd_cache_policy.h"      /* admission + repo-metrics (split out) */
#include "sd_cache_fill_internal.h"     /* sd_cache_fill_state_t + SD_CACHE_CHUNK */
#include "protocols/cvmfs/classify.h"   /* phase-68 manifest-TTL stamping */
#include "observability/metrics/metrics.h"        /* phase-68 T16 counters */
#include "observability/metrics/metrics_macros.h"
#include "fs/cache/cstore.h"
#include "fs/backend/http/sd_http.h"    /* per-upstream fill attribution     */
#include "fs/backend/xroot/sd_xroot.h"  /* brix_sd_xroot_query_checksum      */
#include "fs/path/path.h"               /* brix_sanitize_log_string          */
#include "net/guard/guard.h"            /* signal=cvmfs_tamper audit line    */
#include "core/compat/checksum.h"       /* brix_checksum_hex_name_fd         */
#include "core/fnv.h"                    /* BRIX_FNV1A64_* hash constants     */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/* Emit the unified guard-core audit line (signal=cvmfs_tamper) for a fill
 * whose bytes failed CVMFS integrity verification — CAS hash or manifest/
 * whitelist signature mismatch.  The tamper actor is UPSTREAM — the origin, or
 * the mesh sibling a phase-85 F8 peer attempt filled from — never a client
 * (fills run detached in the thread pool, often coalesced across clients), so
 * `actor`'s last-answering authority rides the ip field (NULL = st->source)
 * and the failed object key rides the path.  Runs on a fill THREAD: the
 * timestamp is built with gmtime_r (never the event-loop's cached iso8601),
 * and ngx_log_error is the same call the surrounding fill code already makes
 * from this thread. */
void
sd_cache_guard_tamper(sd_cache_inst_state *st, brix_sd_instance_t *actor,
    const char *key)
{
    guard_request_t  req;
    char             origin[300];
    char             san_key[512];
    char             line[1024];
    char             ts[sizeof("YYYY-MM-DDThh:mm:ss+00:00")];
    time_t           now;
    struct tm        tmv;

    if (actor == NULL) {
        actor = st->source;
    }
    if (actor == NULL
        || ngx_strcmp(actor->driver->name, "http") != 0
        || sd_http_last_origin(actor, origin, sizeof(origin)) != 0)
    {
        ngx_cpystrn((u_char *) origin, (u_char *) "unknown-origin",
                    sizeof(origin));
    }

    req.ip           = origin;
    req.proto        = "cvmfs";
    req.op           = GUARD_OP_READ;
    req.path         = san_key;
    req.path_len     = brix_sanitize_log_string(key, san_key, sizeof(san_key));
    req.cred_present = 0;
    req.outcome      = OUTCOME_PENDING;
    req.status_code  = 502;      /* the gateway error the waiting client saw */

    now = time(NULL);
    if (gmtime_r(&now, &tmv) == NULL
        || strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S+00:00", &tmv) == 0)
    {
        ngx_cpystrn((u_char *) ts, (u_char *) "1970-01-01T00:00:00+00:00",
                    sizeof(ts));
    }

    if (guard_audit_format(&req, GUARD_R_TAMPER, ts, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0, "%s", line);
    }
}

/* Reject a staged fill whose bytes failed integrity verification: account the
 * wasted WAN cost + failure metrics, emit signal=cvmfs_tamper, quarantine the
 * part for evidence and abort the fill. Shared by the CAS digest mismatch and
 * the manifest signature-chain reject. Always returns NGX_ERROR with errno
 * EBADMSG (T20 budgets retries on it). */
static ngx_int_t
cache_fill_verify_reject(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs, const char *pp)
{
    ngx_brix_cvmfs_repo_metrics_t *rm = sd_cache_repo_metrics(st, key);

    BRIX_CVMFS_METRIC_INC(verify_failures_total);
    if (rm != NULL) {
        BRIX_ATOMIC_INC(&rm->verify_failures_total);
    }
    if (fs->from_cold) {
        /* The corrupt bytes came from the LOCAL cold store tier, not the
         * origin: no WAN accounting, no signal=cvmfs_tamper, no origin
         * penalty — a false tamper signal would feed the maxretry=1 fail2ban
         * jail over a local disk fault. Drop the corrupt cold copy so the
         * origin-fallback refill repopulates both tiers cleanly. */
        ngx_log_error(NGX_LOG_NOTICE, st->log, 0,
            "sd_cache: cold-tier object failed verification for \"%s\" - "
            "removing the cold copy and refilling from the origin", key);
        if (fs->src != NULL && fs->src->driver->unlink != NULL) {
            (void) fs->src->driver->unlink(fs->src, key, 0);
        }
    } else if (fs->from_peer) {
        /* The corrupt bytes came from a mesh SIBLING (phase-85 F8): that IS a
         * remote tamper actor, so raise signal=cvmfs_tamper naming the
         * sibling's authority — but no origin WAN accounting and no origin
         * penalty (the origin never served these bytes; the orchestrator
         * refetches from it next). */
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: mesh-sibling object failed verification for \"%s\" - "
            "refetching from the origin", key);
        sd_cache_guard_tamper(st, fs->src, key);
    } else {
        sd_cache_note_origin_bytes(st, key, fs->off); /* WAN cost is WAN cost */
        /* a verify mismatch IS an upstream fill failure — the bytes came
         * from the origin but did not publish. */
        sd_cache_note_upstream(st, 0, fs->off, sd_cache_ms_since(&fs->t0));
        sd_cache_guard_tamper(st, NULL, key);
        /* The origin that served these bytes is proven bad for this object —
         * bench it so the EBADMSG retry (T20 verify budget) rotates to a clean
         * endpoint instead of re-picking the same corrupt one (no-op for a
         * non-http source). */
        sd_http_penalize_last_origin(st->source);
    }
    brix_cache_quarantine_part(pp, st->policy.quarantine_dir, st->log);
    brix_cstore_fill_abort(fs->staged);       /* part already renamed away */
    errno = EBADMSG;            /* digest mismatch — T20 budgets retries */
    return NGX_ERROR;
}

/* Case-insensitive equality of two hex digests. Origins vary in hex case
 * (XRootD lowercases; some HTTP Digest headers upper-case), so a byte-exact
 * strcmp would false-mismatch identical digests. */
static int
sd_cache_hex_ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        if (ngx_tolower((u_char) *a) != ngx_tolower((u_char) *b)) {
            return 0;
        }
    }
    return *a == '\0' && *b == '\0';
}

/* Verify the staged bytes against the origin-advertised digest (best-effort /
 * require policy). Called only when a digest-verify mode is in force and the
 * CAS/manifest gates did not apply.
 *
 * The origin digest was captured in the pump (fs->origin_alg/hex); here we
 * digest the staged part with the SAME algorithm and compare.
 *
 *   - digest matches            -> fs->verified = 1, NGX_OK (commit)
 *   - digest MISMATCH           -> quarantine + tamper signal, NGX_ERROR
 *   - no origin digest / unknown algorithm:
 *         REQUIRE  -> fail closed (EIO) — an unverifiable object must not cache
 *         BEST-EFFORT -> NGX_OK (commit; nothing to check against)
 *
 * On every fail-closed path the staged fill is aborted so nothing publishes. */
static ngx_int_t
cache_fill_verify_origin(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs, const char *pp)
{
    int        require = (st->policy.verify == BRIX_CACHE_VERIFY_REQUIRE);
    char       hex[129];
    char       norm[32];
    ngx_int_t  rc;
    int        fd;

    if (fs->origin_alg[0] == '\0' || fs->origin_hex[0] == '\0') {
        if (require) {
            ngx_log_error(NGX_LOG_ERR, st->log, 0,
                "sd_cache: verify=require but the origin advertised no usable "
                "digest for \"%s\" - refusing to cache unverifiable bytes", key);
            brix_cstore_fill_abort(fs->staged);
            errno = EIO;
            return NGX_ERROR;
        }
        return NGX_OK;                 /* best-effort: nothing to verify against */
    }
    if (pp == NULL) {
        ngx_log_error(NGX_LOG_ERR, st->log, 0,
            "sd_cache: cannot locate the staged part to verify \"%s\" - "
            "failing the fill closed", key);
        brix_cstore_fill_abort(fs->staged);
        errno = EIO;
        return NGX_ERROR;
    }

    fd = open(pp, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, st->log, errno,
            "sd_cache: verify open of staged part failed for \"%s\"", key);
        brix_cstore_fill_abort(fs->staged);
        errno = EIO;
        return NGX_ERROR;
    }
    rc = brix_checksum_hex_name_fd(fs->origin_alg, fd, pp, st->log,
                                   hex, sizeof(hex), norm, sizeof(norm));
    close(fd);

    if (rc == NGX_DECLINED) {
        /* We do not implement the algorithm the origin advertised. */
        if (require) {
            ngx_log_error(NGX_LOG_ERR, st->log, 0,
                "sd_cache: verify=require but origin algorithm \"%s\" is "
                "unsupported for \"%s\" - failing closed", fs->origin_alg, key);
            brix_cstore_fill_abort(fs->staged);
            errno = EIO;
            return NGX_ERROR;
        }
        return NGX_OK;                 /* best-effort: cannot check, commit */
    }
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, st->log, errno,
            "sd_cache: verify checksum computation failed for \"%s\" - "
            "failing closed", key);
        brix_cstore_fill_abort(fs->staged);
        errno = EIO;
        return NGX_ERROR;
    }

    if (!sd_cache_hex_ieq(hex, fs->origin_hex)) {
        ngx_log_error(NGX_LOG_ERR, st->log, 0,
            "sd_cache: origin-digest MISMATCH for \"%s\" (%s: origin=%s local=%s)"
            " - quarantining and failing the fill", key,
            norm[0] ? norm : fs->origin_alg, fs->origin_hex, hex);
        return cache_fill_verify_reject(st, key, fs, pp);
    }

    fs->verified = 1;
    /* Persisted into the cinfo at commit: the digest we just computed and
     * matched (normalised name preferred over the origin's raw spelling). */
    ngx_cpystrn((u_char *) fs->cks_alg,
                (u_char *) (norm[0] != '\0' ? norm : fs->origin_alg),
                sizeof(fs->cks_alg));
    ngx_cpystrn((u_char *) fs->cks_hex, (u_char *) hex, sizeof(fs->cks_hex));
    return NGX_OK;
}

/* Digest- and signature-verify the staged bytes before the commit publishes
 * them.
 *
 * WHAT: phase-68 cvmfs-cas verification — the key names its own sha1, so the
 *       staged part can be checked with no origin digest — plus the phase-85
 *       F1 manifest/whitelist signature chain when brix_cvmfs_verify_manifest
 *       configured a master key.
 *
 * WHY:  A MISMATCH/signature reject is quarantined for evidence, flagged to
 *       the guard (signal=cvmfs_tamper) and the fill fails (the client sees a
 *       gateway error and retries); an ERROR fails closed with no tamper
 *       signal. CAS-unverifiable keys (manifests) get the signature gate
 *       instead; keys under neither gate commit as before.
 *
 * HOW:  No-op (NGX_OK) unless policy.verify is CVMFS_CAS or a master key is
 *       loaded. Sets fs->verified on a VERIFIED CAS result. On failure aborts
 *       the staged fill and returns NGX_ERROR with errno EBADMSG (mismatch —
 *       T20 budgets retries) or EIO (verify could not run). */
ngx_int_t
cache_fill_verify(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs)
{
    const char                  *pp;
    brix_cache_verify_result_e   vr;

    fs->verified = 0;
    if (st->policy.verify == BRIX_CACHE_VERIFY_OFF
        && st->policy.cvmfs_master_pub == NULL)
    {
        return NGX_OK;                 /* verification disabled — commit as-is */
    }
    pp = (fs->staged->inst->driver->staged_path != NULL)
       ? fs->staged->inst->driver->staged_path(fs->staged) : NULL;

    if (st->policy.verify == BRIX_CACHE_VERIFY_CVMFS_CAS) {
        vr = (pp != NULL)
           ? brix_cache_verify_cvmfs_cas(pp, key, st->log,
                                           fs->cks_alg, fs->cks_hex)
           : BRIX_CACHE_VERIFY_ERROR;
        if (vr == BRIX_CACHE_VERIFY_MISMATCH) {
            return cache_fill_verify_reject(st, key, fs, pp);
        }
        if (vr == BRIX_CACHE_VERIFY_ERROR) {
            ngx_log_error(NGX_LOG_ERR, st->log, errno,
                "sd_cache: cvmfs-cas verify could not run for \"%s\" - "
                "failing the fill closed", key);
            brix_cstore_fill_abort(fs->staged);
            errno = EIO;
            return NGX_ERROR;
        }
        fs->verified = (vr == BRIX_CACHE_VERIFY_VERIFIED);
    }

    if (st->policy.cvmfs_master_pub != NULL) {
        ngx_int_t mv = sd_cache_verify_manifest(st, key, pp);

        if (mv == NGX_ERROR) {              /* definitive signature reject */
            return cache_fill_verify_reject(st, key, fs, pp);
        }
        if (mv == NGX_DECLINED) {           /* chain not evaluable — no
                                             * tamper signal, fail closed  */
            brix_cstore_fill_abort(fs->staged);
            errno = EIO;
            return NGX_ERROR;
        }
    }

    /* best-effort / require: compare the staged bytes against the origin's
     * advertised digest (captured in the pump). OFF/CVMFS-CAS never reach here. */
    if (st->policy.verify == BRIX_CACHE_VERIFY_BESTEFFORT
        || st->policy.verify == BRIX_CACHE_VERIFY_REQUIRE)
    {
        return cache_fill_verify_origin(st, key, fs, pp);
    }
    return NGX_OK;
}

#ifndef BRIX_FS_BACKEND_CACHE_SD_CACHE_FILL_INTERNAL_H
#define BRIX_FS_BACKEND_CACHE_SD_CACHE_FILL_INTERNAL_H

/*
 * sd_cache_fill_internal.h — shared internal state for the whole-file fill spine.
 *
 * The fill spine (sd_cache_fill.c) was split for the file-size cap into the
 * orchestrator + acquire/pump/commit phases (sd_cache_fill.c), the integrity
 * verify phase (sd_cache_fill_verify.c), and the cold-tier demote copy
 * (sd_cache_fill_demote.c). The transient per-attempt state threaded through the
 * phases and the move granule are declared here so the verify phase can consume
 * the same struct the orchestrator owns. Driver-private: not part of the
 * sd_cache public surface (sd_cache.h).
 */

#include "sd_cache_internal.h"    /* sd_cache_inst_state + brix_sd_* types */

#include <time.h>                 /* struct timespec */


/* Move granule for a miss-fill (driver-mediated pread/staged_write). */
#define SD_CACHE_CHUNK (1u << 20)


/* Transient state threaded through the fill phases (acquire -> pump ->
 * verify -> commit). Owned by sd_cache_fill; each phase helper consumes or
 * releases the resources it is documented to on its own failure paths. */
typedef struct {
    brix_sd_instance_t *src;       /* the tier THIS attempt fills from — the
                                    * wrapped source, the cold store tier on a
                                    * phase-85 F7 promote, or a mesh sibling
                                    * on a phase-85 F8 peer attempt           */
    int                 from_cold; /* 1 = promote attempt: no stale-serve, no
                                    * WAN accounting, no origin tamper signal */
    int                 from_peer; /* 1 = mesh-sibling attempt: no stale-serve,
                                    * no origin WAN accounting; a verify reject
                                    * DOES raise signal=cvmfs_tamper naming
                                    * the SIBLING as the actor               */
    brix_sd_obj_t      *so;        /* the open source object                  */
    brix_sd_staged_t   *staged;    /* the staged (uncommitted) store object   */
    brix_sd_stat_t      snap;      /* source size/mtime/mode snapshot         */
    u_char             *buf;       /* SD_CACHE_CHUNK move buffer              */
    off_t               off;       /* bytes pumped so far                     */
    int                 verified;  /* cvmfs-cas / origin-digest verified      */
    char                origin_alg[16];  /* origin-advertised digest algorithm
                                          * (kXR_Qcksum), captured while the
                                          * source object is still open        */
    char                origin_hex[129]; /* origin-advertised digest hex       */
    char                cks_alg[16];   /* locally VERIFIED digest algorithm —
                                        * persisted into the cinfo on commit so
                                        * xrdckverify --cache has a producer   */
    char                cks_hex[129];  /* locally verified digest, hex         */
    struct timespec     t0;        /* T16: per-upstream fill duration         */
} sd_cache_fill_state_t;


/* Digest- and signature-verify the staged bytes before the commit publishes
 * them (phase-68 cvmfs-cas + phase-85 F1 manifest/whitelist signature chain +
 * best-effort/require origin-digest compare). No-op (NGX_OK) unless a verify
 * mode is in force. Sets fs->verified on a VERIFIED result. On failure aborts
 * the staged fill and returns NGX_ERROR with errno EBADMSG (mismatch — T20
 * budgets retries) or EIO (verify could not run). Defined in
 * sd_cache_fill_verify.c, called by sd_cache_fill_attempt in sd_cache_fill.c. */
ngx_int_t cache_fill_verify(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs);

#endif /* BRIX_FS_BACKEND_CACHE_SD_CACHE_FILL_INTERNAL_H */

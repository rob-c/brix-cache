/* swarm_internal.h — cross-file seam for the split G12 swarm engine.
 *
 * WHAT: the membership types, per-process registration/context tables, and
 *       former-static entry points shared between swarm.c (registration,
 *       membership core, roster wire format, roster endpoint) and
 *       swarm_gossip.c (probe thread task, ring rebuild, gossip lifecycle,
 *       worker init).
 * WHY:  swarm.c grew past the file-size gate; the event-loop/thread-pool
 *       engine was lifted whole into swarm_gossip.c. Every symbol DEFINED in
 *       one file but CALLED from the other is declared here — no new state
 *       was introduced, the config-time statics merely became module-internal
 *       externs (same seam idiom as cvmfs_module_internal.h). Nothing here is
 *       part of the public cvmfs:// surface (that lives in cvmfs.h).
 * HOW:  include after cvmfs.h. Each declaration names its defining file.
 */
#ifndef BRIX_CVMFS_SWARM_INTERNAL_H
#define BRIX_CVMFS_SWARM_INTERNAL_H

#include "cvmfs.h"
#include "fs/backend/cache/sd_cache.h"

#define CVMFS_SWARM_MAX_EXPORTS  8
#define CVMFS_SWARM_MAX_MEMBERS  64
#define CVMFS_SWARM_LABEL_MAX    272
#define CVMFS_SWARM_HOST_MAX     256
#define CVMFS_SWARM_MISS_DEAD    3
#define CVMFS_SWARM_ROSTER_MAX   32768
#define CVMFS_SWARM_IO_TIMEOUT_S 5

#define CVMFS_SWARM_ROSTER_PATH  "/cvmfs/.swarm/roster"
#define CVMFS_SWARM_ROSTER_TAIL  "/.swarm/roster"

/* Config-time registration (per-process statics, scrub lifecycle). */
typedef struct {
    char    root[256];
    char    pool[64];
    time_t  interval;
} cvmfs_swarm_reg_t;

typedef struct {
    char                 label[CVMFS_SWARM_LABEL_MAX];
    char                 host[CVMFS_SWARM_HOST_MAX];
    int                  port;
    unsigned             dead:1;
    uint64_t             gen;              /* member's boot generation      */
    ngx_uint_t           miss;             /* consecutive probe failures    */
    brix_sd_instance_t  *inst;             /* lazily built http fill source */
} cvmfs_swarm_member_t;

typedef struct {
    ngx_event_t                timer;
    ngx_thread_task_t         *task;
    const cvmfs_swarm_reg_t   *reg;
    unsigned                   busy:1;
    unsigned                   seeded:1;

    cvmfs_swarm_member_t       members[CVMFS_SWARM_MAX_MEMBERS];
    ngx_uint_t                 n_members;
    int                        self;       /* index into members            */
    uint64_t                   self_gen;
    ngx_uint_t                 rr;         /* probe round-robin cursor      */

    const brix_sd_cache_ring_t *pub_ring;  /* currently published ring      */

    /* probe task payload (owned by the thread while busy — snapshotted at
     * fire time so the thread never reads live membership state) */
    ngx_uint_t                 probe_idx;
    char                       probe_host[CVMFS_SWARM_HOST_MAX];
    int                        probe_port;
    char                       probe_from[CVMFS_SWARM_LABEL_MAX];
    uint64_t                   probe_gen;
    char                       resp[CVMFS_SWARM_ROSTER_MAX];
    size_t                     resp_len;
    unsigned                   probe_ok:1;
} cvmfs_swarm_ctx_t;

/* Defined in swarm.c ---------------------------------------------------------
 *
 * Per-process registration table (written by brix_cvmfs_swarm_register at
 * config time) and the per-worker contexts (written by the worker init in
 * swarm_gossip.c, read by the roster endpoint). */
extern cvmfs_swarm_reg_t   cvmfs_swarm_regs[CVMFS_SWARM_MAX_EXPORTS];
extern ngx_uint_t          cvmfs_swarm_regs_n;
extern cvmfs_swarm_ctx_t  *cvmfs_swarm_ctxs[CVMFS_SWARM_MAX_EXPORTS];

/* Lazy membership seed from the static brix_cache_peers ring — called from
 * both the gossip timer and the roster endpoint, whichever runs first once
 * the backend registry is resolvable. */
void cvmfs_swarm_seed(cvmfs_swarm_ctx_t *sw, ngx_log_t *log);

/* Merge one pulled roster into the view (higher generation wins; equal-gen
 * dead beats alive; a dead line about SELF triggers the SWIM refutation
 * bump). Returns non-zero when the view changed. */
int cvmfs_swarm_roster_merge(cvmfs_swarm_ctx_t *sw, char *text, size_t len,
    ngx_log_t *log);

/* Defined in swarm_gossip.c --------------------------------------------------
 *
 * Publish the ALIVE membership as the live rendezvous ring iff it changed
 * (labels sorted so every converged node computes the identical ring). The
 * roster endpoint also publishes after a push-pull introduction. */
void cvmfs_swarm_ring_publish(cvmfs_swarm_ctx_t *sw, ngx_log_t *log);

#endif /* BRIX_CVMFS_SWARM_INTERNAL_H */

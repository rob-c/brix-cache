/*
 * registry_select_sched.c — §2.3/§2.5 selection policy: cms.sched component
 * blending, the maxload ceiling, and stage-aware selection.
 *
 * WHAT: The metric policy layer of the selection ladder.  srv_sel_metric()
 * turns one registry entry into the scalar the tier accumulators compare —
 * either the legacy load-weight blend (Phase-89 W4, byte-identical when
 * cms.sched is unset) or the stock cms.sched per-component weighted blend of
 * the five raw heartbeat theLoad bytes.  srv_sel_over_maxload() implements
 * the maxload ceiling.  brix_srv_select_stage() is the second phase of stage-
 * aware selection (§2.5): pick the roomiest stage-capable node for a file no
 * one currently holds.
 *
 * WHY: Split from registry_select.c so the ladder mechanics (tiers, affinity,
 * fuzz) and the metric policy are individually reviewable and the file-size
 * ceiling holds.  The weights are process-global set-once config (like
 * brix_srv_load_weight) — never mutated after fork.
 *
 * HOW: All pure computation except brix_srv_select_stage, which takes the
 * registry spinlock for its scan like every other selector.
 */
#include "registry_internal.h"

/*
 * sched_active — is the §2.3 component engine configured?
 *
 * WHAT: Returns 1 when any component weight is non-zero (fuzz/maxload alone
 *       do not switch the metric — they modulate the ladder, not the scalar).
 * WHY:  An all-zero weight vector must keep scoring byte-identical to the
 *       legacy path so existing deployments see no behavior change.
 * HOW:  OR over the six weight fields.
 */
static int
sched_active(void)
{
    return (brix_srv_sched.cpu | brix_srv_sched.io | brix_srv_sched.runq
            | brix_srv_sched.mem | brix_srv_sched.pag
            | brix_srv_sched.space) != 0;
}

/*
 * sched_machine_load — the blended machine-load figure for the ceiling test.
 *
 * WHAT: Returns the node's machine load 0-100: the weighted mean of the five
 *       theLoad bytes when the component engine is on, else the recorded max
 *       (load_pct) — the bottleneck resource.
 * WHY:  The maxload ceiling must judge the same figure the operator weighted;
 *       with no weights the stock-like "hottest component" is the honest read.
 * HOW:  Sum weight×byte over the five machine components (space is disk
 *       occupancy, not machine load — excluded) and divide by the weight sum;
 *       a zero machine-weight sum falls back to load_pct.
 */
static uint32_t
sched_machine_load(const brix_srv_entry_t *e)
{
    uint64_t   num, den;

    den = (uint64_t) brix_srv_sched.cpu + brix_srv_sched.io
        + brix_srv_sched.runq + brix_srv_sched.mem + brix_srv_sched.pag;
    if (den == 0) {
        return e->load_pct;
    }

    num = (uint64_t) brix_srv_sched.cpu  * e->load5[0]
        + (uint64_t) brix_srv_sched.io   * e->load5[1]
        + (uint64_t) brix_srv_sched.runq * e->load5[2]
        + (uint64_t) brix_srv_sched.mem  * e->load5[3]
        + (uint64_t) brix_srv_sched.pag  * e->load5[4];
    return (uint32_t) (num / den);
}

/*
 * srv_sel_over_maxload — §2.3: is this node over the cms.sched ceiling?
 *
 * WHAT: Returns 1 when maxload is configured and the node's blended machine
 *       load exceeds it.  0 when the ceiling is off (the default).
 * WHY:  Stock cms.sched maxload stops sending clients to a saturated node
 *       while cooler nodes exist; the ladder in registry_select.c degrades to
 *       the least-loaded overloaded node when everyone is hot (a divergence
 *       from stock's delay-the-client — BriX prefers serving degraded over
 *       stalling, and the SUPCount hold gate covers the not-ready case).
 * HOW:  Compare sched_machine_load() against the configured ceiling.
 */
int
srv_sel_over_maxload(const brix_srv_entry_t *e)
{
    return brix_srv_sched.maxload > 0
           && sched_machine_load(e) > brix_srv_sched.maxload;
}

/*
 * srv_sel_metric — the scalar one registry entry contributes to the ladder.
 *
 * WHAT: Reads minimise the result, writes maximise it.  With cms.sched
 *       weights set: reads score the weighted mean of the five theLoad bytes
 *       plus the space (util_pct) component; writes keep free_mb as the base
 *       (capacity places data) scaled down by the machine load in proportion
 *       to the machine-weight share, so a hot node with equal space loses.
 *       Without weights: the legacy Phase-89 W4 load_weight blend, or the raw
 *       util/free metric when that too is off — byte-identical to before.
 * WHY:  One function owns "what does better mean", so locate/open/stat and
 *       the stage selector can never disagree.
 * HOW:  Dispatch on sched_active(); both blends are pure integer arithmetic
 *       widened to 64-bit before the divide.
 */
uint32_t
srv_sel_metric(const brix_srv_entry_t *e, int for_write)
{
    uint64_t    num, den;
    uint32_t    machine;
    ngx_uint_t  w;

    if (!sched_active()) {
        /* Legacy: Phase-89 W4 single-weight blend (0 = raw metric). */
        uint32_t metric = for_write ? e->free_mb : e->util_pct;

        w = brix_srv_load_weight;
        if (w == 0) {
            return metric;
        }
        if (for_write) {
            return metric
                   - (uint32_t) ((uint64_t) metric * w * e->load_pct / 10000);
        }
        return (uint32_t) (((100 - w) * (uint64_t) metric
                            + w * (uint64_t) e->load_pct) / 100);
    }

    if (for_write) {
        /* Capacity dominates; machine load discounts it by up to its weight
         * share at full load (mirrors the shape of the legacy write blend). */
        machine = sched_machine_load(e);
        return e->free_mb
               - (uint32_t) ((uint64_t) e->free_mb * machine / 200);
    }

    num = (uint64_t) brix_srv_sched.cpu   * e->load5[0]
        + (uint64_t) brix_srv_sched.io    * e->load5[1]
        + (uint64_t) brix_srv_sched.runq  * e->load5[2]
        + (uint64_t) brix_srv_sched.mem   * e->load5[3]
        + (uint64_t) brix_srv_sched.pag   * e->load5[4]
        + (uint64_t) brix_srv_sched.space * e->util_pct;
    den = (uint64_t) brix_srv_sched.cpu + brix_srv_sched.io
        + brix_srv_sched.runq + brix_srv_sched.mem + brix_srv_sched.pag
        + brix_srv_sched.space;
    return (uint32_t) (num / den);   /* den > 0: sched_active() checked */
}

/*
 * brix_srv_select_stage — §2.5: pick the roomiest stage-capable node.
 *
 * WHAT: Scans live (non-blacklisted, non-stale-excluded) entries whose export
 *       prefixes cover path AND that advertised staging (kYR_status stage
 *       bit), picking the one with the most free space.  Returns 1 and fills
 *       host/port, 0 when no stage-capable node matches.
 * WHY:  Stock cmsd's two-phase read selection: prefer a node that HAS the
 *       file; else route the client to a node that can RECALL it — by free
 *       space, because the recall is a write.  The caller (locate/open) runs
 *       this only after the holder plane (loc cache / kYR_have) came up
 *       empty, so this function needs no holder knowledge.
 * HOW:  Same scan shape as srv_select_core with the write-direction metric,
 *       filtered to e->stage == 1; peers and managers never stage for us.
 */
int
brix_srv_select_stage(const char *path, char *host_out, size_t host_size,
    uint16_t *port_out)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 best = -1;
    uint32_t            best_free = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || !e->stage
            || e->role[0] == 'M' || e->role[0] == 'R'
            || (e->role[0] == 'P' && e->role[1] == '\0'))
        {
            continue;
        }
        if (e->blacklisted_until != 0
            && e->blacklisted_until > ngx_current_msec)
        {
            continue;
        }
        if (!srv_path_matches(e->paths, path)) {
            continue;
        }
        if (best == -1 || e->free_mb > best_free) {
            best = (int) i;
            best_free = e->free_mb;
        }
    }

    if (best >= 0) {
        e = &tbl->slots[best];
        ngx_cpystrn((u_char *) host_out, (u_char *) e->host, host_size);
        *port_out = e->port;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return best >= 0;
}

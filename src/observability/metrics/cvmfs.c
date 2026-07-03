#include "metrics_internal.h"

#include <string.h>

/*
 * WHAT: Prometheus export for the cvmfs:// protocol plane (phase-68).
 * WHY:  a CVMFS site cache is judged on exactly these numbers: request mix by
 *       traffic class, fill volume/failures, CAS verify rejections (the
 *       network-corruption evidence), origin failovers, and the LAN-out vs
 *       WAN-in byte split that yields the hit ratio.
 * HOW:  one labeled family (class is a fixed 4-value set — INVARIANT #8) plus
 *       scalar counters, all read lock-free from shm->cvmfs.
 */

static const char *xrootd_cvmfs_class_names[XROOTD_CVMFS_CLASS_COUNT] = {
    "cas",
    "manifest",
    "geo",
    "reject",
};

/* ---- per-repository slot table (see metrics.h for the design notes) ------ */

/* 1 iff READY slot `r` carries exactly `name`/`len`. */
static int
cvmfs_repo_slot_is(const ngx_xrootd_cvmfs_repo_metrics_t *r,
    const char *name, size_t len)
{
    return r->state == XROOTD_CVMFS_REPO_READY
        && strlen(r->name) == len
        && memcmp(r->name, name, len) == 0;
}

ngx_xrootd_cvmfs_repo_metrics_t *
xrootd_cvmfs_repo_slot(const char *name, size_t len)
{
    ngx_xrootd_metrics_t            *m = xrootd_metrics_shared();
    ngx_xrootd_cvmfs_repo_metrics_t *repos;
    ngx_xrootd_cvmfs_repo_metrics_t *other;
    ngx_uint_t                       i;

    if (m == NULL || name == NULL || len == 0
        || len >= XROOTD_CVMFS_REPO_NAME_MAX)
    {
        return NULL;
    }
    repos = m->cvmfs.repos;
    other = &repos[XROOTD_CVMFS_REPO_SLOTS - 1];

    /* Fast path: lowest-index READY match (the convergence rule). */
    for (i = 0; i < XROOTD_CVMFS_REPO_SLOTS - 1; i++) {
        if (cvmfs_repo_slot_is(&repos[i], name, len)) {
            return &repos[i];
        }
    }

    /* First sight: claim the first EMPTY slot (lock-free; a lost race just
     * rescans). The last slot stays reserved for the overflow bucket. */
    for (i = 0; i < XROOTD_CVMFS_REPO_SLOTS - 1; i++) {
        if (repos[i].state == XROOTD_CVMFS_REPO_EMPTY
            && ngx_atomic_cmp_set(&repos[i].state, XROOTD_CVMFS_REPO_EMPTY,
                                  XROOTD_CVMFS_REPO_CLAIMED))
        {
            memcpy(repos[i].name, name, len);
            repos[i].name[len] = '\0';
            (void) ngx_atomic_cmp_set(&repos[i].state,
                                      XROOTD_CVMFS_REPO_CLAIMED,
                                      XROOTD_CVMFS_REPO_READY);
            /* A racing worker may have claimed an EARLIER slot for the same
             * name; the lowest-index rule keeps everyone converged. */
            {
                ngx_uint_t j;

                for (j = 0; j < XROOTD_CVMFS_REPO_SLOTS - 1; j++) {
                    if (cvmfs_repo_slot_is(&repos[j], name, len)) {
                        return &repos[j];
                    }
                }
            }
            return &repos[i];
        }
    }

    /* Table full: everything else folds into the reserved "_other" slot. */
    if (other->state != XROOTD_CVMFS_REPO_READY
        && ngx_atomic_cmp_set(&other->state, XROOTD_CVMFS_REPO_EMPTY,
                              XROOTD_CVMFS_REPO_CLAIMED))
    {
        memcpy(other->name, "_other", sizeof("_other"));
        (void) ngx_atomic_cmp_set(&other->state, XROOTD_CVMFS_REPO_CLAIMED,
                                  XROOTD_CVMFS_REPO_READY);
    }
    return (other->state == XROOTD_CVMFS_REPO_READY) ? other : NULL;
}

/* 1 iff an EARLIER READY slot carries the same name (claim-race duplicate —
 * the exporter emits only the lowest-index instance). */
static int
cvmfs_repo_slot_is_dup(const ngx_xrootd_cvmfs_repo_metrics_t *repos,
    ngx_uint_t i)
{
    ngx_uint_t j;

    for (j = 0; j < i; j++) {
        if (repos[j].state == XROOTD_CVMFS_REPO_READY
            && strcmp(repos[j].name, repos[i].name) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/* ---- per-upstream slot table (bounded "host:port" label — see metrics.h) --
 * Same lock-free EMPTY->CLAIMED->READY lowest-index scheme as the repo table;
 * the reserved last slot is the "_other" overflow bucket. */

static int
cvmfs_up_slot_is(const ngx_xrootd_cvmfs_upstream_metrics_t *u, const char *host)
{
    return u->state == XROOTD_CVMFS_REPO_READY && strcmp(u->name, host) == 0;
}

static ngx_xrootd_cvmfs_upstream_metrics_t *
cvmfs_upstream_slot(const char *host)
{
    ngx_xrootd_metrics_t                *m = xrootd_metrics_shared();
    ngx_xrootd_cvmfs_upstream_metrics_t *ups, *other;
    size_t                               len;
    ngx_uint_t                           i;

    if (m == NULL || host == NULL || host[0] == '\0') {
        return NULL;
    }
    len = strlen(host);
    if (len >= XROOTD_CVMFS_UPSTREAM_NAME_MAX) {
        return NULL;
    }
    ups   = m->cvmfs.upstreams;
    other = &ups[XROOTD_CVMFS_UPSTREAM_SLOTS - 1];

    for (i = 0; i < XROOTD_CVMFS_UPSTREAM_SLOTS - 1; i++) {
        if (cvmfs_up_slot_is(&ups[i], host)) {
            return &ups[i];
        }
    }
    for (i = 0; i < XROOTD_CVMFS_UPSTREAM_SLOTS - 1; i++) {
        if (ups[i].state == XROOTD_CVMFS_REPO_EMPTY
            && ngx_atomic_cmp_set(&ups[i].state, XROOTD_CVMFS_REPO_EMPTY,
                                  XROOTD_CVMFS_REPO_CLAIMED))
        {
            memcpy(ups[i].name, host, len + 1);
            (void) ngx_atomic_cmp_set(&ups[i].state, XROOTD_CVMFS_REPO_CLAIMED,
                                      XROOTD_CVMFS_REPO_READY);
            {
                ngx_uint_t j;

                for (j = 0; j < XROOTD_CVMFS_UPSTREAM_SLOTS - 1; j++) {
                    if (cvmfs_up_slot_is(&ups[j], host)) {
                        return &ups[j];
                    }
                }
            }
            return &ups[i];
        }
    }
    if (other->state != XROOTD_CVMFS_REPO_READY
        && ngx_atomic_cmp_set(&other->state, XROOTD_CVMFS_REPO_EMPTY,
                              XROOTD_CVMFS_REPO_CLAIMED))
    {
        memcpy(other->name, "_other", sizeof("_other"));
        (void) ngx_atomic_cmp_set(&other->state, XROOTD_CVMFS_REPO_CLAIMED,
                                  XROOTD_CVMFS_REPO_READY);
    }
    return (other->state == XROOTD_CVMFS_REPO_READY) ? other : NULL;
}

void
xrootd_cvmfs_upstream_record(const char *host, int ok, off_t bytes,
    long dur_ms, int failover)
{
    ngx_xrootd_cvmfs_upstream_metrics_t *u = cvmfs_upstream_slot(host);
    ngx_uint_t                           b;

    if (u == NULL) {
        return;
    }
    XROOTD_ATOMIC_INC(&u->requests_total);
    if (failover) {
        XROOTD_ATOMIC_INC(&u->failovers_total);
    }
    if (!ok) {
        XROOTD_ATOMIC_INC(&u->fill_failures_total);
        return;
    }
    XROOTD_ATOMIC_INC(&u->fills_total);
    if (bytes > 0) {
        XROOTD_ATOMIC_ADD(&u->origin_bytes_total, (ngx_atomic_uint_t) bytes);
    }
    if (dur_ms < 0) {
        dur_ms = 0;
    }
    for (b = 0; b < XROOTD_CVMFS_UP_HBUCKETS; b++) {
        if (dur_ms <= xrootd_cvmfs_up_bucket_ms[b]) {
            XROOTD_ATOMIC_INC(&u->dur_bucket[b]);
            break;                       /* non-cumulative; exporter sums up */
        }
    }
    XROOTD_ATOMIC_INC(&u->dur_count);    /* +Inf bucket == dur_count         */
    XROOTD_ATOMIC_ADD(&u->dur_sum_ms, (ngx_atomic_uint_t) dur_ms);
}

/* 1 iff an EARLIER READY upstream slot carries the same name (claim-race dup). */
static int
cvmfs_up_slot_is_dup(const ngx_xrootd_cvmfs_upstream_metrics_t *ups,
    ngx_uint_t i)
{
    ngx_uint_t j;

    for (j = 0; j < i; j++) {
        if (ups[j].state == XROOTD_CVMFS_REPO_READY
            && strcmp(ups[j].name, ups[i].name) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static void
cvmfs_export_upstreams(metrics_writer_t *mw, ngx_xrootd_cvmfs_metrics_t *c)
{
    static const struct {
        const char *name;
        const char *help;
        size_t      off;
    } fam[] = {
        { "xrootd_cvmfs_upstream_requests_total",
          "origin fill attempts per upstream Stratum-1",
          offsetof(ngx_xrootd_cvmfs_upstream_metrics_t, requests_total) },
        { "xrootd_cvmfs_upstream_fills_total",
          "origin fills that published per upstream Stratum-1",
          offsetof(ngx_xrootd_cvmfs_upstream_metrics_t, fills_total) },
        { "xrootd_cvmfs_upstream_fill_failures_total",
          "origin fill attempts that failed per upstream Stratum-1",
          offsetof(ngx_xrootd_cvmfs_upstream_metrics_t, fill_failures_total) },
        { "xrootd_cvmfs_upstream_failovers_total",
          "fills served by a non-primary endpoint per upstream Stratum-1",
          offsetof(ngx_xrootd_cvmfs_upstream_metrics_t, failovers_total) },
        { "xrootd_cvmfs_upstream_origin_bytes_total",
          "bytes pulled per upstream Stratum-1 (WAN in)",
          offsetof(ngx_xrootd_cvmfs_upstream_metrics_t, origin_bytes_total) },
    };
    ngx_uint_t f, i, b;

    for (f = 0; f < sizeof(fam) / sizeof(fam[0]); f++) {
        mw_printf(mw, "# HELP %s %s\n# TYPE %s counter\n",
                  fam[f].name, fam[f].help, fam[f].name);
        for (i = 0; i < XROOTD_CVMFS_UPSTREAM_SLOTS; i++) {
            ngx_xrootd_cvmfs_upstream_metrics_t *u = &c->upstreams[i];

            if (u->state != XROOTD_CVMFS_REPO_READY
                || cvmfs_up_slot_is_dup(c->upstreams, i))
            {
                continue;
            }
            mw_printf(mw, "%s{upstream=\"%s\"} %lu\n", fam[f].name, u->name,
                (unsigned long) *(ngx_atomic_t *) ((u_char *) u + fam[f].off));
        }
    }

    /* fill-duration histogram (Prometheus seconds; le buckets are cumulative) */
    mw_printf(mw,
        "# HELP xrootd_cvmfs_upstream_fill_duration_seconds origin fill duration per upstream\n"
        "# TYPE xrootd_cvmfs_upstream_fill_duration_seconds histogram\n");
    for (i = 0; i < XROOTD_CVMFS_UPSTREAM_SLOTS; i++) {
        ngx_xrootd_cvmfs_upstream_metrics_t *u = &c->upstreams[i];
        unsigned long cum = 0;

        if (u->state != XROOTD_CVMFS_REPO_READY
            || cvmfs_up_slot_is_dup(c->upstreams, i))
        {
            continue;
        }
        for (b = 0; b < XROOTD_CVMFS_UP_HBUCKETS; b++) {
            cum += (unsigned long) u->dur_bucket[b];
            mw_printf(mw,
                "xrootd_cvmfs_upstream_fill_duration_seconds_bucket"
                "{upstream=\"%s\",le=\"%.3f\"} %lu\n",
                u->name, (double) xrootd_cvmfs_up_bucket_ms[b] / 1000.0, cum);
        }
        mw_printf(mw,
            "xrootd_cvmfs_upstream_fill_duration_seconds_bucket"
            "{upstream=\"%s\",le=\"+Inf\"} %lu\n"
            "xrootd_cvmfs_upstream_fill_duration_seconds_sum{upstream=\"%s\"} %.3f\n"
            "xrootd_cvmfs_upstream_fill_duration_seconds_count{upstream=\"%s\"} %lu\n",
            u->name, (unsigned long) u->dur_count,
            u->name, (double) u->dur_sum_ms / 1000.0,
            u->name, (unsigned long) u->dur_count);
    }
}

void
xrootd_export_cvmfs_metrics(metrics_writer_t *mw, ngx_xrootd_metrics_t *shm)
{
    ngx_xrootd_cvmfs_metrics_t *c = &shm->cvmfs;

    mw_emit_labeled(mw, "xrootd_cvmfs_requests_total",
        "CVMFS requests by traffic class", "class",
        xrootd_cvmfs_class_names, XROOTD_CVMFS_CLASS_COUNT,
        c->requests_total);

    mw_emit_scalar(mw, "xrootd_cvmfs_negative_hits_total",
        "404s absorbed by the per-worker negative cache",
        &c->negative_hits_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_fills_total",
        "origin fills published to the cache", &c->fills_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_fill_failures_total",
        "fills that failed definitively", &c->fill_failures_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_verify_failures_total",
        "CAS verify mismatches (fill quarantined, never admitted)",
        &c->verify_failures_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_origin_failovers_total",
        "read attempts that failed over to the next-ranked origin",
        &c->origin_failovers_total);
    mw_emit_scalar(mw, "xrootd_scvmfs_requests_total",
        "requests admitted by the scvmfs security preamble (EXPERIMENTAL)",
        &c->secure_requests_total);

    /* LAN out split by disposition + WAN in: the hit ratio and the
     * WAN-saved factor are one PromQL expression away. */
    mw_printf(mw,
        "# HELP xrootd_cvmfs_bytes_served_total bytes served to clients by cache disposition\n"
        "# TYPE xrootd_cvmfs_bytes_served_total counter\n"
        "xrootd_cvmfs_bytes_served_total{source=\"hit\"} %lu\n"
        "xrootd_cvmfs_bytes_served_total{source=\"fill\"} %lu\n",
        (unsigned long) c->bytes_served_hit_total,
        (unsigned long) c->bytes_served_fill_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_origin_bytes_total",
        "bytes pulled from the Stratum-1 origins (WAN in)",
        &c->origin_bytes_total);

    /* ---- per-repository families (bounded label set — see metrics.h) ---- */
    {
        static const struct {
            const char *name;
            const char *help;
            size_t      off;
        } fam[] = {
            { "xrootd_cvmfs_repo_files_accessed_total",
              "CAS objects served (hit or fill) per repository",
              offsetof(ngx_xrootd_cvmfs_repo_metrics_t, files_accessed_total) },
            { "xrootd_cvmfs_repo_cache_hits_total",
              "requests served from the local store per repository",
              offsetof(ngx_xrootd_cvmfs_repo_metrics_t, cache_hits_total) },
            { "xrootd_cvmfs_repo_cache_misses_total",
              "requests that needed an origin fill per repository",
              offsetof(ngx_xrootd_cvmfs_repo_metrics_t, cache_misses_total) },
            { "xrootd_cvmfs_repo_fills_total",
              "origin fills published per repository",
              offsetof(ngx_xrootd_cvmfs_repo_metrics_t, fills_total) },
            { "xrootd_cvmfs_repo_fill_failures_total",
              "fills that failed definitively per repository",
              offsetof(ngx_xrootd_cvmfs_repo_metrics_t, fill_failures_total) },
            { "xrootd_cvmfs_repo_verify_failures_total",
              "CAS verify mismatches per repository",
              offsetof(ngx_xrootd_cvmfs_repo_metrics_t, verify_failures_total) },
            { "xrootd_cvmfs_repo_negative_hits_total",
              "404s absorbed by the negative cache per repository",
              offsetof(ngx_xrootd_cvmfs_repo_metrics_t, negative_hits_total) },
            { "xrootd_cvmfs_repo_origin_bytes_total",
              "bytes pulled from the Stratum-1 origins per repository (WAN in)",
              offsetof(ngx_xrootd_cvmfs_repo_metrics_t, origin_bytes_total) },
        };
        ngx_uint_t f, i, cls;

        mw_printf(mw,
            "# HELP xrootd_cvmfs_repo_requests_total requests per repository by traffic class\n"
            "# TYPE xrootd_cvmfs_repo_requests_total counter\n");
        for (i = 0; i < XROOTD_CVMFS_REPO_SLOTS; i++) {
            ngx_xrootd_cvmfs_repo_metrics_t *rm = &c->repos[i];

            if (rm->state != XROOTD_CVMFS_REPO_READY
                || cvmfs_repo_slot_is_dup(c->repos, i))
            {
                continue;
            }
            for (cls = 0; cls < XROOTD_CVMFS_CLASS_COUNT; cls++) {
                mw_printf(mw,
                    "xrootd_cvmfs_repo_requests_total{repo=\"%s\",class=\"%s\"} %lu\n",
                    rm->name, xrootd_cvmfs_class_names[cls],
                    (unsigned long) rm->requests_total[cls]);
            }
        }

        for (f = 0; f < sizeof(fam) / sizeof(fam[0]); f++) {
            mw_printf(mw, "# HELP %s %s\n# TYPE %s counter\n",
                      fam[f].name, fam[f].help, fam[f].name);
            for (i = 0; i < XROOTD_CVMFS_REPO_SLOTS; i++) {
                ngx_xrootd_cvmfs_repo_metrics_t *rm = &c->repos[i];

                if (rm->state != XROOTD_CVMFS_REPO_READY
                    || cvmfs_repo_slot_is_dup(c->repos, i))
                {
                    continue;
                }
                mw_printf(mw, "%s{repo=\"%s\"} %lu\n", fam[f].name, rm->name,
                    (unsigned long) *(ngx_atomic_t *)
                        ((u_char *) rm + fam[f].off));
            }
        }

        mw_printf(mw,
            "# HELP xrootd_cvmfs_repo_bytes_served_total bytes served per repository by cache disposition\n"
            "# TYPE xrootd_cvmfs_repo_bytes_served_total counter\n");
        for (i = 0; i < XROOTD_CVMFS_REPO_SLOTS; i++) {
            ngx_xrootd_cvmfs_repo_metrics_t *rm = &c->repos[i];

            if (rm->state != XROOTD_CVMFS_REPO_READY
                || cvmfs_repo_slot_is_dup(c->repos, i))
            {
                continue;
            }
            mw_printf(mw,
                "xrootd_cvmfs_repo_bytes_served_total{repo=\"%s\",source=\"hit\"} %lu\n"
                "xrootd_cvmfs_repo_bytes_served_total{repo=\"%s\",source=\"fill\"} %lu\n",
                rm->name, (unsigned long) rm->bytes_served_hit_total,
                rm->name, (unsigned long) rm->bytes_served_fill_total);
        }
    }

    cvmfs_export_upstreams(mw, c);
}

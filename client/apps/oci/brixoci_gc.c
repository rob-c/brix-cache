/* brixoci_gc.c — `brixoci gc` (phase-104 D15.3): reclaim what a delete left.
 *
 *   brixoci gc <store-dir> [--grace SECS] [--dry-run] [--json]
 *
 * WHAT: the offline face of the registry GC pass — options in, one pass over
 *       an on-disk `brix_oci_registry_root`, a report out.
 * WHY:  the request handlers deliberately never delete a blob (see
 *       shared/oci/gc.h for why that is the only correct thing for a handler
 *       to do). Answering the whole-store question offline is what this
 *       subcommand is for, and running it by hand is what an operator wants
 *       when the answer must be inspected before it is acted on — which is
 *       what `--dry-run` and `--json` are for.
 * HOW:  the pass itself is shared/oci/gc.c, because the registry's own
 *       maintenance timer runs exactly the same one (D15.5). Everything in
 *       this file is argument handling and presentation: a divergence
 *       between what the tool sweeps and what the server sweeps would be a
 *       divergence nobody could see from either side.
 */
#include "brixoci_internal.h"

#include "cli/jsonout.h"
#include "oci/gc.h"

#include <stdio.h>
#include <string.h>


static void
gc_report_json(const brix_oci_gc_t *c)
{
    const brix_oci_gc_stats_t *s = &c->st;

    fputc('{', stdout);
    brix_json_kv_str(stdout, "store", c->root, 1);
    brix_json_kv_bool(stdout, "dry_run", c->dry_run, 1);
    brix_json_kv_ll(stdout, "grace", c->grace, 1);
    brix_json_kv_ll(stdout, "repositories", (long long) s->repos, 1);
    brix_json_kv_ll(stdout, "manifests", (long long) s->manifests, 1);
    brix_json_kv_ll(stdout, "blobs_live", (long long) s->blobs_live, 1);
    brix_json_kv_ll(stdout, "blobs_swept", (long long) s->blobs_swept, 1);
    brix_json_kv_ll(stdout, "blobs_within_grace", (long long) s->blobs_young,
                    1);
    brix_json_kv_ll(stdout, "layer_marks_dropped", (long long) s->marks, 1);
    brix_json_kv_ll(stdout, "referrers_dropped", (long long) s->refs, 1);
    brix_json_kv_ll(stdout, "bytes_reclaimed", (long long) s->bytes, 0);
    fputs("}\n", stdout);
}


static void
gc_report_text(const brix_oci_gc_t *c)
{
    const brix_oci_gc_stats_t *s = &c->st;
    const char                *verb = c->dry_run ? "would sweep" : "swept";

    printf("scanned %lu repositories, %lu manifests\n", s->repos,
           s->manifests);
    printf("%s %lu blobs (%llu bytes), kept %lu live, %lu within grace\n",
           verb, s->blobs_swept, s->bytes, s->blobs_live, s->blobs_young);
    printf("%s %lu stale layer marks, %lu dangling referrer descriptors\n",
           verb, s->marks, s->refs);
}


int
brixoci_gc_run(const brixoci_opts_t *o, const char **pos, int npos, char *err,
               size_t errlen)
{
    brix_oci_gc_t c;
    int           rc;

    if (npos != 1) {
        snprintf(err, errlen, "gc takes exactly one store directory");
        return BRIXOCI_EUSAGE;
    }
    memset(&c, 0, sizeof(c));
    c.root = pos[0];
    c.grace = o->grace;
    c.dry_run = o->dry_run;

    rc = brix_oci_gc_run(&c, err, errlen);
    if (rc == BRIX_OCI_GC_EROOT) {
        return BRIXOCI_EUSAGE;
    }
    if (rc != BRIX_OCI_GC_OK) {
        return BRIX_OCI_REG_ETRANSPORT;
    }
    if (o->json) {
        gc_report_json(&c);
    } else {
        gc_report_text(&c);
    }
    return BRIX_OCI_REG_OK;
}

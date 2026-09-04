/* test_vfs_nearline_probe.c — phase-107 C2 (W6): the startup advisor probe
 * brix_vfs_chain_nearline_unstageable(), proven on synthetic driver chains.
 *
 * WHAT: Links the REAL vfs_recall.o and drives its chain walk over hand-built
 *       instances (the test_vfs_caps.c pattern): every combination of
 *       CAP_NEARLINE with/without a recall slot, alone and under a decorator.
 *
 * WHY:  The arm this probe feeds — the [warn] in brix_init_server_stage_advisor
 *       and prepare_recall's kXR_Unsupported refusal — is UNCONSTRUCTIBLE from
 *       a live config today: every shipped driver that can advertise
 *       CAP_NEARLINE (frm, xroot `nearline`, http tape, pblock) also implements
 *       the recall slot, so no nginx.conf can make the probe return 1. That is
 *       exactly why it needs a unit test: the defensive arm would otherwise be
 *       dead code whose first execution is a future driver's misconfiguration.
 *       The walk must also stay in lockstep with brix_vfs_recall's own tier
 *       selection (same object file, same two questions per tier), so proving
 *       it against synthetic chains pins the shared semantics.
 *
 * HOW:  vfs_recall.o's few externs are stubbed below; brix_vfs_decorator_source
 *       is stubbed to read inst->state, letting each synthetic instance carry
 *       its downstream link directly (the real accessor derives the same edge
 *       from the decorator's private state).
 */
#include <stdio.h>
#include <stddef.h>
#include "fs/backend/sd.h"

/* Prototype under test (declared in fs/vfs/vfs.h; kept local so this unit
 * needs only sd.h and links only vfs_recall.o). */
int brix_vfs_chain_nearline_unstageable(brix_sd_instance_t *chain);

/* ---- stubs for vfs_recall.o's externs (none reached by the probe except
 * brix_sd_caps and brix_vfs_decorator_source) ------------------------------ */
uint32_t brix_sd_caps(const brix_sd_instance_t *inst)
    { return inst->caps; }
brix_sd_instance_t *brix_vfs_decorator_source(const brix_sd_instance_t *inst)
    { return (brix_sd_instance_t *) inst->state; }
const char *brix_sd_backend_name(const brix_sd_instance_t *inst)
    { (void) inst; return "syn"; }
void brix_sd_ucred_wipe(brix_sd_cred_t *cred) { (void) cred; }
int brix_vfs_cred_gate_active(const void *vctx) { (void) vctx; return 0; }
const char *brix_vfs_export_relative(const void *vctx, const char *path)
    { (void) vctx; return path; }
const brix_sd_cred_t *brix_vfs_ns_cred(const void *vctx)
    { (void) vctx; return NULL; }
ngx_int_t brix_vfs_require_confined_mutation(void *vctx, int op)
    { (void) vctx; (void) op; return NGX_OK; }
ngx_int_t brix_vfs_gate_confined(const void *vctx, int op)
    { (void) vctx; (void) op; return NGX_OK; }
ngx_int_t brix_path_resolved_to_pfn(const void *vctx, const char *path,
    char *pfn, size_t cap)
{
    size_t len;
    (void) vctx;
    if (path == NULL || pfn == NULL) { return NGX_ERROR; }
    len = strlen(path);
    if (len >= cap) { return NGX_ERROR; }
    memcpy(pfn, path, len + 1);
    return NGX_OK;
}
void brix_metric_vfs_recall(int outcome) { (void) outcome; }
void brix_metric_vfs_evict(const char *driver_name, uint64_t bytes)
    { (void) driver_name; (void) bytes; }

/* dummy slot bodies — only their addresses matter to the probe */
static ngx_int_t
syn_recall(brix_sd_instance_t *i, const char *k, char r[40])
    { (void) i; (void) k; (void) r; return NGX_OK; }
static ngx_int_t
syn_recall_cred(brix_sd_instance_t *i, const char *k,
    const brix_sd_cred_t *c, char r[40])
    { (void) i; (void) k; (void) c; (void) r; return NGX_OK; }

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else         { printf("ok  : %s\n", msg); } } while (0)

int
main(void)
{
    /* synthetic drivers: the four nearline/recall combinations + a flat one */
    static const brix_sd_driver_t flat = {
        .name = "flat", .caps = BRIX_SD_CAP_RANGE_READ,
    };
    static const brix_sd_driver_t nl_none = {          /* the broken shape */
        .name = "nl-none",
        .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_NEARLINE,
    };
    static const brix_sd_driver_t nl_recall = {
        .name = "nl-recall", .recall = syn_recall,
        .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_NEARLINE,
    };
    static const brix_sd_driver_t nl_cred_only = {
        .name = "nl-cred", .recall_cred = syn_recall_cred,
        .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_NEARLINE,
    };
    /* a recall slot on a tier that does NOT advertise nearline: the probe must
     * ignore it — the slot is only reachable behind CAP_NEARLINE (sd.h) */
    static const brix_sd_driver_t flat_recall = {
        .name = "flat-recall", .recall = syn_recall,
        .caps = BRIX_SD_CAP_RANGE_READ,
    };

    /* single-tier chains (state = downstream link = NULL) */
    brix_sd_instance_t i_flat    = { .driver = &flat,        .caps = flat.caps };
    brix_sd_instance_t i_none    = { .driver = &nl_none,     .caps = nl_none.caps };
    brix_sd_instance_t i_recall  = { .driver = &nl_recall,   .caps = nl_recall.caps };
    brix_sd_instance_t i_cred    = { .driver = &nl_cred_only,.caps = nl_cred_only.caps };

    CHECK(brix_vfs_chain_nearline_unstageable(NULL) == 0,
          "NULL chain (default POSIX export) is stageable");
    CHECK(brix_vfs_chain_nearline_unstageable(&i_flat) == 0,
          "flat driver: no nearline tier, nothing to warn about");
    CHECK(brix_vfs_chain_nearline_unstageable(&i_none) == 1,
          "nearline tier with NO recall slot is unstageable");
    CHECK(brix_vfs_chain_nearline_unstageable(&i_recall) == 0,
          "nearline tier with a recall slot is stageable");
    CHECK(brix_vfs_chain_nearline_unstageable(&i_cred) == 0,
          "recall_cred alone satisfies the probe (either twin will do)");

    /* decorated chains: a flat decorator (cache) over each leaf shape — the
     * probe must DESCEND exactly as brix_vfs_recall does */
    {
        brix_sd_instance_t leaf_none   = { .driver = &nl_none,
                                           .caps = nl_none.caps };
        brix_sd_instance_t leaf_recall = { .driver = &nl_recall,
                                           .caps = nl_recall.caps };
        brix_sd_instance_t dec_over_none   = { .driver = &flat,
                                               .caps = flat.caps,
                                               .state = &leaf_none };
        brix_sd_instance_t dec_over_recall = { .driver = &flat,
                                               .caps = flat.caps,
                                               .state = &leaf_recall };

        CHECK(brix_vfs_chain_nearline_unstageable(&dec_over_none) == 1,
              "decorator over a recall-less nearline leaf: still unstageable");
        CHECK(brix_vfs_chain_nearline_unstageable(&dec_over_recall) == 0,
              "decorator over a recall-capable nearline leaf: stageable");
    }

    /* the slot on the WRONG tier does not rescue a broken nearline tier: the
     * pairing is per-tier (cap AND slot on the same instance), matching
     * brix_vfs_recall's own selection — a recall slot the walk would never
     * dispatch to must not silence the warning */
    {
        brix_sd_instance_t leaf_slot_only = { .driver = &flat_recall,
                                              .caps = flat_recall.caps };
        brix_sd_instance_t top_nl_none    = { .driver = &nl_none,
                                              .caps = nl_none.caps,
                                              .state = &leaf_slot_only };

        CHECK(brix_vfs_chain_nearline_unstageable(&top_nl_none) == 1,
              "recall slot on a non-nearline tier does not pair with a "
              "recall-less nearline tier");
    }

    /* per-export cap masking (phase-83): an instance whose NEARLINE bit was
     * masked off is not a nearline tier, whatever its driver could do */
    {
        brix_sd_instance_t masked = { .driver = &nl_none,
                                      .caps = BRIX_SD_CAP_RANGE_READ };

        CHECK(brix_vfs_chain_nearline_unstageable(&masked) == 0,
              "masked-off CAP_NEARLINE removes the tier from the probe");
    }

    if (fails) {
        printf("%d FAILURES\n", fails);
        return 1;
    }
    printf("ALL PASS\n");
    return 0;
}

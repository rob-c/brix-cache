/*
 * test_sreq_compat.c — journal-record migration-compat unit test.
 *
 * WHAT: Verifies that brix_sreq_decode handles three cases correctly:
 *       (1) a full-size record (sizeof brix_sreq_t) round-trips with the cred
 *           intact; (2) a legacy-size record (offsetof brix_sreq_t, cred) —
 *           written before the cred field was appended — decodes with a zeroed
 *           cred (matching pre-feature semantics: service-credential flush);
 *       (3) any other size is rejected as corrupt (NGX_ERROR).
 *
 * WHY:  brix_sreq_t grew an appended brix_stage_cred_t as its final member.
 *       Journals written before the upgrade must replay without data loss; the
 *       zeroed-cred path means "no per-user credential, flush as the service
 *       identity", which is the same behaviour the pre-feature code had.
 *
 * HOW:  Allocate a full-size record, populate the cred fields, then call
 *       brix_sreq_decode() with (a) sizeof rec, (b) the pre-cred legacy size,
 *       (c) one byte short of legacy, (d) one byte over full size.  Only (a)
 *       and (b) must return NGX_OK; (c) and (d) must return NGX_ERROR.
 *
 * Run via: tests/c/run_sreq_compat.sh
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Pull in nginx minimal types + stage_engine.h via src-root include. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/xfer/stage_engine.h"

int
main(void)
{
    brix_sreq_t rec, out;
    size_t      legacy = offsetof(brix_sreq_t, cred);

    memset(&rec, 0, sizeof(rec));
    snprintf(rec.reqid, sizeof(rec.reqid), "r-1");
    rec.kind = BRIX_STAGE_FLUSH;
    snprintf(rec.cred.key, sizeof(rec.cred.key), "x5h-abc");
    rec.cred.deny = 1;

    /* full-size record round-trips with the cred */
    assert(brix_sreq_decode(&rec, sizeof(rec), &out) == NGX_OK);
    assert(strcmp(out.cred.key, "x5h-abc") == 0 && out.cred.deny == 1);

    /* legacy-size record decodes with a zeroed cred */
    assert(brix_sreq_decode(&rec, legacy, &out) == NGX_OK);
    assert(out.cred.key[0] == '\0' && out.cred.deny == 0);
    assert(strcmp(out.reqid, "r-1") == 0);

    /* anything else is corrupt */
    assert(brix_sreq_decode(&rec, legacy - 1, &out) == NGX_ERROR);
    assert(brix_sreq_decode(&rec, sizeof(rec) + 1, &out) == NGX_ERROR);

    printf("test_sreq_compat: all assertions passed\n");
    return 0;
}

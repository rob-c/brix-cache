/*
 * test_sreq_compat.c — journal-record migration-compat unit test.
 *
 * WHAT: Verifies that brix_sreq_decode handles these cases correctly:
 *       (1) a full-size record (sizeof brix_sreq_t) round-trips with the cred
 *           intact; (2) a legacy-size record (offsetof brix_sreq_t, cred) —
 *           written before the cred field was appended — decodes with a zeroed
 *           cred (matching pre-feature semantics: service-credential flush);
 *       (3) any other size is rejected as corrupt (NGX_ERROR);
 *       (4) the in-memory-only cred.bearer (token write-back) never survives a
 *           journal round-trip: the persisted identity prefix
 *           (BRIX_SREQ_IDENTITY_SIZE) excludes the token bytes, and decode always
 *           forces cred.bearer empty — a raw WLCG bearer is never on disk.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE          /* memmem() — bearer-absence scan */
#endif

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

    /* --- bearer journal-safety (token write-back) ---------------------------
     * The in-memory-only cred.bearer must NEVER survive a journal round-trip.
     * BRIX_SREQ_IDENTITY_SIZE is exactly what the journal writers persist: the
     * identity prefix, stopping before the bearer. */
    {
        size_t ident = BRIX_SREQ_IDENTITY_SIZE;

        /* The persisted prefix ends at cred.deny and excludes the whole bearer. */
        assert(ident == offsetof(brix_sreq_t, cred)
                        + offsetof(brix_stage_cred_t, bearer));
        assert(ident < sizeof(brix_sreq_t));      /* bearer is beyond the prefix */

        /* Stamp a live token into the in-memory record, then persist only the
         * identity prefix the way stage_journal_write does. */
        snprintf(rec.cred.bearer, sizeof(rec.cred.bearer),
                 "eyJ.SECRET-BEARER.sig");

        /* SECURITY-NEG: the token bytes are NOT within the persisted prefix. */
        assert(memmem(&rec, ident, "SECRET-BEARER", 13) == NULL);

        /* A persisted (identity-size) record decodes OK with the identity intact
         * and the bearer forced empty — the token never reappears on replay. */
        assert(brix_sreq_decode(&rec, ident, &out) == NGX_OK);
        assert(strcmp(out.cred.key, "x5h-abc") == 0 && out.cred.deny == 1);
        assert(out.cred.bearer[0] == '\0');

        /* COMPAT: a full-size in-memory record (bearer set) also decodes with the
         * bearer scrubbed — decode never yields a token even from a padded/full
         * record that happens to carry one. */
        assert(brix_sreq_decode(&rec, sizeof(rec), &out) == NGX_OK);
        assert(out.cred.bearer[0] == '\0');

        /* Any size in [ident, sizeof] is a valid persisted record (covers the
         * old pre-bearer full size = ident + trailing struct padding). */
        assert(brix_sreq_decode(&rec, ident + 1, &out) == NGX_OK);
        assert(out.cred.bearer[0] == '\0');

        /* But ident-1 (a truncated identity) is still corrupt. */
        assert(brix_sreq_decode(&rec, ident - 1, &out) == NGX_ERROR);
    }

    printf("test_sreq_compat: all assertions passed\n");
    return 0;
}

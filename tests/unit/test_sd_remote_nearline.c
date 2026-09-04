/*
 * test_sd_remote_nearline.c — the remote-origin (s3://) driver's nearline pair:
 * residency (is this object readable now?) and recall (start the restore),
 * driven with no bucket.
 *
 * WHY: the two classifiers in these slots encode decisions that are invisible
 *      from outside — a wrong one is not a crash, it is a wrong answer that
 *      costs money or serves an unreadable object — so nothing else catches
 *      them regressing:
 *
 *      1. x-amz-archive-status must override an online-LOOKING storage class.
 *         INTELLIGENT_TIERING keeps its class name when it demotes an object to
 *         an archive tier and reports the demotion in that header alone;
 *         classifying on the class only would report an unreadable object as
 *         ONLINE and turn every read of it into an opaque 403.
 *      2. An UNRECOGNISED storage class must be ONLINE — the deliberate
 *         asymmetry with the http driver's locality map, which errors on an
 *         unknown token. AWS adds classes routinely and every one outside the
 *         archival list serves reads directly; guessing "archived" would park
 *         every open on a restore that was never needed.
 *      3. `ongoing-request="false"` is ONLINE, not NEARLINE. A completed
 *         restore leaves a readable temporary copy; calling it NEARLINE makes
 *         the cache pay for the same archive retrieval twice.
 *
 *      And the security-negative that binds them: a residency HEAD that FAILS
 *      (403 from the origin) must never fall through to RestoreObject. A denied
 *      read becoming a billable restore against someone else's bucket is the
 *      one outcome neither slot may ever produce.
 *
 * Unity build: this TU #includes sd_remote_nearline.c and supplies the S3
 * primitives it calls (open_read / archive_state / restore / close) plus the
 * two params builders as mocks, so every scenario is deterministic and no HTTP
 * happens. Compiled by cmdscripts.sd_remote_nearline_unit.
 */
#define XRDPROTO_NO_NGX 1

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "fs/backend/remote/sd_remote_internal.h"

static int failures;

static void
check(int ok, const char *what)
{
    if (!ok) {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

/* ---- mocked S3 layer ------------------------------------------------------
 * One scripted HEAD answer, plus a capture of what the slots asked for, so the
 * assertions can look at the object path that would have gone on the wire and
 * count the restores that were (or were not) issued. */
typedef struct {
    int  open_fail;         /* sd_s3_open_read answers NULL with this errno */
    int  head_fail;         /* sd_s3_archive_state answers -1 with this errno */
    char sclass[64];        /* x-amz-storage-class the HEAD reports */
    char restore[128];      /* x-amz-restore */
    char astatus[64];       /* x-amz-archive-status */
    int  heads;             /* HEADs issued */
    int  restores;          /* RestoreObjects issued */
    int  restore_days;      /* days the last RestoreObject asked for */
    char key[256];          /* object path the last call addressed */
} mock_s3;

static mock_s3 g_s3;

/* A handle the slots only ever pass back to the mocks. */
static int g_handle;

sd_s3_file *
sd_s3_open_read(const sd_s3_open_params *p, char *errbuf, size_t errcap)
{
    (void) errbuf; (void) errcap;

    snprintf(g_s3.key, sizeof(g_s3.key), "%s", p->key ? p->key : "");
    if (g_s3.open_fail != 0) {
        errno = g_s3.open_fail;
        return NULL;
    }
    return (sd_s3_file *) &g_handle;
}

static void
mock_copy(const sd_s3_meta_buf *b, const char *val)
{
    if (b != NULL && b->buf != NULL && b->cap > 0) {
        snprintf(b->buf, b->cap, "%s", val);
    }
}

int
sd_s3_archive_state(sd_s3_file *f, const sd_s3_archive_buf_t *out, char *errbuf,
    size_t errcap)
{
    (void) f; (void) errbuf; (void) errcap;

    g_s3.heads++;
    if (g_s3.head_fail != 0) {
        errno = g_s3.head_fail;
        return -1;
    }
    mock_copy(out->storage_class,  g_s3.sclass);
    mock_copy(out->restore,        g_s3.restore);
    mock_copy(out->archive_status, g_s3.astatus);
    return 0;
}

int
sd_s3_restore(const sd_s3_open_params *p, int days, char *errbuf, size_t errcap)
{
    (void) errbuf; (void) errcap;

    g_s3.restores++;
    g_s3.restore_days = days;
    snprintf(g_s3.key, sizeof(g_s3.key), "%s", p->key ? p->key : "");
    return 0;
}

void
sd_s3_close(sd_s3_file *f)
{
    (void) f;
}

void
sd_remote_s3_key(const brix_sd_remote_cfg_t *cfg, const char *key, char *dst,
    size_t dstcap)
{
    snprintf(dst, dstcap, "/%s%s", cfg->bucket, key);
}

void
sd_remote_s3_params(const brix_sd_remote_cfg_t *cfg, const char *objpath,
    sd_s3_open_params *p)
{
    memset(p, 0, sizeof(*p));
    p->host = cfg->host;
    p->port = cfg->port;
    p->key  = objpath;
}

/* ---- cred plumbing (real: sd_remote.c / sd_remote_meta.c) ----------------
 * Gate answers "no per-user credential" so the slots run on the service
 * credential; the params overlay is a no-op for the same reason. */
int
sd_remote_cred_gate(const brix_sd_cred_t *cred)
{
    (void) cred;
    return 0;
}

void
sd_remote_params_cred(sd_s3_open_params *p, const char *ak, const char *sk,
    const char *region, const char *session)
{
    (void) p; (void) ak; (void) sk; (void) region; (void) session;
}

#include "fs/backend/remote/sd_remote_nearline.c"   /* NOLINT — unity build */

/* ---- fixture -------------------------------------------------------------- */

static brix_sd_remote_cfg_t g_cfg;
static brix_sd_instance_t   g_inst;

/* Reset to "a plain STANDARD object on an archive-backed bucket": the HEAD
 * succeeds, nothing is archived, no restore has been asked for. */
static void
fixture_reset(void)
{
    memset(&g_s3, 0, sizeof(g_s3));
    memset(&g_cfg, 0, sizeof(g_cfg));
    memset(&g_inst, 0, sizeof(g_inst));
    snprintf(g_cfg.host, sizeof(g_cfg.host), "s3.example.org");
    snprintf(g_cfg.bucket, sizeof(g_cfg.bucket), "tape");
    g_cfg.nearline     = 1;
    g_cfg.restore_days = 3;
    g_inst.state       = &g_cfg;
    snprintf(g_s3.sclass, sizeof(g_s3.sclass), "STANDARD");
}

/* ---- is_archived: which objects need a restore before they can be read ---- */

static void
test_is_archived(void)
{
    printf("archive classification\n");

    check(sd_remote_is_archived("GLACIER", "") == 1, "GLACIER is archived");
    check(sd_remote_is_archived("DEEP_ARCHIVE", "") == 1,
          "DEEP_ARCHIVE is archived");
    check(sd_remote_is_archived("STANDARD", "") == 0, "STANDARD is not");
    check(sd_remote_is_archived("STANDARD_IA", "") == 0, "STANDARD_IA is not");
    check(sd_remote_is_archived("GLACIER_IR", "") == 0,
          "GLACIER_IR reads directly despite the name");

    /* The class name alone would call this online. */
    check(sd_remote_is_archived("INTELLIGENT_TIERING", "ARCHIVE_ACCESS") == 1,
          "an archive status overrides an online-looking class");
    check(sd_remote_is_archived("INTELLIGENT_TIERING", "DEEP_ARCHIVE_ACCESS")
          == 1, "DEEP_ARCHIVE_ACCESS likewise");
    check(sd_remote_is_archived("INTELLIGENT_TIERING", "") == 0,
          "un-demoted INTELLIGENT_TIERING is online");

    /* The asymmetry with the http locality map, asserted so a later "make both
     * consistent" change has to argue with a test rather than with a comment. */
    check(sd_remote_is_archived("EXPRESS_ONEZONE", "") == 0,
          "an unknown class is online, never archived");
    check(sd_remote_is_archived("", "") == 0, "an absent class is online");

    /* Exact match only: no prefix or substring shortcuts. */
    check(sd_remote_is_archived("GLACIER_XL", "") == 0,
          "a class that merely starts with GLACIER is not GLACIER");
    check(sd_remote_is_archived("glacier", "") == 0,
          "the match is case-sensitive, as the header is");
}

/* ---- restore_state: the three states of an archived object ---------------- */

static void
test_restore_state(void)
{
    printf("restore state\n");

    check(sd_remote_restore_state("") == BRIX_SD_RES_NEARLINE,
          "no restore asked for is NEARLINE");
    check(sd_remote_restore_state("ongoing-request=\"true\"")
          == BRIX_SD_RES_NEARLINE, "a running restore is NEARLINE");
    check(sd_remote_restore_state(
              "ongoing-request=\"false\", expiry-date=\"Fri, 1 Jan 2027 00:00:00 GMT\"")
          == BRIX_SD_RES_ONLINE, "a completed restore is readable NOW");
    check(sd_remote_restore_state("ongoing-request=\"false\"")
          == BRIX_SD_RES_ONLINE, "…with or without the expiry half");
}

/* ---- residency ------------------------------------------------------------ */

static void
test_residency(void)
{
    brix_sd_residency_t res;

    printf("residency\n");

    fixture_reset();
    res = (brix_sd_residency_t) -1;
    check(sd_remote_residency(&g_inst, "/d/f", &res) == NGX_OK
          && res == BRIX_SD_RES_ONLINE && g_s3.heads == 1
          && strcmp(g_s3.key, "/tape/d/f") == 0,
          "a STANDARD object is ONLINE off one HEAD of /bucket/key");

    fixture_reset();
    snprintf(g_s3.sclass, sizeof(g_s3.sclass), "DEEP_ARCHIVE");
    check(sd_remote_residency(&g_inst, "/k", &res) == NGX_OK
          && res == BRIX_SD_RES_NEARLINE, "an archived object is NEARLINE");

    fixture_reset();
    snprintf(g_s3.sclass, sizeof(g_s3.sclass), "GLACIER");
    snprintf(g_s3.restore, sizeof(g_s3.restore),
             "ongoing-request=\"false\", expiry-date=\"Fri, 1 Jan 2027 00:00:00 GMT\"");
    check(sd_remote_residency(&g_inst, "/k", &res) == NGX_OK
          && res == BRIX_SD_RES_ONLINE,
          "a restored copy is ONLINE while it lasts");

    /* Never OFFLINE and never LOST: S3 expresses neither, and inventing LOST
     * from a 404 would tell every plane above that a file was DESTROYED. */
    fixture_reset();
    g_s3.head_fail = ENOENT;
    check(sd_remote_residency(&g_inst, "/gone", &res) == NGX_ERROR
          && errno == ENOENT, "an absent key is ENOENT, not LOST");

    fixture_reset();
    g_s3.open_fail = EACCES;
    check(sd_remote_residency(&g_inst, "/k", &res) == NGX_ERROR
          && g_s3.heads == 0, "a refused open never reaches the HEAD");

    fixture_reset();
    check(sd_remote_residency(NULL, "/k", &res) == NGX_ERROR && errno == EINVAL,
          "a NULL instance is EINVAL");
    fixture_reset();
    check(sd_remote_residency(&g_inst, NULL, &res) == NGX_ERROR
          && errno == EINVAL && g_s3.heads == 0, "a NULL key is EINVAL");
    fixture_reset();
    check(sd_remote_residency(&g_inst, "/k", NULL) == NGX_ERROR
          && errno == EINVAL && g_s3.heads == 0, "a NULL out is EINVAL");
    fixture_reset();
    g_inst.state = NULL;
    check(sd_remote_residency(&g_inst, "/k", &res) == NGX_ERROR
          && errno == EINVAL, "an un-built instance is EINVAL");
}

/* ---- recall --------------------------------------------------------------- */

static void
test_recall(void)
{
    char reqid[40];

    printf("recall\n");

    /* Already readable: no restore, and NGX_OK so the caller fills normally. */
    fixture_reset();
    memset(reqid, 'x', sizeof(reqid));
    check(sd_remote_recall(&g_inst, "/k", reqid) == NGX_OK
          && g_s3.restores == 0 && reqid[0] == '\0',
          "an ONLINE object is NGX_OK with no restore paid for");

    /* Archived: one restore, always NGX_AGAIN, and the operator's window. */
    fixture_reset();
    snprintf(g_s3.sclass, sizeof(g_s3.sclass), "GLACIER");
    check(sd_remote_recall(&g_inst, "/d/f", reqid) == NGX_AGAIN
          && g_s3.restores == 1 && g_s3.restore_days == 3
          && strcmp(g_s3.key, "/tape/d/f") == 0,
          "an archived object queues one RestoreObject for restore_days");

    /* An empty request id is the contract: S3 issues none, and empty means
     * "queued, poll residency". */
    check(reqid[0] == '\0', "recall leaves the request id empty");

    /* A restore already in flight joins it rather than reporting done. */
    fixture_reset();
    snprintf(g_s3.sclass, sizeof(g_s3.sclass), "GLACIER");
    snprintf(g_s3.restore, sizeof(g_s3.restore), "ongoing-request=\"true\"");
    check(sd_remote_recall(&g_inst, "/k", reqid) == NGX_AGAIN
          && g_s3.restores == 1, "an in-flight restore is still NGX_AGAIN");

    /* A completed restore is a fill, not another retrieval. */
    fixture_reset();
    snprintf(g_s3.sclass, sizeof(g_s3.sclass), "GLACIER");
    snprintf(g_s3.restore, sizeof(g_s3.restore), "ongoing-request=\"false\"");
    check(sd_remote_recall(&g_inst, "/k", reqid) == NGX_OK
          && g_s3.restores == 0, "a completed restore is never re-paid for");

    fixture_reset();
    snprintf(g_s3.sclass, sizeof(g_s3.sclass), "GLACIER");
    check(sd_remote_recall(&g_inst, "/k", NULL) == NGX_AGAIN,
          "a NULL request id is accepted, not dereferenced");

    /* Security-negative: a DENIED residency must not fall through to a
     * billable RestoreObject against a bucket we were just refused. */
    fixture_reset();
    g_s3.head_fail = EACCES;
    memset(reqid, 'x', sizeof(reqid));
    check(sd_remote_recall(&g_inst, "/k", reqid) == NGX_ERROR
          && g_s3.restores == 0 && errno == EACCES && reqid[0] == '\0',
          "a denied residency never becomes a restore");

    fixture_reset();
    g_s3.head_fail = ENOENT;
    check(sd_remote_recall(&g_inst, "/gone", reqid) == NGX_ERROR
          && g_s3.restores == 0, "an absent key is not restored into existence");
}

int
main(void)
{
    test_is_archived();
    test_restore_state();
    test_residency();
    test_recall();

    if (failures != 0) {
        printf("sd_remote nearline suite: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("sd_remote nearline suite: all checks passed\n");
    return 0;
}

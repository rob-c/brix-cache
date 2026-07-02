/* client/tests/c/vfs_s3_smoke.c
 *
 * WHAT: Smoke driver for the xrdc_vfs S3 backend (Task A5).
 *       Exercises the VFS S3 backend directly — NOT via xrdcp — so that the test
 *       confirms A5's backend code without waiting for task C3 to rewire xrdcp.
 * WHY:  xrdcp's s3:// path currently goes through copy_web, not the VFS backend.
 *       A direct smoke driver bypasses that routing and calls xrdc_vfs_open /
 *       pwrite / commit / pread end-to-end.
 * HOW:  Mode selected via argv[1] (or default if absent):
 *         (default)  "roundtrip"  — single-PUT + multipart write→read round-trip
 *         "badcreds"              — wrong credentials → XRDC_EAUTH on commit
 *         "nonseq"                — non-sequential pwrite → XRDC_EUSAGE
 *
 *       Environment variables:
 *         S3_URL                 — s3://host:port/bucket/key  (required)
 *         AWS_ACCESS_KEY_ID      — S3 access key              (required for roundtrip)
 *         AWS_SECRET_ACCESS_KEY  — S3 secret key              (required for roundtrip)
 *         AWS_DEFAULT_REGION     — S3 region (default us-east-1)
 *         S3_PART_MAX_OVERRIDE   — part size override in bytes (for MPU testing)
 *
 *       Exit 0 = all selected tests passed; exit 1 = at least one test failed.
 *
 * NOTE: link against $(CLIENT_LIB) + $(PROTO_LIB) + $(LDLIBS) (same as aio-smoke).
 */

#include "../../lib/vfs.h"
#include "../../lib/xrdc.h"
#include "../../src/core/compat/crypto.h"   /* xrootd_crypto_init — arms SHA-256/HMAC */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Helpers */
static void
die(const char *tag, const xrdc_status *st)
{
    fprintf(stderr, "FAIL [%s]: kxr=%d errno=%d msg=%s\n",
            tag, st ? st->kxr : 0, st ? st->sys_errno : 0,
            st ? st->msg : "(null)");
    exit(1);
}

static const char *
s3_url(void)
{
    const char *u = getenv("S3_URL");
    if (u == NULL || u[0] == '\0') {
        fprintf(stderr, "FAIL: S3_URL env not set\n");
        exit(1);
    }
    return u;
}

/* Build a key-specific URL by replacing the last path component. */
static void
make_key_url(const char *base_url, const char *key_suffix,
             char *out, size_t outsz)
{
    const char *slash = strrchr(base_url, '/');
    if (slash != NULL) {
        size_t prefix_len = (size_t) (slash - base_url + 1);
        snprintf(out, outsz, "%.*s%s", (int) prefix_len, base_url, key_suffix);
    } else {
        snprintf(out, outsz, "%s/%s", base_url, key_suffix);
    }
}

/* Test 1: single-PUT round-trip */
/*
 * test_single_put — write a small object (single-PUT path) and read it back.
 *
 * WHAT: opens a write handle with known expected_size (≤ S3_PART_MAX) so the
 *       backend picks the single-PUT path; pwrite the payload; commit; close;
 *       reopen for read; pread and compare bytes.
 * WHY:  confirms the single-PUT write→read path end-to-end.
 */
static void
test_single_put(const char *url)
{
    static const char payload[] = "vfs_s3_smoke: single-PUT round-trip test";
    size_t            payload_len = sizeof(payload) - 1;

    xrdc_status       st;
    xrdc_vfs_open_opts opts;
    xrdc_vfs_file    *wf = NULL;
    xrdc_vfs_file    *rf = NULL;
    char              url_key[2048];
    char              buf[256];
    ssize_t           nr;
    int               rc;

    make_key_url(url, "smoke_single.bin", url_key, sizeof(url_key));
    printf("  test_single_put: %s\n", url_key);

    xrdc_status_clear(&st);
    memset(&opts, 0, sizeof(opts));
    opts.expected_size = (int64_t) payload_len;
    opts.cred          = NULL;

    /* Open for write (single-PUT path: expected_size <= S3_PART_MAX) */
    rc = xrdc_vfs_open(url_key, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                       &opts, &wf, &st);
    if (rc != 0) { die("single-PUT open write", &st); }

    /* pwrite — sequential at offset 0 */
    rc = xrdc_vfs_pwrite(wf, 0, payload, payload_len, &st);
    if (rc != 0) { die("single-PUT pwrite", &st); }

    /* commit — issues the actual PUT */
    rc = xrdc_vfs_commit(wf, &st);
    if (rc != 0) { die("single-PUT commit", &st); }
    xrdc_vfs_close(wf);
    wf = NULL;

    /* Reopen for read */
    xrdc_status_clear(&st);
    opts.expected_size = -1;
    rc = xrdc_vfs_open(url_key, XRDC_VFS_READ, &opts, &rf, &st);
    if (rc != 0) { die("single-PUT open read", &st); }

    /* pread the whole object */
    nr = xrdc_vfs_pread(rf, 0, buf, sizeof(buf), &st);
    if (nr < 0) { die("single-PUT pread", &st); }
    xrdc_vfs_close(rf);
    rf = NULL;

    /* Verify bytes */
    if ((size_t) nr != payload_len) {
        fprintf(stderr, "FAIL single-PUT: read %zd bytes, expected %zu\n",
                nr, payload_len);
        exit(1);
    }
    if (memcmp(buf, payload, payload_len) != 0) {
        fprintf(stderr, "FAIL single-PUT: byte mismatch\n");
        exit(1);
    }
    printf("  single-PUT OK (%zu bytes)\n", payload_len);
}

/* Test 2: multipart upload round-trip */
/*
 * test_multipart — write a multi-part object and read it back.
 *
 * WHAT: opens a write handle with expected_size=-1 so the backend picks the MPU
 *       path; writes 3 × part_size bytes (part_size = S3_PART_MAX_OVERRIDE or
 *       a fallback of 512 bytes for the test) in sequential pwrite calls; the
 *       backend flushes each full part; commit completes the upload; read back
 *       and compare.
 * WHY:  confirms CreateMultipartUpload → PutPart × N → CompleteMultipartUpload.
 * HOW:  uses S3_PART_MAX_OVERRIDE=512 (set by the pytest fixture) so that 3
 *       small pwrite calls each generate a distinct part upload.  Falls back to
 *       512 if the env is unset (allowing the driver to run standalone).
 */
static void
test_multipart(const char *url)
{
    const char       *override_env = getenv("S3_PART_MAX_OVERRIDE");
    size_t            part_sz  = (override_env && override_env[0])
                                 ? (size_t) strtoll(override_env, NULL, 10)
                                 : 512;   /* default for standalone test */
    int               n_parts  = 3;
    size_t            total    = part_sz * (size_t) n_parts;
    char             *wbuf     = malloc(total);
    char             *rbuf     = malloc(total);
    xrdc_status       st;
    xrdc_vfs_open_opts opts;
    xrdc_vfs_file    *wf = NULL;
    xrdc_vfs_file    *rf = NULL;
    char              url_key[2048];
    int               i;
    ssize_t           nr;
    int               rc;
    size_t            total_read;

    if (wbuf == NULL || rbuf == NULL) {
        fprintf(stderr, "FAIL multipart: OOM\n");
        exit(1);
    }

    /* Fill write buffer with a recognisable pattern */
    for (size_t j = 0; j < total; j++) {
        wbuf[j] = (char) ((j & 0xff) ^ 0xa5);
    }

    make_key_url(url, "smoke_mpu.bin", url_key, sizeof(url_key));
    printf("  test_multipart: %s (part_sz=%zu, n_parts=%d, total=%zu)\n",
           url_key, part_sz, n_parts, total);

    xrdc_status_clear(&st);
    memset(&opts, 0, sizeof(opts));
    opts.expected_size = -1;   /* unknown size → forces MPU path */
    opts.cred          = NULL;

    /* Open for write (MPU path: expected_size < 0) */
    rc = xrdc_vfs_open(url_key, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                       &opts, &wf, &st);
    if (rc != 0) { die("multipart open write", &st); }

    /* Write part_sz bytes at a time so each call fills one part */
    for (i = 0; i < n_parts; i++) {
        int64_t off = (int64_t) ((size_t) i * part_sz);
        rc = xrdc_vfs_pwrite(wf, off, wbuf + (size_t) off, part_sz, &st);
        if (rc != 0) { die("multipart pwrite", &st); }
    }

    /* commit — flushes remaining part buffer + CompleteMultipartUpload */
    rc = xrdc_vfs_commit(wf, &st);
    if (rc != 0) { die("multipart commit", &st); }
    xrdc_vfs_close(wf);
    wf = NULL;

    /* Reopen for read */
    xrdc_status_clear(&st);
    rc = xrdc_vfs_open(url_key, XRDC_VFS_READ, &opts, &rf, &st);
    if (rc != 0) { die("multipart open read", &st); }

    /* pread all bytes (possibly in multiple calls if S3_PREAD_MAX is small) */
    total_read = 0;
    while (total_read < total) {
        size_t want = total - total_read;
        nr = xrdc_vfs_pread(rf, (int64_t) total_read,
                            rbuf + total_read, want, &st);
        if (nr < 0) { die("multipart pread", &st); }
        if (nr == 0) { break; }   /* EOF */
        total_read += (size_t) nr;
    }
    xrdc_vfs_close(rf);
    rf = NULL;

    if (total_read != total) {
        fprintf(stderr, "FAIL multipart: read %zu bytes, expected %zu\n",
                total_read, total);
        free(wbuf); free(rbuf);
        exit(1);
    }
    if (memcmp(wbuf, rbuf, total) != 0) {
        fprintf(stderr, "FAIL multipart: byte mismatch\n");
        free(wbuf); free(rbuf);
        exit(1);
    }
    printf("  multipart OK (%zu bytes, %d parts)\n", total, n_parts);
    free(wbuf);
    free(rbuf);
}

/* Test 3: bad credentials → XRDC_EAUTH */
/*
 * test_bad_creds — verify that wrong credentials surface as XRDC_EAUTH.
 *
 * WHAT: sets AWS_ACCESS_KEY_ID to a garbage value, opens a write handle and
 *       tries to commit; expects XRDC_EAUTH (not a crash or hang).
 * WHY:  the backend must map 403 Forbidden to a clean XRDC_EAUTH error, not
 *       XRDC_EIO or a crash, so callers can distinguish auth failures from I/O.
 * HOW:  setenv the bad cred; open for write with expected_size=-1 (MPU path
 *       issues CreateMultipartUpload which will 403); check for XRDC_EAUTH.
 *       Restore the original key afterward (best-effort).
 */
static void
test_bad_creds(const char *url)
{
    char              url_key[2048];
    xrdc_status       st;
    xrdc_vfs_open_opts opts;
    xrdc_vfs_file    *wf = NULL;
    const char       *orig_ak = getenv("AWS_ACCESS_KEY_ID");
    int               rc;

    make_key_url(url, "smoke_badcreds.bin", url_key, sizeof(url_key));
    printf("  test_bad_creds: %s\n", url_key);

    /* Temporarily install a bogus access key */
    setenv("AWS_ACCESS_KEY_ID", "BADKEYBADKEYBADKEY01", 1);

    xrdc_status_clear(&st);
    memset(&opts, 0, sizeof(opts));
    opts.expected_size = -1;   /* MPU: auth error surfaces at CreateMPU (POST ?uploads) */
    opts.cred          = NULL;

    rc = xrdc_vfs_open(url_key, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                       &opts, &wf, &st);

    /* Restore the original key before any assertions */
    if (orig_ak != NULL) {
        setenv("AWS_ACCESS_KEY_ID", orig_ak, 1);
    } else {
        unsetenv("AWS_ACCESS_KEY_ID");
    }

    if (rc == 0) {
        /* open succeeded (rare: server may have cached the session) — try commit */
        rc = xrdc_vfs_commit(wf, &st);
        xrdc_vfs_abort(wf);
        xrdc_vfs_close(wf);
    }

    if (rc == 0) {
        fprintf(stderr, "FAIL bad_creds: expected error with bad access key but got success\n");
        exit(1);
    }
    if (st.kxr != XRDC_EAUTH) {
        fprintf(stderr, "FAIL bad_creds: expected XRDC_EAUTH (%d) but got kxr=%d msg=%s\n",
                XRDC_EAUTH, st.kxr, st.msg);
        exit(1);
    }
    printf("  bad_creds OK (got XRDC_EAUTH: %s)\n", st.msg);
}

/* Test 4: non-sequential pwrite → XRDC_EUSAGE */
/*
 * test_nonseq — verify that a non-sequential pwrite returns XRDC_EUSAGE.
 *
 * WHAT: opens a write handle (MPU or single-PUT), writes offset 0 successfully,
 *       then attempts a pwrite at a non-contiguous offset and expects XRDC_EUSAGE.
 * WHY:  S3 objects are written sequentially; the backend must reject random-write
 *       attempts with a clear, diagnosable error rather than corrupting data.
 * HOW:  open; pwrite at 0; pwrite at offset 100 (gap); expect XRDC_EUSAGE on
 *       the second call; abort; close.
 */
static void
test_nonseq(const char *url)
{
    char              url_key[2048];
    xrdc_status       st;
    xrdc_vfs_open_opts opts;
    xrdc_vfs_file    *wf = NULL;
    char              buf[32];
    int               rc;

    make_key_url(url, "smoke_nonseq.bin", url_key, sizeof(url_key));
    printf("  test_nonseq: %s\n", url_key);

    memset(buf, 'X', sizeof(buf));
    xrdc_status_clear(&st);
    memset(&opts, 0, sizeof(opts));
    opts.expected_size = -1;   /* MPU path */
    opts.cred          = NULL;

    rc = xrdc_vfs_open(url_key, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                       &opts, &wf, &st);
    if (rc != 0) { die("nonseq open", &st); }

    /* First write at offset 0 — must succeed */
    rc = xrdc_vfs_pwrite(wf, 0, buf, sizeof(buf), &st);
    if (rc != 0) { die("nonseq first pwrite", &st); }

    /* Second write at a non-contiguous offset — must fail with XRDC_EUSAGE */
    xrdc_status_clear(&st);
    rc = xrdc_vfs_pwrite(wf, 100, buf, sizeof(buf), &st);

    xrdc_vfs_abort(wf);
    xrdc_vfs_close(wf);
    wf = NULL;

    if (rc == 0) {
        fprintf(stderr, "FAIL nonseq: expected XRDC_EUSAGE for gap write but got success\n");
        exit(1);
    }
    if (st.kxr != XRDC_EUSAGE) {
        fprintf(stderr, "FAIL nonseq: expected XRDC_EUSAGE (%d) but got kxr=%d msg=%s\n",
                XRDC_EUSAGE, st.kxr, st.msg);
        exit(1);
    }
    printf("  nonseq OK (got XRDC_EUSAGE: %s)\n", st.msg);
}

/* main */
int
main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "roundtrip";
    const char *url  = s3_url();

    /* Arm the shared HMAC-SHA256/SHA-256 kernels (libxrdproto EVP_MAC/EVP_MD).
     * Without this, xrootd_hmac_sha256 returns 0 and every SigV4 call fails.
     * xrdcp does this in its main(); smoke drivers must do it too. */
    xrootd_crypto_init();

    if (strcmp(mode, "roundtrip") == 0) {
        printf("=== vfs_s3_smoke: roundtrip ===\n");
        test_single_put(url);
        test_multipart(url);
        printf("=== PASS ===\n");
    } else if (strcmp(mode, "badcreds") == 0) {
        printf("=== vfs_s3_smoke: badcreds ===\n");
        test_bad_creds(url);
        printf("=== PASS ===\n");
    } else if (strcmp(mode, "nonseq") == 0) {
        printf("=== vfs_s3_smoke: nonseq ===\n");
        test_nonseq(url);
        printf("=== PASS ===\n");
    } else {
        fprintf(stderr, "Usage: %s [roundtrip|badcreds|nonseq]\n", argv[0]);
        return 1;
    }
    return 0;
}

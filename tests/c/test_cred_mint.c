/* test_cred_mint.c — unit tests for opt-in x509 credential minting
 * (phase-2 T9). Covers: mint for a principal against a throwaway CA (PEM
 * parses, notAfter ~= now+ttl, issuer == CA subject, subject encodes the
 * principal), cache reuse within the refresh window, re-mint past expiry /
 * inside the refresh window, and failure on a bad CA path (no file written).
 * Run via tests/c/run_cred_mint.sh. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "fs/backend/cred_mint.h"

/* Link stub: cred_mint.c calls ngx_log_error() (a macro around
 * ngx_log_error_core) for diagnostics; the full nginx logging subsystem is
 * not linked into this standalone unit test binary. Tests pass log=NULL and
 * only assert on brix_cred_mint()'s return value / on-disk effects, so a
 * no-op stub is sufficient (mirrors run_sreq_compat.sh's stub convention). */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* Mint a throwaway self-signed CA (cert+key) via the openssl CLI. */
static void
mint_ca(const char *cert_path, const char *key_path)
{
    char cmd[2600];
    int  rc;

    snprintf(cmd, sizeof(cmd),
        "openssl req -x509 -newkey rsa:2048 -nodes "
        "-keyout %s -subj /CN=brix-test-mint-ca -days 30 -out %s "
        "2>/dev/null", key_path, cert_path);
    rc = system(cmd);
    assert(rc == 0);
}

static X509 *
load_x509(const char *path)
{
    FILE *f = fopen(path, "r");
    X509 *cert;

    assert(f != NULL);
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return cert;
}

static char *
subject_line(X509 *cert)
{
    static char buf[512];
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    return buf;
}

static char *
issuer_line(X509 *cert)
{
    static char buf[512];
    X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
    return buf;
}

/* Seconds between now and an ASN1_TIME (positive = future). */
static long
seconds_until(const ASN1_TIME *t)
{
    int days = 0, secs = 0;
    assert(ASN1_TIME_diff(&days, &secs, NULL, t) == 1);
    return (long) days * 86400 + secs;
}

/* Overwrite a .pem's notAfter to force it into an expired/near-expiry state
 * (re-signed by the same throwaway CA so parsing still succeeds). */
static void
force_notafter(const char *cert_path, const char *key_path,
    const char *pem_path, long seconds_from_now)
{
    FILE     *f;
    X509     *ca_cert;
    EVP_PKEY *ca_key;
    X509     *cert;

    f = fopen(cert_path, "r");
    ca_cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    f = fopen(key_path, "r");
    ca_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    f = fopen(pem_path, "r");
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    assert(cert != NULL);

    X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert), seconds_from_now);
    assert(X509_sign(cert, ca_key, EVP_sha256()) > 0);

    f = fopen(pem_path, "w");
    assert(f != NULL);
    assert(PEM_write_X509(f, cert) == 1);
    fclose(f);

    X509_free(cert);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
}

int
main(void)
{
    char dir[]      = "/tmp/cred-mint-test-XXXXXX";
    char ca_cert[1200], ca_key[1200], pem_path[1200], bogus[1200];
    struct stat st1, st2;
    X509       *cert;

    assert(mkdtemp(dir) != NULL);
    snprintf(ca_cert, sizeof(ca_cert), "%s/ca.pem", dir);
    snprintf(ca_key,  sizeof(ca_key),  "%s/ca.key", dir);
    snprintf(pem_path, sizeof(pem_path), "%s/alice.pem", dir);
    mint_ca(ca_cert, ca_key);

    /* (a) mint for a principal -> PEM parses, notAfter ~= now+ttl (within a
     *     few seconds), issuer == CA subject, subject encodes the principal. */
    assert(brix_cred_mint(dir, ca_cert, ca_key, "alice", "alice",
                          3600, NULL) == NGX_OK);
    assert(access(pem_path, F_OK) == 0);

    cert = load_x509(pem_path);
    assert(cert != NULL);
    {
        long left = seconds_until(X509_get0_notAfter(cert));
        assert(left > 3590 && left < 3610);
    }
    {
        X509 *ca = load_x509(ca_cert);
        assert(strcmp(issuer_line(cert), subject_line(ca)) == 0);
        X509_free(ca);
    }
    assert(strstr(subject_line(cert), "alice") != NULL);
    assert(strstr(subject_line(cert), "brix-minted") != NULL);
    X509_free(cert);

    /* (b) a second mint call within the refresh window REUSES the cached
     *     file (same mtime — no re-mint). */
    assert(stat(pem_path, &st1) == 0);
    sleep(1);
    assert(brix_cred_mint(dir, ca_cert, ca_key, "alice", "alice",
                          3600, NULL) == NGX_OK);
    assert(stat(pem_path, &st2) == 0);
    assert(st1.st_mtime == st2.st_mtime);

    /* (c) an expired cached file -> re-mint (new notAfter, file changes). */
    force_notafter(ca_cert, ca_key, pem_path, -60 /* already expired */);
    assert(stat(pem_path, &st1) == 0);
    sleep(1);
    assert(brix_cred_mint(dir, ca_cert, ca_key, "alice", "alice",
                          3600, NULL) == NGX_OK);
    assert(stat(pem_path, &st2) == 0);
    assert(st1.st_mtime != st2.st_mtime);
    cert = load_x509(pem_path);
    {
        long left = seconds_until(X509_get0_notAfter(cert));
        assert(left > 3590 && left < 3610);
    }
    X509_free(cert);

    /* (c2) a cached file inside the refresh window (< 300s left) also
     *      re-mints rather than being reused. */
    force_notafter(ca_cert, ca_key, pem_path, 100 /* inside refresh window */);
    assert(stat(pem_path, &st1) == 0);
    sleep(1);
    assert(brix_cred_mint(dir, ca_cert, ca_key, "alice", "alice",
                          3600, NULL) == NGX_OK);
    assert(stat(pem_path, &st2) == 0);
    assert(st1.st_mtime != st2.st_mtime);

    /* (d) mint with a bad CA path -> NGX_ERROR, no file written for a
     *     never-before-seen key. */
    snprintf(bogus, sizeof(bogus), "%s/nosuchfile.pem", dir);
    assert(brix_cred_mint(dir, bogus, ca_key, "bob", "bob",
                          3600, NULL) == NGX_ERROR);
    {
        char bob_path[1200];
        snprintf(bob_path, sizeof(bob_path), "%s/bob.pem", dir);
        assert(access(bob_path, F_OK) != 0);
    }
    assert(brix_cred_mint(dir, ca_cert, bogus, "carol", "carol",
                          3600, NULL) == NGX_ERROR);
    {
        char carol_path[1200];
        snprintf(carol_path, sizeof(carol_path), "%s/carol.pem", dir);
        assert(access(carol_path, F_OK) != 0);
    }

    /* No stray temp files left behind after any of the above. */
    {
        char cmd[1400];
        snprintf(cmd, sizeof(cmd), "ls %s/.mint-* >/dev/null 2>&1", dir);
        assert(system(cmd) != 0);
    }

    printf("test_cred_mint: all assertions passed\n");
    return 0;
}

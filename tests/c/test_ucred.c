/* test_ucred.c — unit tests for per-user backend credential selection.
 * Covers: principal derivation, fs-safe literal vs DN-hash keying, select
 * found/missing/expired, by-key resolve. Run via tests/c/run_ucred_tests.sh. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "core/types/identity.h"
#include "fs/backend/ucred.h"

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fputs(content, f);
    fclose(f);
}

/* Make a throwaway self-signed cert PEM with the given validity (days; negative
 * = already expired) via the openssl CLI or Python cryptography library.
 * OpenSSL 3.0+ rejects non-positive -days; the Python cryptography library
 * (always present in the CI environment) is used instead for expired certs. */
static void mint_pem(const char *path, int days) {
    char cmd[1024];
    int  rc;

    if (days > 0) {
        snprintf(cmd, sizeof(cmd),
            "openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null "
            "-subj /CN=ucredtest -days %d -out %s 2>/dev/null", days, path);
        assert(system(cmd) == 0);
        return;
    }
    /* Expired cert: use Python's cryptography library so we can set arbitrary
     * notAfter without relying on openssl -days accepting negative values. */
    snprintf(cmd, sizeof(cmd),
        "python3 -c \""
        "from cryptography import x509; "
        "from cryptography.x509.oid import NameOID; "
        "from cryptography.hazmat.primitives import hashes, serialization; "
        "from cryptography.hazmat.primitives.asymmetric import rsa; "
        "import datetime; "
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048); "
        "subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u\\\"ucredtest\\\")]); "
        "t0 = datetime.datetime(2020,1,1,tzinfo=datetime.timezone.utc); "
        "cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)"
        ".public_key(key.public_key()).serial_number(x509.random_serial_number())"
        ".not_valid_before(t0).not_valid_after(t0 + datetime.timedelta(days=1))"
        ".sign(key, hashes.SHA256())); "
        "open('%s','wb').write(cert.public_bytes(serialization.Encoding.PEM))"
        "\"",
        path);
    rc = system(cmd);
    assert(rc == 0);
}

int main(void) {
    char dir[] = "/tmp/ucred-test-XXXXXX";
    char buf[512], key[128], path[1200];
    brix_identity_t id;
    brix_sd_ucred_t out;

    assert(mkdtemp(dir) != NULL);

    /* principal: NULL id → NGX_ERROR (path-traversal / null-deref safety) */
    assert(brix_sd_ucred_principal(NULL, buf, sizeof(buf)) == NGX_ERROR);

    /* principal: dn wins over subject; unauthenticated fails */
    memset(&id, 0, sizeof(id));
    assert(brix_sd_ucred_principal(&id, buf, sizeof(buf)) == NGX_ERROR);
    id.is_authenticated = 1;
    id.subject.data = (u_char *) "AKIAEXAMPLE"; id.subject.len = 11;
    assert(brix_sd_ucred_principal(&id, buf, sizeof(buf)) == NGX_OK);
    assert(strcmp(buf, "AKIAEXAMPLE") == 0);
    id.dn.data = (u_char *) "/DC=test/CN=Alice"; id.dn.len = 17;
    assert(brix_sd_ucred_principal(&id, buf, sizeof(buf)) == NGX_OK);
    assert(strcmp(buf, "/DC=test/CN=Alice") == 0);

    /* keying: fs-safe literal kept, DN hashed with the x5h- prefix */
    assert(brix_sd_ucred_key("AKIAEXAMPLE", key, sizeof(key)) == NGX_OK);
    assert(strcmp(key, "AKIAEXAMPLE") == 0);
    assert(brix_sd_ucred_key("/DC=test/CN=Alice", key, sizeof(key)) == NGX_OK);
    assert(strncmp(key, "x5h-", 4) == 0 && strlen(key) == 4 + 32);

    /* dot-traversal safety: "." and ".." must hash (never literal) so that
     * brix_sd_ucred_resolve never builds <dir>/../.pem or <dir>/.pem. */
    {
        char dotkey[128];
        assert(brix_sd_ucred_key(".", dotkey, sizeof(dotkey)) == NGX_OK);
        assert(strncmp(dotkey, "x5h-", 4) == 0 && strlen(dotkey) == 4 + 32);
        assert(brix_sd_ucred_key("..", dotkey, sizeof(dotkey)) == NGX_OK);
        assert(strncmp(dotkey, "x5h-", 4) == 0 && strlen(dotkey) == 4 + 32);
    }
    /* Restore key to the DN hash used by subsequent select tests. */
    assert(brix_sd_ucred_key("/DC=test/CN=Alice", key, sizeof(key)) == NGX_OK);

    /* select: missing → DECLINED, expired=0 */
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);
    assert(!out.expired && out.key[0] != '\0' && out.principal[0] == '/');

    /* select: valid hash-keyed PEM → OK with the resolved path */
    snprintf(path, sizeof(path), "%s/%s.pem", dir, key);
    mint_pem(path, 30);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(strcmp(out.path, path) == 0 && strcmp(out.key, key) == 0);

    /* select: expired PEM → DECLINED, expired=1 */
    mint_pem(path, -1);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);
    assert(out.expired);

    /* select: garbage PEM (unparseable) → DECLINED, treated as missing */
    write_file(path, "not a pem\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);

    /* resolve by key (the flush path) */
    mint_pem(path, 30);
    assert(brix_sd_ucred_resolve(dir, key, &out) == NGX_OK);
    assert(brix_sd_ucred_resolve(dir, "x5h-doesnotexist0000000000000000", &out)
           == NGX_DECLINED);

    /* literal fs-safe key select for the S3 identity */
    memset(&id, 0, sizeof(id));
    id.is_authenticated = 1;
    id.subject.data = (u_char *) "AKIAEXAMPLE"; id.subject.len = 11;
    snprintf(path, sizeof(path), "%s/AKIAEXAMPLE.pem", dir);
    mint_pem(path, 30);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(strcmp(out.key, "AKIAEXAMPLE") == 0);

    /* ---- Phase-2 Task-2: bearer (.token) credential tests --------------- */

    /* Set up a DN-keyed identity for bearer tests. */
    memset(&id, 0, sizeof(id));
    id.is_authenticated = 1;
    id.dn.data = (u_char *) "/DC=bearer/CN=TestUser";
    id.dn.len  = 22;

    char bkey[128];
    assert(brix_sd_ucred_key("/DC=bearer/CN=TestUser", bkey, sizeof(bkey)) == NGX_OK);
    assert(strncmp(bkey, "x5h-", 4) == 0);

    char bpem_path[1200];
    char btok_path[1200];
    snprintf(bpem_path, sizeof(bpem_path), "%s/%s.pem", dir, bkey);
    snprintf(btok_path, sizeof(btok_path), "%s/%s.token", dir, bkey);

    /* (a) .token present, no .pem → NGX_OK, is_bearer=1, bearer has token text. */
    {
        FILE *f = fopen(btok_path, "w");
        assert(f != NULL);
        fputs("eyJhbGciOiJSUzI1NiJ9.test.token\n", f);
        fclose(f);
    }
    /* Ensure no stale .pem from prior tests. */
    unlink(bpem_path);

    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_bearer == 1);
    assert(strcmp(out.bearer, "eyJhbGciOiJSUzI1NiJ9.test.token") == 0);

    /* (b) Both .pem and .token present → x509 wins (is_bearer=0, path ends .pem). */
    mint_pem(bpem_path, 30);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_bearer == 0);
    assert(strstr(out.path, ".pem") != NULL);

    /* (c) Expired .pem with a .token present → DECLINED expired, no token fallback. */
    mint_pem(bpem_path, -1);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);
    assert(out.expired == 1);

    /* (d) Neither .pem nor .token → DECLINED. */
    unlink(bpem_path);
    unlink(btok_path);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);
    assert(out.expired == 0);

    /* (e) .token with trailing newline → bearer is trimmed (no CR/LF). */
    {
        FILE *f = fopen(btok_path, "w");
        assert(f != NULL);
        fputs("trimtest.token.value\r\n", f);
        fclose(f);
    }
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_bearer == 1);
    assert(strcmp(out.bearer, "trimtest.token.value") == 0);

    /* ---- Phase-3 Task-3: S3 (.s3) credential tests ----------------------- */

    /* Set up a DN-keyed identity for S3 tests (fresh key namespace from the
     * bearer tests above). */
    memset(&id, 0, sizeof(id));
    id.is_authenticated = 1;
    id.dn.data = (u_char *) "/DC=s3test/CN=TestUser";
    id.dn.len  = 22;

    char skey[128];
    assert(brix_sd_ucred_key("/DC=s3test/CN=TestUser", skey, sizeof(skey)) == NGX_OK);
    assert(strncmp(skey, "x5h-", 4) == 0);

    char spem_path[1200];
    char stok_path[1200];
    char ss3_path[1200];
    snprintf(spem_path, sizeof(spem_path), "%s/%s.pem", dir, skey);
    snprintf(stok_path, sizeof(stok_path), "%s/%s.token", dir, skey);
    snprintf(ss3_path,  sizeof(ss3_path),  "%s/%s.s3",    dir, skey);

    /* (a) .s3 present alone (3 lines: ak/sk/region) -> NGX_OK, is_s3=1,
     * ak/sk/region populated, is_bearer=0. */
    write_file(ss3_path, "AKIAS3EXAMPLE\nsupersecretkeyvalue\nus-west-2\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_s3 == 1);
    assert(out.is_bearer == 0);
    assert(strcmp(out.s3_ak, "AKIAS3EXAMPLE") == 0);
    assert(strcmp(out.s3_sk, "supersecretkeyvalue") == 0);
    assert(strcmp(out.s3_region, "us-west-2") == 0);

    /* (a2) .s3 with only 2 lines (no region) -> region defaults to
     * "us-east-1". */
    write_file(ss3_path, "AKIAS3EXAMPLE\nsupersecretkeyvalue\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_s3 == 1);
    assert(strcmp(out.s3_region, "us-east-1") == 0);

    /* (b) precedence: .pem present (with .s3 also present) -> x509 wins,
     * is_s3=0. */
    write_file(ss3_path, "AKIAS3EXAMPLE\nsupersecretkeyvalue\nus-west-2\n");
    mint_pem(spem_path, 30);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_s3 == 0);
    assert(out.is_bearer == 0);
    assert(strstr(out.path, ".pem") != NULL);
    unlink(spem_path);

    /* (c) precedence: .token present (no .pem), .s3 also present -> bearer
     * wins over s3. */
    write_file(stok_path, "bearer.wins.over.s3\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_bearer == 1);
    assert(out.is_s3 == 0);
    assert(strcmp(out.bearer, "bearer.wins.over.s3") == 0);
    unlink(stok_path);

    /* (d) malformed .s3: missing secret key (only 1 line) -> DECLINED. */
    write_file(ss3_path, "AKIAS3EXAMPLE\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);

    /* (d2) malformed .s3: empty file -> DECLINED. */
    write_file(ss3_path, "");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);

    /* (d3) malformed .s3: empty secret-key line -> DECLINED. */
    write_file(ss3_path, "AKIAS3EXAMPLE\n\nus-west-2\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);

    /* (e) resolve-by-key (the flush path) also finds the .s3 credential. */
    write_file(ss3_path, "AKIAS3EXAMPLE\nsupersecretkeyvalue\nus-west-2\n");
    assert(brix_sd_ucred_resolve(dir, skey, &out) == NGX_OK);
    assert(out.is_s3 == 1);
    assert(strcmp(out.s3_ak, "AKIAS3EXAMPLE") == 0);

    /* Clean up temp dir files (best-effort; mkdtemp dir is /tmp so OS cleans it). */
    unlink(btok_path);
    unlink(ss3_path);

    /* ---- ceph-peruser item: .keyring credential tests -------------------- */

    /* Set up a DN-keyed identity for keyring tests (fresh key namespace). */
    memset(&id, 0, sizeof(id));
    id.is_authenticated = 1;
    id.dn.data = (u_char *) "/DC=cephtest/CN=TestUser";
    id.dn.len  = 24;

    char ckey[128];
    assert(brix_sd_ucred_key("/DC=cephtest/CN=TestUser", ckey, sizeof(ckey)) == NGX_OK);
    assert(strncmp(ckey, "x5h-", 4) == 0);

    char cpem_path[1200];
    char ctok_path[1200];
    char cs3_path[1200];
    char ckeyring_path[1200];
    snprintf(cpem_path,     sizeof(cpem_path),     "%s/%s.pem",     dir, ckey);
    snprintf(ctok_path,     sizeof(ctok_path),     "%s/%s.token",   dir, ckey);
    snprintf(cs3_path,      sizeof(cs3_path),      "%s/%s.s3",      dir, ckey);
    snprintf(ckeyring_path, sizeof(ckeyring_path), "%s/%s.keyring", dir, ckey);

    /* (a) .keyring present alone -> NGX_OK, is_ceph=1, ceph_keyring = the
     * keyring PATH, ceph_user = the bare id parsed from "[client.bob]". */
    write_file(ckeyring_path,
        "[client.bob]\n\tkey = AQBvExampleBase64EqualsPadding==\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_ceph == 1);
    assert(out.is_bearer == 0 && out.is_s3 == 0);
    assert(strcmp(out.ceph_keyring, ckeyring_path) == 0);
    assert(strcmp(out.ceph_user, "bob") == 0);

    /* (b) precedence: .pem present (with .keyring also present) -> x509
     * wins, is_ceph=0. */
    mint_pem(cpem_path, 30);
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_ceph == 0);
    assert(strstr(out.path, ".pem") != NULL);
    unlink(cpem_path);

    /* (c) precedence: .token present (no .pem), .keyring also present ->
     * bearer wins over ceph. */
    write_file(ctok_path, "bearer.wins.over.ceph\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_bearer == 1);
    assert(out.is_ceph == 0);
    unlink(ctok_path);

    /* (d) precedence: .s3 present (no .pem/.token), .keyring also present ->
     * s3 wins over ceph. */
    write_file(cs3_path, "AKIACEPHEXAMPLE\nsupersecretkeyvalue\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_OK);
    assert(out.is_s3 == 1);
    assert(out.is_ceph == 0);
    unlink(cs3_path);

    /* (e) malformed .keyring: no "[client.X]" section header -> DECLINED. */
    write_file(ckeyring_path, "this is not a keyring file\nkey = deadbeef\n");
    assert(brix_sd_ucred_select(dir, &id, &out) == NGX_DECLINED);

    /* (f) resolve-by-key (the flush path) also finds the .keyring
     * credential. */
    write_file(ckeyring_path, "[client.bob]\n\tkey = AQBvAnotherKeyValue==\n");
    assert(brix_sd_ucred_resolve(dir, ckey, &out) == NGX_OK);
    assert(out.is_ceph == 1);
    assert(strcmp(out.ceph_user, "bob") == 0);
    assert(strcmp(out.ceph_keyring, ckeyring_path) == 0);

    unlink(ckeyring_path);

    printf("test_ucred: all assertions passed\n");
    return 0;
}

/*
 * signing_policy_unittest.c — SP-* grammar and matcher conformance (ngx-free).
 *
 * Build/run: tests/c/run_signing_policy_tests.sh
 * Exit 0 = all checks pass.
 */
#include "auth/crypto/signing_policy.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;
#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", (msg)); } \
    else { printf("  ok: %s\n", (msg)); }                       \
} while (0)

static const char *CA_DN = "/DC=test/DC=xrootd/CN=Test XRootD CA";

static brix_sp_policy_t *parse_ok(const char *s) {
    char err[256];
    brix_sp_policy_t *p = brix_sp_parse(s, strlen(s), err, sizeof(err));
    if (p == NULL) { printf("  parse unexpectedly failed: %s\n", err); }
    return p;
}

static void test_glob(void) {
    printf("SP glob:\n");
    CHECK(brix_sp_glob_match("/DC=test/DC=xrootd/*", "/DC=test/DC=xrootd/CN=Bob"),
          "SP-01 star matches trailing incl slash");
    CHECK(brix_sp_glob_match("/DC=test/*/CN=Bob", "/DC=test/DC=x/DC=y/CN=Bob"),
          "SP-02 star crosses embedded slashes");
    CHECK(!brix_sp_glob_match("/DC=test/DC=xrootd/*", "/DC=other/CN=Bob"),
          "SP-03 non-matching prefix rejected");
    CHECK(brix_sp_glob_match("/dc=TEST/*", "/DC=test/CN=Bob"),
          "SP-04 case-insensitive");
    CHECK(brix_sp_glob_match("/DC=test/CN=?ob", "/DC=test/CN=Bob"),
          "SP-05 question mark one char");
}

static void test_enforce(void) {
    printf("SP enforce:\n");
    const char *ok =
        "access_id_CA  X509  '/DC=test/DC=xrootd/CN=Test XRootD CA'\n"
        "pos_rights    globus  CA:sign\n"
        "cond_subjects globus  '\"/DC=test/DC=xrootd/*\"'\n";
    brix_sp_policy_t *p = parse_ok(ok);
    CHECK(p != NULL, "SP-06 canonical file parses");
    CHECK(p && brix_sp_ca_dn_present(p, CA_DN), "SP-07 CA DN block found");
    CHECK(p && brix_sp_subject_allowed(p, CA_DN, "/DC=test/DC=xrootd/CN=Bob"),
          "SP-08 in-namespace subject allowed");
    CHECK(p && !brix_sp_subject_allowed(p, CA_DN, "/DC=evil/CN=Mallory"),
          "SP-09 out-of-namespace subject rejected");
    CHECK(p && !brix_sp_subject_allowed(p, "/DC=wrong/CN=Other CA",
                                   "/DC=test/DC=xrootd/CN=Bob"),
          "SP-10 unknown CA fails closed");
    if (p) brix_sp_free(p);
}

static void test_variants(void) {
    printf("SP grammar variants:\n");
    /* comments, blank lines, CRLF, single unquoted glob */
    const char *v =
        "# comment\r\n"
        "\r\n"
        "access_id_CA X509 '/DC=test/DC=xrootd/CN=Test XRootD CA'\r\n"
        "pos_rights globus CA:sign\r\n"
        "cond_subjects globus \"/DC=test/DC=xrootd/*\"\r\n";
    brix_sp_policy_t *p = parse_ok(v);
    CHECK(p != NULL, "SP-11 CRLF+comments+single-glob parses");
    CHECK(p && brix_sp_subject_allowed(p, CA_DN, "/DC=test/DC=xrootd/CN=Bob"),
          "SP-12 single unquoted glob enforced");
    if (p) brix_sp_free(p);

    /* multi-block file, one block per CA */
    const char *multi =
        "access_id_CA X509 '/DC=a/CN=CA A'\n"
        "pos_rights globus CA:sign\n"
        "cond_subjects globus '\"/DC=a/*\"'\n"
        "access_id_CA X509 '/DC=test/DC=xrootd/CN=Test XRootD CA'\n"
        "pos_rights globus CA:sign\n"
        "cond_subjects globus '\"/DC=test/DC=xrootd/*\"'\n";
    brix_sp_policy_t *m = parse_ok(multi);
    CHECK(m && brix_sp_subject_allowed(m, CA_DN, "/DC=test/DC=xrootd/CN=Bob"),
          "SP-13 second block matches its own CA");
    CHECK(m && !brix_sp_subject_allowed(m, CA_DN, "/DC=a/CN=X"),
          "SP-14 block A namespace not granted to CA B");
    if (m) brix_sp_free(m);
}

static void test_malformed(void) {
    printf("SP malformed → fail closed:\n");
    char err[256];
    CHECK(brix_sp_parse("access_id_CA X509\n", 18, err, sizeof(err)) == NULL,
          "SP-15 truncated access_id_CA line rejected");
    CHECK(brix_sp_parse("garbage tokens here\n", 20, err, sizeof(err)) == NULL,
          "SP-16 unknown directive rejected");
    /* neg_rights block grants nothing */
    const char *neg =
        "access_id_CA X509 '/DC=test/DC=xrootd/CN=Test XRootD CA'\n"
        "neg_rights globus CA:sign\n"
        "cond_subjects globus '\"/DC=test/DC=xrootd/*\"'\n";
    brix_sp_policy_t *p = brix_sp_parse(neg, strlen(neg), err, sizeof(err));
    CHECK(p != NULL && !brix_sp_subject_allowed(p, CA_DN,
              "/DC=test/DC=xrootd/CN=Bob"),
          "SP-17 neg_rights grants nothing");
    if (p) brix_sp_free(p);
}

int main(void) {
    test_glob();
    test_enforce();
    test_variants();
    test_malformed();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}

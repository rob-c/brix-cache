/*
 * sd_ceph_unittest.c — standalone unit test for the Ceph driver's pure
 * LFN->object-key mapping (sd_ceph_normalize / sd_ceph_key / sd_ceph_ino).
 *
 * These are the security-critical, cluster-independent parts of the backend: the
 * map must be injective (no two logical paths alias one object) and prefix-
 * confined (no `..` escapes the export's key prefix). They need no librados and
 * no nginx, so they are tested here with plain gcc and no running cluster.
 *
 * Build & run (BRIX_HAVE_CEPH intentionally OFF so only the pure helpers
 * compile — no librados needed):
 *   cc -Wall -Wextra -I. sd_ceph_unittest.c sd_ceph.c sd_ceph_compat.c \
 *      -o /tmp/sd_ceph_ut && /tmp/sd_ceph_ut
 */
#include "sd_ceph.h"
#include "sd_ceph_compat.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void
check_norm_ok(const char *in, const char *want)
{
    char out[256];
    int  rc = sd_ceph_normalize(in, out, sizeof(out));

    if (rc != 0 || strcmp(out, want) != 0) {
        fprintf(stderr, "FAIL normalize(\"%s\") -> rc=%d \"%s\" (want \"%s\")\n",
                in, rc, rc == 0 ? out : "<err>", want);
        failures++;
    }
}

static void
check_norm_reject(const char *in)
{
    char out[256];

    if (sd_ceph_normalize(in, out, sizeof(out)) == 0) {
        fprintf(stderr, "FAIL normalize(\"%s\") accepted \"%s\" (want reject)\n",
                in, out);
        failures++;
    }
}

static void
check_key(const char *prefix, const char *lfn, const char *want)
{
    char out[256];
    int  rc = sd_ceph_key(prefix, lfn, out, sizeof(out));

    if (rc != 0 || strcmp(out, want) != 0) {
        fprintf(stderr, "FAIL key(\"%s\",\"%s\") -> rc=%d \"%s\" (want \"%s\")\n",
                prefix, lfn, rc, rc == 0 ? out : "<err>", want);
        failures++;
    }
}

/* ---- Exercise sd_ceph_normalize canonicalization rules ----
 *
 * WHAT: Runs the accept-and-canonicalize table for sd_ceph_normalize; each row
 * asserts a well-formed input maps to its expected canonical form. Bumps the
 * shared failures counter (via check_norm_ok) on any mismatch.
 *
 * WHY: Canonicalization is the first half of the injective map contract. Grouping
 * these rows in one helper keeps main's cyclomatic complexity under the cap while
 * preserving every assertion and its order.
 *
 * HOW:
 *   1. Assert slash collapsing, synthesized leading slash, and dot-drop rules.
 *   2. Assert dot-dot popping (one component, to root, trailing) rules.
 *   3. Assert trailing-slash stripping and the bare-root and empty-string cases.
 */
static void
test_normalize_canonicalization(void)
{
    check_norm_ok("/a/b/c",          "/a/b/c");
    check_norm_ok("a/b/c",           "/a/b/c");   /* leading slash synthesized */
    check_norm_ok("/a//b///c",       "/a/b/c");   /* repeated slashes collapse */
    check_norm_ok("/a/./b/./c",      "/a/b/c");   /* dot component dropped      */
    check_norm_ok("/a/b/../c",       "/a/c");     /* dot-dot pops one component */
    check_norm_ok("/a/b/../../c",    "/c");       /* dot-dot pops to root       */
    check_norm_ok("/a/b/",           "/a/b");     /* trailing slash stripped    */
    check_norm_ok("/",               "/");        /* bare root                  */
    check_norm_ok("",                "/");         /* empty -> root              */
    check_norm_ok("/a/b/..",         "/a");       /* trailing dot-dot           */
    check_norm_ok("/a/../b",         "/b");
}

/* ---- Assert the key map is injective across aliasing inputs ----
 *
 * WHAT: Composes two object keys from inputs that differ only by redundant
 * slashes and a dot component, then asserts they collapse to the identical key.
 * Bumps the shared failures counter on mismatch.
 *
 * WHY: Injectivity is the security-critical half of the map contract: two logical
 * paths that name the same file must never produce two distinct objects.
 *
 * HOW:
 *   1. Build k1 from the redundant-slash, dot-bearing form.
 *   2. Build k2 from the already-canonical form.
 *   3. Fail if the two composed keys differ.
 */
static void
test_key_alias_injectivity(void)
{
    char k1[256], k2[256];

    sd_ceph_key("p", "/x//y/./z",   k1, sizeof(k1));
    sd_ceph_key("p", "/x/y/z",       k2, sizeof(k2));
    if (strcmp(k1, k2) != 0) {
        fprintf(stderr, "FAIL alias: \"%s\" != \"%s\"\n", k1, k2);
        failures++;
    }
}

/* ---- Assert dot-dot escape attempts are rejected ----
 *
 * WHAT: Feeds sd_ceph_normalize a table of inputs whose dot-dot sequences would
 * climb above the export root; each must be rejected. Bumps the shared failures
 * counter (via check_norm_reject) on any accepted input.
 *
 * WHY: Prefix confinement is the other security-critical guarantee: no input may
 * escape the export's key prefix, so every above-root climb must fail closed.
 *
 * HOW:
 *   1. Assert rejection of dot-dot at or immediately below root.
 *   2. Assert rejection of mid-path climbs that net above root.
 *   3. Assert rejection of a relative traversal payload.
 */
static void
test_normalize_escape_rejects(void)
{
    check_norm_reject("/..");
    check_norm_reject("..");
    check_norm_reject("/a/../..");
    check_norm_reject("/a/../../b");
    check_norm_reject("../etc/passwd");
}

/* ---- Exercise sd_ceph_key prefix composition ----
 *
 * WHAT: Runs the prefix-plus-normalized-path composition table; each row asserts
 * a prefix and logical path yield the expected object key. Bumps the shared
 * failures counter (via check_key) on any mismatch.
 *
 * WHY: Key composition is where the confined, canonical path is joined to the
 * export prefix; the empty-prefix and trailing-slash-prefix edge cases must be
 * pinned so a prefix change cannot silently alter object placement.
 *
 * HOW:
 *   1. Assert the empty-prefix pass-through case.
 *   2. Assert the plain-prefix and redundant-slash normalization cases.
 *   3. Assert the trailing-slash prefix case preserves the literal double slash.
 */
static void
test_key_composition(void)
{
    check_key("",        "/data/f.root",  "/data/f.root");
    check_key("xrd",     "/data/f.root",  "xrd/data/f.root");
    check_key("xrd",     "data//f.root",  "xrd/data/f.root");
    check_key("pool42/", "/a/b",          "pool42//a/b");
}

/* ---- Assert the inode hash is stable and collision-free on a spot check ----
 *
 * WHAT: Asserts sd_ceph_ino returns the same value for repeated calls on one oid
 * and different values for two distinct oids. Bumps the shared failures counter
 * on either violation.
 *
 * WHY: The synthetic inode number must be deterministic per object (so stat is
 * stable across calls) yet distinguish distinct objects, which callers rely on
 * for directory enumeration identity.
 *
 * HOW:
 *   1. Fail if two calls on the same oid disagree.
 *   2. Fail if two distinct oids hash to the same value.
 */
static void
test_ino_hash(void)
{
    if (sd_ceph_ino("xrd/a") != sd_ceph_ino("xrd/a")) {
        fprintf(stderr, "FAIL ino not stable\n");
        failures++;
    }
    if (sd_ceph_ino("xrd/a") == sd_ceph_ino("xrd/b")) {
        fprintf(stderr, "FAIL ino collision on distinct oids\n");
        failures++;
    }
}

/* ---- Assert XrdCeph striper-layout classification and pfn recovery ----
 *
 * WHAT: Exercises sd_ceph_oid_is_first_stripe, sd_ceph_oid_to_pfn, and
 * sd_ceph_oid_is_stripe_data over first-stripe, data-stripe, flat-object, and
 * malformed-suffix oids. Bumps the shared failures counter on any misclassification.
 *
 * WHY: Catalog enumeration must keep exactly the first stripe per file, skip data
 * stripes, and treat flat (non-striped) objects as their own entry; getting this
 * wrong duplicates or drops files during directory listing.
 *
 * HOW:
 *   1. Assert first-stripe recognition accepts stripe .0 and rejects .1 and flat.
 *   2. Assert pfn recovery strips the stripe suffix from a first-stripe oid.
 *   3. Assert data-stripe recognition accepts hex data suffixes and rejects the
 *      first stripe, flat objects, non-hex, and short suffixes.
 */
static void
test_striper_layout(void)
{
    char pfn[256];

    if (!sd_ceph_oid_is_first_stripe("data/f.root.0000000000000000")
        || sd_ceph_oid_is_first_stripe("data/f.root.0000000000000001")
        || sd_ceph_oid_is_first_stripe("data/f.root")) {
        fprintf(stderr, "FAIL is_first_stripe classification\n");
        failures++;
    }
    if (sd_ceph_oid_to_pfn("data/f.root.0000000000000000", pfn, sizeof(pfn))
            != 0 || strcmp(pfn, "data/f.root") != 0) {
        fprintf(stderr, "FAIL oid_to_pfn -> \"%s\"\n", pfn);
        failures++;
    }
    if (sd_ceph_oid_is_stripe_data("data/f.root.0000000000000000")   /* first */
        || !sd_ceph_oid_is_stripe_data("data/f.root.0000000000000001") /* data */
        || !sd_ceph_oid_is_stripe_data("data/f.root.00000000000000ff") /* data */
        || sd_ceph_oid_is_stripe_data("data/f.root")            /* flat object */
        || sd_ceph_oid_is_stripe_data("data/f.root.000000000000000g") /* non-hex */
        || sd_ceph_oid_is_stripe_data("data/f.root.1")) {       /* short suffix */
        fprintf(stderr, "FAIL is_stripe_data classification\n");
        failures++;
    }
}

/* ---- Assert one-level child classification for the stripe-collapse listing ----
 *
 * WHAT: Exercises sd_ceph_path_child over root/deep listings: file children,
 * synthetic-directory children, non-children (the dir itself, siblings whose
 * name merely prefixes the dir, out-of-tree paths), and the unrepresentable-
 * name skip. Bumps the shared failures counter on any misclassification.
 *
 * WHY: This is the collapse step of the phase-89 §B.1 directory listing: a
 * wrong match either leaks entries across directories (a sibling whose name
 * shares the dir as a string prefix) or drops/duplicates listing rows.
 *
 * HOW:
 *   1. Assert root-listing file and dir children.
 *   2. Assert deep-listing file and dir children.
 *   3. Assert the non-child rejections (self, prefix-sibling, out-of-tree).
 *   4. Assert the tiny-cap unrepresentable-name skip returns 0.
 */
static void
test_path_child(void)
{
    char name[256];
    char tiny[3];

    if (sd_ceph_path_child("/", "/f.root", name, sizeof(name)) != 1
        || strcmp(name, "f.root") != 0) {
        fprintf(stderr, "FAIL path_child root file\n");
        failures++;
    }
    if (sd_ceph_path_child("/", "/d/x/y", name, sizeof(name)) != 2
        || strcmp(name, "d") != 0) {
        fprintf(stderr, "FAIL path_child root dir\n");
        failures++;
    }
    if (sd_ceph_path_child("/a/b", "/a/b/f", name, sizeof(name)) != 1
        || strcmp(name, "f") != 0) {
        fprintf(stderr, "FAIL path_child deep file\n");
        failures++;
    }
    if (sd_ceph_path_child("/a/b", "/a/b/c/f", name, sizeof(name)) != 2
        || strcmp(name, "c") != 0) {
        fprintf(stderr, "FAIL path_child deep dir\n");
        failures++;
    }
    if (sd_ceph_path_child("/a/b", "/a/b",   name, sizeof(name)) != 0   /* self */
        || sd_ceph_path_child("/a/b", "/a/bc/f", name, sizeof(name)) != 0 /* prefix sibling */
        || sd_ceph_path_child("/a/b", "/a/x/f",  name, sizeof(name)) != 0 /* out of tree */
        || sd_ceph_path_child("/a/b", "/z",      name, sizeof(name)) != 0) {
        fprintf(stderr, "FAIL path_child non-child rejection\n");
        failures++;
    }
    if (sd_ceph_path_child("/", "/longname", tiny, sizeof(tiny)) != 0) {
        fprintf(stderr, "FAIL path_child unrepresentable-name skip\n");
        failures++;
    }
}

/* ---- Run every pure-mapping check group and report the aggregate result ----
 *
 * WHAT: Invokes each check-group helper in order, then prints a pass line and
 * returns 0 if the shared failures counter is zero, or a failure count and
 * returns 1 otherwise.
 *
 * WHY: The pure LFN->object-key helpers are cluster-independent and security
 * critical, so they are exercised here as a standalone program with no librados
 * and no nginx; this orchestrator stays a flat sequence of named check groups.
 *
 * HOW:
 *   1. Run canonicalization, alias-injectivity, and escape-rejection checks.
 *   2. Run key composition, inode-hash, and striper-layout checks.
 *   3. Report success or the failure count via the shared counter.
 */
int
main(void)
{
    test_normalize_canonicalization();
    test_key_alias_injectivity();
    test_normalize_escape_rejects();
    test_key_composition();
    test_ino_hash();
    test_striper_layout();
    test_path_child();

    if (failures == 0) {
        printf("sd_ceph_unittest: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "sd_ceph_unittest: %d FAILURE(S)\n", failures);
    return 1;
}

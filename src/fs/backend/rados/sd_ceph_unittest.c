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

int
main(void)
{
    /* canonicalization: collapse slashes, drop ".", apply ".." */
    check_norm_ok("/a/b/c",          "/a/b/c");
    check_norm_ok("a/b/c",           "/a/b/c");   /* leading slash synthesized */
    check_norm_ok("/a//b///c",       "/a/b/c");   /* repeated slashes collapse */
    check_norm_ok("/a/./b/./c",      "/a/b/c");   /* "." dropped               */
    check_norm_ok("/a/b/../c",       "/a/c");     /* ".." pops one component   */
    check_norm_ok("/a/b/../../c",    "/c");       /* ".." pops to root         */
    check_norm_ok("/a/b/",           "/a/b");     /* trailing slash stripped   */
    check_norm_ok("/",               "/");        /* bare root                 */
    check_norm_ok("",                "/");        /* empty -> root             */
    check_norm_ok("/a/b/..",         "/a");       /* trailing ".."             */
    check_norm_ok("/a/../b",         "/b");

    /* injectivity: distinct-looking inputs that must collapse to one key DO,
     * and genuinely different paths stay different (spot check). */
    {
        char k1[256], k2[256];
        sd_ceph_key("p", "/x//y/./z",   k1, sizeof(k1));
        sd_ceph_key("p", "/x/y/z",       k2, sizeof(k2));
        if (strcmp(k1, k2) != 0) {
            fprintf(stderr, "FAIL alias: \"%s\" != \"%s\"\n", k1, k2);
            failures++;
        }
    }

    /* escape attempts: any ".." that would climb above the root is rejected. */
    check_norm_reject("/..");
    check_norm_reject("..");
    check_norm_reject("/a/../..");
    check_norm_reject("/a/../../b");
    check_norm_reject("../etc/passwd");

    /* key composition: prefix + normalized path */
    check_key("",        "/data/f.root",  "/data/f.root");
    check_key("xrd",     "/data/f.root",  "xrd/data/f.root");
    check_key("xrd",     "data//f.root",  "xrd/data/f.root");
    check_key("pool42/", "/a/b",          "pool42//a/b");

    /* inode hash: stable + distinct for distinct oids */
    if (sd_ceph_ino("xrd/a") != sd_ceph_ino("xrd/a")) {
        fprintf(stderr, "FAIL ino not stable\n");
        failures++;
    }
    if (sd_ceph_ino("xrd/a") == sd_ceph_ino("xrd/b")) {
        fprintf(stderr, "FAIL ino collision on distinct oids\n");
        failures++;
    }

    /* XrdCeph striper layout: catalog enumeration keeps the first stripe (one per
     * file), skips data stripes, and treats flat (non-striped) objects as their
     * own entry. */
    if (!sd_ceph_oid_is_first_stripe("data/f.root.0000000000000000")
        || sd_ceph_oid_is_first_stripe("data/f.root.0000000000000001")
        || sd_ceph_oid_is_first_stripe("data/f.root")) {
        fprintf(stderr, "FAIL is_first_stripe classification\n");
        failures++;
    }
    {
        char pfn[256];
        if (sd_ceph_oid_to_pfn("data/f.root.0000000000000000", pfn, sizeof(pfn))
                != 0 || strcmp(pfn, "data/f.root") != 0) {
            fprintf(stderr, "FAIL oid_to_pfn -> \"%s\"\n", pfn);
            failures++;
        }
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

    if (failures == 0) {
        printf("sd_ceph_unittest: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "sd_ceph_unittest: %d FAILURE(S)\n", failures);
    return 1;
}

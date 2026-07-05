/*
 * test_sd_ceph_compat.c — pure libradosstriper layout helpers (stripe naming +
 * the readdir first-stripe filter). Matches stock XrdCeph: first stripe is
 * "<name>.0000000000000000"; root readdir keeps those and strips the 17-char
 * suffix. Cluster-free.
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../../src/fs/backend/rados/sd_ceph_compat.h"

int main(void) {
    char buf[256];

    /* first stripe = name + ".0000000000000000" (17 chars) */
    assert(sd_ceph_first_stripe("atlas:/x/f", buf, sizeof(buf)) == 0);
    assert(strcmp(buf, "atlas:/x/f.0000000000000000") == 0);

    /* is-first-stripe: yes for .0..0, no for higher stripes / short names */
    assert(sd_ceph_oid_is_first_stripe("atlas:/x/f.0000000000000000") == 1);
    assert(sd_ceph_oid_is_first_stripe("atlas:/x/f.0000000000000001") == 0);
    assert(sd_ceph_oid_is_first_stripe("atlas:/x/f.000000000000000a") == 0);
    assert(sd_ceph_oid_is_first_stripe(".0000000000000000") == 1);   /* empty name edge */
    assert(sd_ceph_oid_is_first_stripe("short") == 0);
    assert(sd_ceph_oid_is_first_stripe("") == 0);

    /* oid → pfn: strip the 17-char first-stripe suffix */
    assert(sd_ceph_oid_to_pfn("atlas:/x/f.0000000000000000", buf, sizeof(buf)) == 0);
    assert(strcmp(buf, "atlas:/x/f") == 0);
    /* a non-first-stripe oid is rejected */
    assert(sd_ceph_oid_to_pfn("atlas:/x/f.0000000000000001", buf, sizeof(buf)) != 0);

    /* round-trip: first_stripe then to_pfn */
    assert(sd_ceph_first_stripe("cms:/store/a/b", buf, sizeof(buf)) == 0);
    char pfn[256];
    assert(sd_ceph_oid_to_pfn(buf, pfn, sizeof(pfn)) == 0);
    assert(strcmp(pfn, "cms:/store/a/b") == 0);

    /* truncation → -1 */
    assert(sd_ceph_first_stripe("atlas:/x/f", buf, 8) == -1);

    printf("test_sd_ceph_compat: ALL PASS\n");
    return 0;
}

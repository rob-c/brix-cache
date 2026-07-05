/*
 * test_site_n2n.c — the tunable site name-translation (N2N) that maps a logical
 * path (LFN) to the physical name a backend addresses. Covers the real GridPP
 * Ceph schemes: RAL/Glasgow (RADOS object name "<pool>:<prefix><lfn>", pool split
 * by stock XrdCephOss::extractPool) and CephFS (POSIX path "<localroot><lfn>"),
 * plus identity. Pure libc; the reverse pfn2lfn powers the root directory listing.
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../../src/fs/backend/site_n2n.h"

int main(void) {
    char pfn[1024], lfn[1024];
    const char *rest;
    brix_n2n_cfg_t c;

    /* 1. identity */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_IDENTITY;
    assert(brix_n2n_lfn2pfn(&c, "/atlas/x", pfn, sizeof(pfn)) == 0);
    assert(strcmp(pfn, "/atlas/x") == 0);
    assert(brix_n2n_pfn2lfn(&c, "/atlas/x", lfn, sizeof(lfn)) == 0);
    assert(strcmp(lfn, "/atlas/x") == 0);

    /* 2. RAL: "<pool>:<lfn>" (no prefix) */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "atlas");
    assert(brix_n2n_lfn2pfn(&c, "/atlas/rucio/f1", pfn, sizeof(pfn)) == 0);
    assert(strcmp(pfn, "atlas:/atlas/rucio/f1") == 0);
    assert(brix_n2n_pfn2lfn(&c, pfn, lfn, sizeof(lfn)) == 0);
    assert(strcmp(lfn, "/atlas/rucio/f1") == 0);

    /* 3. Glasgow-style tuning: a pool + a spacetoken prefix */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "cms");
    snprintf(c.prefix, sizeof(c.prefix), "/store");
    assert(brix_n2n_lfn2pfn(&c, "/data/f", pfn, sizeof(pfn)) == 0);
    assert(strcmp(pfn, "cms:/store/data/f") == 0);
    assert(brix_n2n_pfn2lfn(&c, pfn, lfn, sizeof(lfn)) == 0);
    assert(strcmp(lfn, "/data/f") == 0);

    /* 4. extractPool (stock XrdCephOss::extractPool semantics) */
    assert(brix_n2n_extract_pool("atlas:/atlas/rucio/f1", pfn, sizeof(pfn), &rest) == 0);
    assert(strcmp(pfn, "atlas") == 0);
    assert(strcmp(rest, "/atlas/rucio/f1") == 0);
    /* no colon → stock returns the whole string as the pool */
    assert(brix_n2n_extract_pool("noprefixhere", pfn, sizeof(pfn), &rest) == 0);
    assert(strcmp(pfn, "noprefixhere") == 0);

    /* 5. CephFS: "<localroot><lfn>" POSIX path */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_CEPHFS_PATH;
    snprintf(c.prefix, sizeof(c.prefix), "/mnt/cephfs/atlas");
    assert(brix_n2n_lfn2pfn(&c, "/rucio/data/f", pfn, sizeof(pfn)) == 0);
    assert(strcmp(pfn, "/mnt/cephfs/atlas/rucio/data/f") == 0);
    assert(brix_n2n_pfn2lfn(&c, pfn, lfn, sizeof(lfn)) == 0);
    assert(strcmp(lfn, "/rucio/data/f") == 0);

    /* 6. security: path-traversal in the LFN is rejected by every scheme */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "atlas");
    assert(brix_n2n_lfn2pfn(&c, "/a/../../etc/passwd", pfn, sizeof(pfn)) != 0);
    assert(brix_n2n_lfn2pfn(&c, "../x", pfn, sizeof(pfn)) != 0);
    c.scheme = BRIX_N2N_CEPHFS_PATH;
    assert(brix_n2n_lfn2pfn(&c, "/ok/../../bad", pfn, sizeof(pfn)) != 0);

    /* 7. truncation → -1 (no overflow) */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "atlas");
    assert(brix_n2n_lfn2pfn(&c, "/atlas/rucio/f1", pfn, 4) == -1);

    /* 8. pfn2lfn rejects a pfn not under the expected pool/prefix */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_CEPHFS_PATH;
    snprintf(c.prefix, sizeof(c.prefix), "/mnt/cephfs/atlas");
    assert(brix_n2n_pfn2lfn(&c, "/elsewhere/f", lfn, sizeof(lfn)) != 0);

    printf("test_site_n2n: ALL PASS\n");
    return 0;
}

/*
 * test_meta_advisory.c — the shared advisory unix-metadata codec (Phase 0).
 *
 * Object stores (XrdCeph/RADOS, S3) have no native POSIX mode/mtime/owner, so a
 * chmod/utime is persisted as a single reserved xattr string and read back on
 * stat. This pins the wire format: encode→decode round-trips, decode tolerates
 * missing fields + unknown future tokens, and patch is a field-merge RMW.
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include "../../src/fs/backend/meta_advisory.h"

int main(void) {
    char buf[256];
    brix_meta_advisory_t m, d;

    /* 1. full encode → decode round-trip */
    memset(&m, 0, sizeof(m));
    m.mode = 0640; m.have_mode = 1;
    m.uid = 1000; m.gid = 2000; m.have_owner = 1;
    m.mtime = 1782726000; m.mtime_ns = 500; m.have_mtime = 1;
    int n = brix_meta_advisory_encode(&m, buf, sizeof(buf));
    assert(n > 0 && (size_t) n == strlen(buf));
    assert(strncmp(buf, "v1 ", 3) == 0);

    memset(&d, 0xff, sizeof(d));
    assert(brix_meta_advisory_decode(buf, strlen(buf), &d) == 0);
    assert(d.have_mode && d.mode == 0640);
    assert(d.have_owner && d.uid == 1000 && d.gid == 2000);
    assert(d.have_mtime && d.mtime == 1782726000 && d.mtime_ns == 500);

    /* 2. partial: only mode present → decode sets have_mode only */
    memset(&m, 0, sizeof(m));
    m.mode = 0700; m.have_mode = 1;
    n = brix_meta_advisory_encode(&m, buf, sizeof(buf));
    assert(n > 0);
    memset(&d, 0, sizeof(d));
    assert(brix_meta_advisory_decode(buf, strlen(buf), &d) == 0);
    assert(d.have_mode && d.mode == 0700);
    assert(!d.have_owner && !d.have_mtime);

    /* 3. forward-compat: unknown version + unknown token are ignored, knowns parsed */
    const char *future = "v9 mode=0644 acl=rwxr-x newthing=42 mtime=123";
    memset(&d, 0, sizeof(d));
    assert(brix_meta_advisory_decode(future, strlen(future), &d) == 0);
    assert(d.have_mode && d.mode == 0644);
    assert(d.have_mtime && d.mtime == 123);
    assert(!d.have_owner);

    /* 4. patch = read-modify-write field merge: existing mode, add mtime */
    strcpy(buf, "v1 mode=0644");
    memset(&d, 0, sizeof(d));
    d.mtime = 999; d.mtime_ns = 0; d.have_mtime = 1;     /* delta: only mtime */
    n = brix_meta_advisory_patch(buf, sizeof(buf), &d);
    assert(n > 0);
    memset(&m, 0, sizeof(m));
    assert(brix_meta_advisory_decode(buf, strlen(buf), &m) == 0);
    assert(m.have_mode && m.mode == 0644);               /* preserved */
    assert(m.have_mtime && m.mtime == 999);              /* applied */

    /* 5. patch overwrites a present field */
    strcpy(buf, "v1 mode=0644");
    memset(&d, 0, sizeof(d));
    d.mode = 0600; d.have_mode = 1;
    assert(brix_meta_advisory_patch(buf, sizeof(buf), &d) > 0);
    memset(&m, 0, sizeof(m));
    assert(brix_meta_advisory_decode(buf, strlen(buf), &m) == 0);
    assert(m.mode == 0600);

    /* 6. truncation → -1 (no overflow) */
    memset(&m, 0, sizeof(m));
    m.mode = 0644; m.have_mode = 1; m.uid = 1; m.gid = 1; m.have_owner = 1;
    m.mtime = 1782726000; m.have_mtime = 1;
    assert(brix_meta_advisory_encode(&m, buf, 8) == -1);

    /* 7. empty/garbage decode is benign (no fields set) */
    memset(&d, 0, sizeof(d));
    assert(brix_meta_advisory_decode("", 0, &d) == 0);
    assert(!d.have_mode && !d.have_owner && !d.have_mtime);

    printf("test_meta_advisory: ALL PASS\n");
    return 0;
}

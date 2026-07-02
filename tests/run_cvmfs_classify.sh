#!/usr/bin/env bash
# tests/run_cvmfs_classify.sh — standalone unit test for the pure-C classifier.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d /tmp/cvmfs_classify.XXXXXX)"; trap 'rm -rf "$T"' EXIT
cat > "$T/t.c" <<'EOF'
#include "protocols/cvmfs/classify.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static cvmfs_url_info_t C(const char *p) {
    cvmfs_url_info_t i; assert(cvmfs_classify_url(p, strlen(p), &i) == 0); return i;
}

int main(void) {
    cvmfs_url_info_t i;

    i = C("/cvmfs/atlas.cern.ch/data/ab/cdef0123456789abcdef0123456789abcdef01");
    assert(i.cls == CVMFS_URL_CAS);
    assert(i.repo_len == 13 && memcmp(i.repo, "atlas.cern.ch", 13) == 0);
    assert(i.cas_hex_len == 40 && i.cas_suffix == 0);
    assert(memcmp(i.cas_hex, "abcdef0123456789abcdef0123456789abcdef01", 40) == 0);

    i = C("/cvmfs/atlas.cern.ch/data/ab/cdef0123456789abcdef0123456789abcdef01C");
    assert(i.cls == CVMFS_URL_CAS && i.cas_suffix == 'C');

    i = C("/cvmfs/atlas.cern.ch/.cvmfspublished");
    assert(i.cls == CVMFS_URL_MANIFEST);
    i = C("/cvmfs/atlas.cern.ch/.cvmfswhitelist");
    assert(i.cls == CVMFS_URL_MANIFEST);

    i = C("/cvmfs/atlas.cern.ch/api/v1.0/geo/me/a,b,c");
    assert(i.cls == CVMFS_URL_GEO);

    /* rejects: wrong prefix, traversal, bad hex, short hash, bad suffix,
     * bad repo chars, empty repo */
    assert(C("/etc/passwd").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/../etc/passwd").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a/data/zz/ff").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/data/ab/cdef").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/data/ab/cdef0123456789abcdef0123456789abcdef01Z").cls
           == CVMFS_URL_REJECT);
    assert(C("/cvmfs/bad repo/.cvmfspublished").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs//.cvmfspublished").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/.cvmfspublished/extra").cls == CVMFS_URL_REJECT);

    printf("run_cvmfs_classify: 15 checks OK\n");
    return 0;
}
EOF
gcc -Wall -Werror -I"$HERE/src" -o "$T/t" "$T/t.c" "$HERE/src/protocols/cvmfs/classify.c"
"$T/t"

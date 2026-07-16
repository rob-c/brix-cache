"""Standalone CVMFS URL classifier unit test."""

from __future__ import annotations

from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run


CLASSIFY_TEST = r'''
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
    assert(C("/etc/passwd").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/../etc/passwd").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a/data/zz/ff").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/data/ab/cdef").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/data/ab/cdef0123456789abcdef0123456789abcdef01Z").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/bad repo/.cvmfspublished").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs//.cvmfspublished").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/.cvmfspublished/extra").cls == CVMFS_URL_REJECT);
    printf("run_cvmfs_classify: 15 checks OK\n");
    return 0;
}
'''


def run_checks(base: Path) -> list[tuple[bool, str]]:
    source = base / "test_cvmfs_classify.c"
    binary = base / "test_cvmfs_classify"
    source.write_text(CLASSIFY_TEST, encoding="utf-8")
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Werror",
            "-I",
            str(REPO_ROOT / "src"),
            "-I",
            str(REPO_ROOT / "shared"),
            str(source),
            str(REPO_ROOT / "shared/cvmfs/grammar/classify.c"),
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return [result(False, f"compile CVMFS classifier failed: {(built.stderr or built.stdout)[-2000:]}")]
    ran = run([str(binary)], cwd=REPO_ROOT)
    return [result(ran.returncode == 0, f"CVMFS classifier exited {ran.returncode}: {(ran.stderr or ran.stdout)[-2000:]}")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cvmfs_classify.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))

/*
 * fuzz_rpm_header.c — libFuzzer target for the clean-room RPM header reader.
 *
 * WHAT: presents arbitrary bytes to brix_rpm_open() as a .rpm file and, when
 *       it accepts them, exercises every accessor repomd emission uses:
 *       strings, integers, string arrays, and the joined file list.
 *
 * WHY:  the reader (shared/rpm/rpmhdr.c) is a hand-written parser of the
 *       rpm.org container — chosen over librpm by the clean-room mandate,
 *       which means its bounds arithmetic has no upstream to inherit from
 *       (§D12.2). An index entry is {tag, type, offset, count}: four
 *       attacker-chosen integers that address into a data region, and the
 *       accessors dereference what they name. `count * size` wrapping, an
 *       offset past `dl`, or a string region with no NUL are all reads of
 *       whatever follows the header in our own address space.
 *
 * HOW:  brix_rpm_open() wants a path, so the bytes go through a memfd
 *       addressed as /proc/self/fd/N — no temp file to leak between runs, and
 *       the reader still gets the seekable file it expects. Accepting a file
 *       is only half the contract: the harness then walks the file list to
 *       nfiles(), which is where a dangling DIRINDEXES entry or an overlong
 *       joined path would show up, and asserts the pkgid is 64 hex.
 *
 * Build:
 *   cd tests/fuzz
 *   clang -O1 -g -fsanitize=fuzzer,address,undefined -I ../../shared \
 *       fuzz_rpm_header.c ../../shared/rpm/rpmhdr.c ../../shared/oci/digest.c \
 *       -lcrypto -o fuzz_rpm_header
 *   ./fuzz_rpm_header -runs=200000 corpus_rpm_header/
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "rpm/rpmhdr.h"

#define MAX_FILES 4096

static const uint32_t STR_TAGS[] = {
    BRIX_RPMTAG_NAME, BRIX_RPMTAG_VERSION, BRIX_RPMTAG_RELEASE,
    BRIX_RPMTAG_SUMMARY, BRIX_RPMTAG_DESCRIPTION, BRIX_RPMTAG_ARCH,
    BRIX_RPMTAG_LICENSE, BRIX_RPMTAG_VENDOR, BRIX_RPMTAG_SOURCERPM,
    BRIX_RPMTAG_PAYLOADCOMPRESSOR
};

static const uint32_t ARR_TAGS[] = {
    BRIX_RPMTAG_PROVIDENAME, BRIX_RPMTAG_REQUIRENAME,
    BRIX_RPMTAG_REQUIREVERSION, BRIX_RPMTAG_BASENAMES,
    BRIX_RPMTAG_DIRNAMES, BRIX_RPMTAG_CHANGELOGNAME
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    brix_rpm_pkg_t *pkg;
    char            path[64];
    char            err[256];
    char            file[4096];
    uint32_t        i, n, v;
    int             fd, ghost;
    size_t          k;

    if (size > 4u << 20) {
        return 0;
    }

    fd = memfd_create("pkg", MFD_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    if (size && write(fd, data, size) != (ssize_t) size) {
        close(fd);
        return 0;
    }
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    err[0] = '\0';
    pkg = brix_rpm_open(path, err, sizeof(err));
    if (pkg == NULL) {
        assert(err[0] != '\0');
        close(fd);
        return 0;
    }

    assert(strlen(brix_rpm_pkgid(pkg)) == 64);
    assert(brix_rpm_size_bytes(pkg) == (int64_t) size);

    for (k = 0; k < sizeof(STR_TAGS) / sizeof(STR_TAGS[0]); k++) {
        const char *s = brix_rpm_str(pkg, STR_TAGS[k]);
        if (s != NULL) {
            (void) strlen(s);         /* must be terminated inside the region */
        }
    }
    for (k = 0; k < sizeof(ARR_TAGS) / sizeof(ARR_TAGS[0]); k++) {
        n = brix_rpm_count(pkg, ARR_TAGS[k]);
        for (i = 0; i < n && i < MAX_FILES; i++) {
            const char *s = brix_rpm_stra(pkg, ARR_TAGS[k], i);
            if (s != NULL) {
                (void) strlen(s);
            }
        }
        /* One past the end is a defined answer, not a read. */
        assert(brix_rpm_stra(pkg, ARR_TAGS[k], n) == NULL || n >= MAX_FILES);
    }
    (void) brix_rpm_u32(pkg, BRIX_RPMTAG_SIZE, 0, &v);
    (void) brix_rpm_sig_u32(pkg, BRIX_RPMSIGTAG_PAYLOADSIZE, &v);

    n = brix_rpm_nfiles(pkg);
    for (i = 0; i < n && i < MAX_FILES; i++) {
        uint32_t mode;
        if (brix_rpm_file(pkg, i, file, sizeof(file), &mode, &ghost) == 0) {
            (void) brix_rpm_path_sane(file);
        }
    }

    brix_rpm_close(pkg);
    close(fd);
    return 0;
}

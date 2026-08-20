/*
 * fuzz_tar_header.c — libFuzzer target for the OCI layer tar reader.
 *
 * WHAT: hands arbitrary bytes to brix_tar_open_fd()/brix_tar_next() as if
 *       they were a layer blob, walks every entry it yields, and drains each
 *       body — the exact call sequence the flattener makes.
 *
 * WHY:  a layer is the largest attacker-controlled structure in the ingest
 *       path: ustar and pax and GNU-long headers, octal and base-256 numeric
 *       fields, continuation records, and a decompressor in front of all of
 *       it (§D6). Every entry's path and linkname become path components a
 *       few frames later, so a header walk that runs off its 512-byte block
 *       or trusts a size field is a read of our own memory into a published
 *       tree.
 *
 * HOW:  the reader wants an fd, so the input goes into a memfd — no temp file,
 *       no cleanup, and the same seekable-fd behaviour a real blob has. The
 *       walk is bounded (entries and bytes) because a valid tar can legally
 *       describe an unbounded stream and libFuzzer measures wall time, not
 *       intent. Every yielded path/linkname is read to its terminator: the
 *       reader promises NUL-terminated fixed buffers, and that promise is
 *       what the flattener's containment checks are written against.
 *       Diff-id capture (tar_digest.c) is on for every input so the hash
 *       rides every produced byte; it is only *finished* for a raw archive,
 *       where the drain past the end-of-archive marker is bounded by the
 *       input itself — finishing a gzip bomb would measure zlib, not us.
 *
 * Build:
 *   cd tests/fuzz
 *   clang -O1 -g -fsanitize=fuzzer,address,undefined -I ../../shared \
 *       fuzz_tar_header.c ../../shared/oci/tar.c ../../shared/oci/tar_pax.c \
 *       ../../shared/cvmfs/catalog/catalog_write.c \
 *       ../../shared/cvmfs/catalog/catalog.c ../../shared/cvmfs/grammar/hash.c \
 *       -lz -lsqlite3 -lcrypto -o fuzz_tar_header
 *   ./fuzz_tar_header -runs=200000 corpus_tar_header/
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "oci/tar.h"

#define MAX_ENTRIES 4096
#define MAX_BODY    (8u << 20)

/* gzip / zstd magic: a compressed stream can expand without bound, so the
 * diff-id drain is only run over an archive whose length we can see. */
static int raw_archive(const uint8_t *d, size_t n)
{
    if (n >= 2 && d[0] == 0x1f && d[1] == 0x8b) {
        return 0;
    }
    return !(n >= 4 && d[0] == 0x28 && d[1] == 0xb5 && d[2] == 0x2f
             && d[3] == 0xfd);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    brix_tar_entry_t  e;
    brix_tar_t       *t;
    char              err[256];
    char              buf[8192];
    char              hex[65];
    size_t            drained = 0;
    int               fd, n, entries = 0, walked = 0;

    if (size > 1u << 20) {
        return 0;
    }

    fd = memfd_create("layer", MFD_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    if (size && write(fd, data, size) != (ssize_t) size) {
        close(fd);
        return 0;
    }
    lseek(fd, 0, SEEK_SET);

    t = brix_tar_open_fd(fd, err, sizeof(err));
    if (t == NULL) {
        assert(err[0] != '\0');       /* a refusal has to say why */
        close(fd);
        return 0;
    }
    assert(brix_tar_digest_enable(t) == 0);

    while (entries++ < MAX_ENTRIES && (walked = brix_tar_next(t, &e)) == 1) {
        assert(memchr(e.path, '\0', sizeof(e.path)) != NULL);
        assert(memchr(e.linkname, '\0', sizeof(e.linkname)) != NULL);
        assert(e.size >= 0);
        assert(e.xattr != NULL || e.xattr_len == 0);

        while ((n = brix_tar_read(t, buf, sizeof(buf))) > 0) {
            drained += (size_t) n;
            if (drained > MAX_BODY) {
                break;                /* a legal tar may describe forever */
            }
        }
        if (n < 0 || drained > MAX_BODY) {
            break;
        }
    }

    assert(brix_tar_error(t) != NULL);

    if (walked == 0 && raw_archive(data, size)
        && brix_tar_digest_finish(t, hex, sizeof(hex)) == 0) {
        size_t i;

        assert(strlen(hex) == 64);
        for (i = 0; i < 64; i++) {
            assert((hex[i] >= '0' && hex[i] <= '9')
                   || (hex[i] >= 'a' && hex[i] <= 'f'));
        }
    }
    brix_tar_close(t);
    close(fd);
    return 0;
}

/* Persisted checksum metadata must remain fresh, locked and byte-preserving. */
#include "core/compat/integrity_info_internal.h"
#include "fs/meta/xmeta_path.h"
#include "platform/platform_api.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    const char *fault;
    unsigned locks, unlocks, saves;
    int sidecar;
} fixture;

/* WHAT: Recover the isolated fault context. WHY: Metadata operations retain real ownership.
 * HOW: Read the explicit fixture pointer from the process environment. */
static fixture *state(void)
{
    void *pointer = NULL; const char *text = getenv("BRIX_INTEGRITY_RECORD_FIXTURE");
    if (text) { assert(sscanf(text, "%p", &pointer) == 1); }
    return pointer;
}

/* WHAT: Select a fault. WHY: Setup and verification must use normal storage operations.
 * HOW: Match the active label only inside the target operation. */
static int fault(const char *name)
{
    fixture *f = state(); return f && f->fault && !strcmp(f->fault, name);
}

int __real_brix_xmeta_path_load(const char *, brix_xmeta_t *);
int __real_brix_xmeta_path_save(const char *, const brix_xmeta_t *);
int __real_brix_xmeta_path_lock(const char *);
void __real_brix_xmeta_path_unlock(int);
int __real_brix_xmeta_init(brix_xmeta_t *, int64_t, int64_t);
int __real_brix_xmeta_digest_set(brix_xmeta_t *, uint16_t, const void *, uint16_t);
ssize_t __real_getxattr(const char *, const char *, void *, size_t);
int __real_setxattr(const char *, const char *, const void *, size_t, int);

/* WHAT: Exercise the sidecar carrier. WHY: Filesystems may refuse user xattrs.
 * HOW: Refuse only xattr access; real sidecar encoding and I/O remain active. */
ssize_t __wrap_getxattr(const char *path, const char *name, void *value, size_t size)
{
    if (state()->sidecar) { errno = ENOTSUP; return -1; }
    return __real_getxattr(path, name, value, size);
}

/* WHAT: Select the sidecar write path. WHY: Fallback must preserve the same record contract.
 * HOW: Return the supported absence error before the real carrier handles the write. */
int __wrap_setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
    if (state()->sidecar) { errno = ENOTSUP; return -1; }
    return __real_setxattr(path, name, value, size, flags);
}

/* WHAT: Refuse record reads. WHY: A hard load error must not overwrite stored metadata.
 * HOW: Retain real decoding except at the selected fault boundary. */
int __wrap_brix_xmeta_path_load(const char *path, brix_xmeta_t *record)
{
    if (fault("load")) { errno = EIO; return BRIX_XMETA_ERR; }
    return __real_brix_xmeta_path_load(path, record);
}

/* WHAT: Observe record writes. WHY: Failure must remain best effort without changing file bytes.
 * HOW: Count saves and optionally refuse before touching persistent storage. */
int __wrap_brix_xmeta_path_save(const char *path, const brix_xmeta_t *record)
{
    state()->saves++;
    if (fault("save")) { errno = ENOSPC; return BRIX_XMETA_ERR; }
    return __real_brix_xmeta_path_save(path, record);
}

/* WHAT: Acquire real metadata locks. WHY: Every successful acquisition needs one release.
 * HOW: Refuse the chosen lock or count a real returned descriptor. */
int __wrap_brix_xmeta_path_lock(const char *path)
{
    if (fault("lock")) { errno = EACCES; return -1; }
    int fd = __real_brix_xmeta_path_lock(path); if (fd >= 0) { state()->locks++; }
    return fd;
}

/* WHAT: Observe lock release. WHY: Partial allocation paths must not leak descriptors.
 * HOW: Verify ownership and call the real unlock/close. */
void __wrap_brix_xmeta_path_unlock(int fd)
{
    assert(fd >= 0 && fcntl(fd, F_GETFD) >= 0); state()->unlocks++;
    __real_brix_xmeta_path_unlock(fd);
    assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
}

/* WHAT: Refuse initialization of a foreign record. WHY: Failed allocation cannot publish an empty digest.
 * HOW: Fail only the explicit initialization scenario. */
int __wrap_brix_xmeta_init(brix_xmeta_t *record, int64_t size, int64_t granule)
{
    if (fault("init")) { errno = ENOMEM; return BRIX_XMETA_ERR; }
    return __real_brix_xmeta_init(record, size, granule);
}

/* WHAT: Refuse digest replacement. WHY: A failed in-memory update must not be persisted.
 * HOW: Return the metadata error while leaving all other paths real. */
int __wrap_brix_xmeta_digest_set(brix_xmeta_t *record, uint16_t algorithm,
                                const void *value, uint16_t length)
{
    if (fault("digest")) { errno = ENOMEM; return BRIX_XMETA_ERR; }
    return __real_brix_xmeta_digest_set(record, algorithm, value, length);
}

/* WHAT: Validate a fresh persisted digest. WHY: Cache lookup must be exact and freshness-bound.
 * HOW: Read through the public record fallback and compare the full caller value. */
static void expect_digest(const char *path, const char *algorithm, const char *hex)
{
    brix_integrity_info_t value = {0};
    assert(integrity_record_read(path, algorithm, &value) == 1);
    assert(value.from_cache == 1 && !strcmp(value.hex, hex));
}

/* WHAT: Verify successful replacement preserves unrelated metadata.
 * WHY: The digest list is shared with other algorithms and record ownership fields.
 * HOW: Seed a second algorithm, replace the requested digest and read both back. */
static void check_roundtrip(const char *path, const char *algorithm, const char *hex)
{
    integrity_record_write(path, algorithm, hex); expect_digest(path, algorithm, hex);
    const char *other = !strcmp(algorithm, "md5") ? "sha1" : "md5";
    integrity_record_write(path, other, "aabbccdd");
    integrity_record_write(path, algorithm, hex); expect_digest(path, algorithm, hex);
    expect_digest(path, other, "aabbccdd");
    brix_xmeta_t record; assert(brix_xmeta_path_load(path, &record) == BRIX_XMETA_OK);
    assert(record.file_size == 4097 && record.have_blockcrc == 0);
    brix_xmeta_free(&record);
}

/* WHAT: Keep failed updates from replacing a valid cache entry.
 * WHY: Best-effort cache writes must not damage the live data or old metadata.
 * HOW: Inject one ownership boundary, then read with faults disabled. */
static void check_write_failure(fixture *f, const char *path, const char *mode)
{
    int fresh = !strcmp(mode, "init");
    if (!fresh) { integrity_record_write(path, "sha256", "abcd"); }
    unsigned before = f->saves; f->fault = mode;
    integrity_record_write(path, "sha256", "deadbeef"); f->fault = NULL;
    assert(f->locks == f->unlocks);
    if (fresh) {
        brix_integrity_info_t value = {0}; assert(integrity_record_read(path, "sha256", &value) == 0);
    } else { expect_digest(path, "sha256", "abcd"); }
    assert(f->saves == before + (unsigned) !strcmp(mode, "save"));
}

/* WHAT: Refuse stale and malformed records. WHY: A checksum is valid only for its recorded file state.
 * HOW: Change size or timestamps, or install an invalid digest payload, then require a cache miss. */
static void check_read_refusal(const char *path, const char *mode)
{
    integrity_record_write(path, "sha256", "abcd");
    if (!strcmp(mode, "size")) { assert(truncate(path, 4096) == 0); }
    else if (!strcmp(mode, "mtime")) {
        struct timespec times[2] = {{.tv_sec = 12345}, {.tv_sec = 12345, .tv_nsec = 1}};
        assert(utimensat(AT_FDCWD, path, times, 0) == 0);
    } else {
        brix_xmeta_t record; assert(brix_xmeta_path_load(path, &record) == BRIX_XMETA_OK);
        char invalid[256]; memset(invalid, 'x', sizeof(invalid));
        uint16_t length = !strcmp(mode, "oversize") ? 256 : 8;
        if (!strcmp(mode, "empty")) { length = 0; }
        assert(brix_xmeta_digest_set(&record, BRIX_XMETA_ALG_SHA256, invalid, length) == BRIX_XMETA_OK);
        assert(brix_xmeta_path_save(path, &record) == BRIX_XMETA_OK); brix_xmeta_free(&record);
    }
    brix_integrity_info_t value = {0}; strcpy(value.hex, "untouched");
    assert(integrity_record_read(path, "sha256", &value) == 0);
    assert(!value.from_cache && !strcmp(value.hex, "untouched"));
}

/* WHAT: Reject unusable write inputs. WHY: Cache bookkeeping must not create work for absent data.
 * HOW: Exercise null, unknown algorithm and overlong value paths with zero saves. */
static void check_inputs(fixture *f, const char *path)
{
    char long_value[1024]; memset(long_value, 'a', sizeof(long_value) - 1); long_value[1023] = 0;
    integrity_record_write(NULL, "sha256", "abcd");
    integrity_record_write(path, "unknown", "abcd");
    integrity_record_write(path, "sha256", long_value);
    brix_integrity_info_t value = {0}; assert(integrity_record_read(NULL, "sha256", &value) == 0);
    assert(integrity_record_read(path, "unknown", &value) == 0);
    assert(f->locks == 0 && f->saves == 0);
}

/* WHAT: Alter one binary-record boundary. WHY: Invalid fields need independent rejection checks.
 * HOW: Change the documented length byte, total record size or comparison timestamp. */
static time_t alter_binary_record(const char *mode, unsigned char *wire, size_t *length)
{
    /* Repository-defined record: Name[16], fmTime[8], csTime[4], reserved[3], Length[1]. */
    if (!strcmp(mode, "zero-length")) { wire[31] = 0; }
    if (!strcmp(mode, "negative-length")) { wire[31] = 255; }
    if (!strcmp(mode, "oversize-length")) { wire[31] = 65; }
    if (!strcmp(mode, "truncated")) { (*length)--; }
    if (!strcmp(mode, "stale")) { return 12346; }
    return !strcmp(mode, "ignore-time") ? 0 : 12345;
}

/* WHAT: Validate the binary checksum record's trust boundaries.
 * WHY: Short, stale and impossible-length records must not become cache hits.
 * HOW: Encode a known value, alter one documented field and inspect output canaries. */
static void check_binary(const char *mode)
{
    brix_integrity_info_t input = {0}, output = {0}; unsigned char wire[128];
    strcpy(input.alg_name, "sha256"); strcpy(input.hex, "01aBcDeF");
    if (!strcmp(mode, "full")) { memset(input.hex, 'A', 128); input.hex[128] = 0; }
    if (!strcmp(mode, "invalid-hex")) { strcpy(input.hex, "01gz"); }
    memset(wire, 0xcc, sizeof(wire));
    size_t length = brix_cksdata_encode(&input, 12345, wire);
    if (!strcmp(mode, "invalid-hex")) {
        assert(length == 0);
        for (unsigned i = 0; i < sizeof(wire); i++) { assert(wire[i] == 0xcc); }
        return;
    }
    assert(length == 96 && wire[96] == 0xcc);
    time_t timestamp = alter_binary_record(mode, wire, &length);
    strcpy(output.hex, "unchanged"); strcpy(output.alg_name, "unchanged");
    int valid = !strcmp(mode, "valid") || !strcmp(mode, "full") || !strcmp(mode, "ignore-time");
    assert(brix_cksdata_decode(wire, length, timestamp, &output) == valid);
    if (!valid) { assert(!output.from_cache && !strcmp(output.hex, "unchanged")); return; }
    assert(output.from_cache && !strcmp(output.alg_name, "sha256"));
    if (!strcmp(mode, "full")) {
        assert(strlen(output.hex) == 128);
        for (unsigned i = 0; i < 128; i++) { assert(output.hex[i] == 'a'); }
    } else { assert(!strcmp(output.hex, "01abcdef")); }
}

/* WHAT: Run a persisted-integrity contract. WHY: Each file and fault context is independently owned.
 * HOW: Use caller-created data, real carrier locks and one selected scenario. */
int main(int argc, char **argv)
{
    assert(argc == 6); fixture f = {.sidecar = atoi(argv[5])}; char pointer[64];
    snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_INTEGRITY_RECORD_FIXTURE", pointer, 1) == 0);
    if (!strcmp(argv[1], "roundtrip")) { check_roundtrip(argv[2], argv[3], argv[4]); }
    else if (!strcmp(argv[1], "failure")) { check_write_failure(&f, argv[2], argv[3]); }
    else if (!strcmp(argv[1], "refusal")) { check_read_refusal(argv[2], argv[3]); }
    else if (!strcmp(argv[1], "binary")) { check_binary(argv[3]); }
    else { assert(!strcmp(argv[1], "inputs")); check_inputs(&f, argv[2]); }
    assert(f.locks == f.unlocks); assert(unsetenv("BRIX_INTEGRITY_RECORD_FIXTURE") == 0);
    puts("integrity record verified"); return 0;
}

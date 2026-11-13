/* CSI publication preserves metadata and never invents checksum coverage. */
#include "core/ngx_brix_module.h"
#include "fs/backend/csi_tagstore.h"
#include "fs/meta/xmeta_path.h"
#include "core/compat/crc32c.h"
#include <assert.h>

#define GRANULE 4096u
typedef struct {
    const char *mode;
    int active, allocation_armed;
    unsigned reads, locks, unlocks, saves;
} fixture;

/* WHAT: Recover the fault fixture. WHY: Each injected error belongs to one process.
 * HOW: Decode its owned environment pointer. */
static fixture *state(void)
{
    const char *value = getenv("BRIX_CSI_RECORD_FIXTURE"); void *pointer = NULL;
    if (value != NULL) { assert(sscanf(value, "%p", &pointer) == 1); }
    return pointer;
}

/* WHAT: Select an active fault. WHY: File and metadata setup must use real operations.
 * HOW: Require both the operation phase and matching label. */
static int fault(const char *name)
{
    fixture *f = state(); return f && f->active && !strcmp(f->mode, name);
}

int __real_brix_xmeta_path_load(const char *, brix_xmeta_t *);
int __real_brix_xmeta_path_save(const char *, const brix_xmeta_t *);
int __real_brix_xmeta_path_lock(const char *);
void __real_brix_xmeta_path_unlock(int);
int __real_brix_xmeta_init(brix_xmeta_t *, int64_t, int64_t);
void *__real_realloc(void *, size_t);
void *__real_calloc(size_t, size_t);
void *__real_malloc(size_t);
ssize_t __real_pread64(int, void *, size_t, off_t);

/* WHAT: Refuse or omit record coverage. WHY: CSI must handle absent tables and I/O errors.
 * HOW: Preserve the real carrier except for the selected return or owned CRC table. */
int __wrap_brix_xmeta_path_load(const char *path, brix_xmeta_t *record)
{
    if (fault("load")) { errno = EIO; return BRIX_XMETA_ERR; }
    int rc = __real_brix_xmeta_path_load(path, record);
    if (rc == BRIX_XMETA_OK && (fault("no-crcs") || fault("crc-alloc"))) {
        free(record->blockcrc); record->blockcrc = NULL; record->have_blockcrc = 0;
        state()->allocation_armed = 1;
    }
    return rc;
}

/* WHAT: Observe publication. WHY: Failed saves must retain the dirty handle.
 * HOW: Refuse the selected save, otherwise persist through the real carrier. */
int __wrap_brix_xmeta_path_save(const char *path, const brix_xmeta_t *record)
{
    if (state() && state()->active) { state()->saves++; }
    if (fault("save")) { errno = ENOSPC; return BRIX_XMETA_ERR; }
    return __real_brix_xmeta_path_save(path, record);
}

/* WHAT: Acquire the real record lock or refuse it. WHY: No publication may bypass locking.
 * HOW: Count successful ownership only. */
int __wrap_brix_xmeta_path_lock(const char *path)
{
    if (fault("lock")) { errno = EACCES; return -1; }
    int fd = __real_brix_xmeta_path_lock(path);
    if (fd >= 0 && state() && state()->active) { state()->locks++; }
    return fd;
}

/* WHAT: Release lock ownership. WHY: Every acquired lock must unwind once.
 * HOW: Count and forward the real unlock. */
void __wrap_brix_xmeta_path_unlock(int fd)
{
    if (state() && state()->active) { state()->unlocks++; }
    __real_brix_xmeta_path_unlock(fd);
}

/* WHAT: Refuse geometry allocation. WHY: Resize failure must preserve old metadata.
 * HOW: Fail only during the flush phase. */
int __wrap_brix_xmeta_init(brix_xmeta_t *record, int64_t size, int64_t granule)
{
    if (fault("init")) { errno = ENOMEM; return BRIX_XMETA_ERR; }
    return __real_brix_xmeta_init(record, size, granule);
}

/* WHAT: Refuse folded-table growth. WHY: Overflow must fall back to bounded verification.
 * HOW: Fail the active update's realloc. */
void *__wrap_realloc(void *pointer, size_t size)
{
    if (fault("fold-alloc")) { errno = ENOMEM; return NULL; }
    return __real_realloc(pointer, size);
}

/* WHAT: Refuse a missing CRC table. WHY: No record may claim coverage without storage.
 * HOW: Arm this allocation only after loading the owned record. */
void *__wrap_calloc(size_t count, size_t size)
{
    if (fault("crc-alloc") && state()->allocation_armed && size == sizeof(uint32_t)) {
        errno = ENOMEM; return NULL;
    }
    return __real_calloc(count, size);
}

/* WHAT: Refuse readback scratch storage. WHY: Unverified blocks must remain unset.
 * HOW: Match only the configured block-sized buffer. */
void *__wrap_malloc(size_t size)
{
    if (fault("scratch-alloc") && size == GRANULE) { errno = ENOMEM; return NULL; }
    return __real_malloc(size);
}

/* WHAT: Interrupt or shorten readback. WHY: EINTR differs from unverifiable data.
 * HOW: Inject one interruption or a persistent short read before the real pread. */
ssize_t __wrap_pread64(int fd, void *buffer, size_t length, off_t offset)
{
    if (state() && state()->active) {
        state()->reads++;
        if (fault("eintr") && state()->reads == 1) { errno = EINTR; return -1; }
        if (fault("short")) { return 0; }
    }
    return __real_pread64(fd, buffer, length, offset);
}

/* WHAT: Seed actual file bytes and metadata. WHY: Geometry tests need a persisted predecessor.
 * HOW: Save a valid record with recognizable scalar and string metadata. */
static void seed_record(const char *path, size_t length)
{
    brix_xmeta_t record; assert(brix_xmeta_init(&record, length, GRANULE) == BRIX_XMETA_OK);
    record.creation_time = 77; record.access_cnt = 9; record.flush_gen = 17;
    record.bytes_flushed = 123; record.etag_len = 3; memcpy(record.etag, "tag", 3);
    assert(brix_xmeta_path_save(path, &record) == BRIX_XMETA_OK); brix_xmeta_free(&record);
}

/* WHAT: Assert persisted coverage. WHY: Flush may leave explicit gaps but never false CRCs.
 * HOW: Compare every present checksum to actual bytes and inspect metadata preservation. */
static void check_record(const char *path, const unsigned char *bytes, size_t length,
                         unsigned covered, int seeded)
{
    brix_xmeta_t record; assert(brix_xmeta_path_load(path, &record) == BRIX_XMETA_OK);
    assert(record.file_size == (int64_t) length && record.buffer_size == GRANULE);
    assert(record.nblocks == length / GRANULE && record.have_blockcrc);
    for (unsigned index = 0; index < record.nblocks; index++) {
        uint32_t expected = index < covered ? brix_crc32c_value(bytes + index * GRANULE, GRANULE) : 0;
        assert(record.blockcrc[index] == expected);
    }
    assert((record.no_cksum_time != 0) == (covered < record.nblocks));
    if (seeded) {
        assert(record.creation_time == 77 && record.access_cnt == 9 && record.flush_gen == 17);
        assert(record.bytes_flushed == 123 && record.etag_len == 3 && !memcmp(record.etag, "tag", 3));
    }
    brix_xmeta_free(&record);
}

/* WHAT: Verify read-after-write and partial-block semantics. WHY: Dirty CRCs are stale.
 * HOW: Use a real write handle's uncached record and mutate only the supplied read bytes. */
static void check_read(const char *path, unsigned char *bytes, size_t length)
{
    brix_csi_t reader; assert(brix_csi_open(&reader, path, GRANULE, 1) == BRIX_CSI_OK);
    assert(brix_csi_verify_read(&reader, bytes, 0, length) == BRIX_CSI_OK);
    bytes[0] ^= 1;
    assert(brix_csi_verify_read(&reader, bytes, 0, length) == BRIX_CSI_MISMATCH);
    assert(brix_csi_verify_read(&reader, bytes, 0, 1) == BRIX_CSI_OK);
    assert(brix_csi_write_update(&reader, bytes, 0, 1) == BRIX_CSI_OK);
    assert(brix_csi_verify_read(&reader, bytes, 0, length) == BRIX_CSI_OK);
    reader.dirty = 0; brix_csi_close(&reader); bytes[0] ^= 1;
}

/* WHAT: Run actual publication with one failure. WHY: Dirty state is retained until saved.
 * HOW: Use owned bytes and a real metadata carrier, then inspect all tags and lock counts. */
static void check_flush(fixture *f, const char *path, unsigned blocks, unsigned original)
{
    size_t length = (size_t) blocks * GRANULE; unsigned char *bytes = malloc(length); assert(bytes);
    memset(bytes, 0x5a, length); int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600); assert(fd >= 0);
    assert(write(fd, bytes, length) == (ssize_t) length);
    if (original) { seed_record(path, (size_t) original * GRANULE); }
    brix_csi_t writer; assert(brix_csi_open(&writer, path, GRANULE, 1) == BRIX_CSI_OK);
    f->active = !strcmp(f->mode, "fold-alloc");
    assert(brix_csi_write_update(&writer, bytes, 0, length) == BRIX_CSI_OK);
    f->active = 0;
    /* Force readback for the whole extent; the fold-allocation case does this itself. */
    if (strcmp(f->mode, "fold") != 0) { free(writer.local); writer.local = NULL; writer.local_n = 0; }
    f->active = 1; int rc = brix_csi_flush_bound(&writer, fd); f->active = 0;
    int failed = !strcmp(f->mode, "load") || !strcmp(f->mode, "save")
        || !strcmp(f->mode, "lock") || !strcmp(f->mode, "init") || !strcmp(f->mode, "crc-alloc");
    assert(rc == (failed ? BRIX_CSI_ERR : BRIX_CSI_OK) && writer.dirty == (unsigned) failed);
    assert(f->locks == f->unlocks);
    if (!failed) {
        unsigned covered = blocks < BRIX_CSI_FLUSH_READ ? blocks : BRIX_CSI_FLUSH_READ;
        if (!strcmp(f->mode, "fold")) { covered = blocks; }
        if (!strcmp(f->mode, "short") || !strcmp(f->mode, "scratch-alloc")) { covered = 0; }
        check_record(path, bytes, length, covered, original != 0);
        if (covered == blocks) { check_read(path, bytes, length); }
    }
    writer.dirty = 0; brix_csi_close(&writer); assert(close(fd) == 0); free(bytes);
}

/* WHAT: Check invalid inputs and the local-table ceiling. WHY: Refusal must be bounded.
 * HOW: Call the public CSI API without any filesystem operation or huge allocation. */
static void check_invalid(const char *mode)
{
    brix_csi_t writer = {0}; writer.granule = GRANULE; unsigned char bytes[GRANULE] = {0};
    if (!strcmp(mode, "cap")) {
        assert(brix_csi_write_update(&writer, bytes, (off_t) GRANULE * BRIX_CSI_LOCAL_MAX,
                                    GRANULE) == BRIX_CSI_OK);
        assert(writer.overflow && writer.local == NULL && writer.dirty); return;
    }
    assert(brix_csi_verify_read(NULL, bytes, 0, 1) == BRIX_CSI_ERR && errno == EINVAL);
    assert(brix_csi_verify_read(&writer, NULL, 0, 1) == BRIX_CSI_ERR);
    assert(brix_csi_verify_read(&writer, bytes, -1, 1) == BRIX_CSI_ERR);
    assert(brix_csi_write_update(NULL, bytes, 0, 1) == BRIX_CSI_ERR);
    assert(brix_csi_write_update(&writer, NULL, 0, 1) == BRIX_CSI_ERR);
    assert(brix_csi_write_update(&writer, bytes, -1, 1) == BRIX_CSI_ERR);
    assert(brix_csi_write_update(&writer, NULL, 0, 0) == BRIX_CSI_OK && !writer.dirty);
    assert(brix_csi_flush(NULL) == BRIX_CSI_ERR && brix_csi_flush(&writer) == BRIX_CSI_ERR);
    assert(brix_csi_flush_bound(&writer, -1) == BRIX_CSI_ERR);
}

/* WHAT: Run a bounded checksum scenario. WHY: All fixtures own their disk paths and state.
 * HOW: Dispatch publication or input validation, then clear the private fault pointer. */
int main(int argc, char **argv)
{
    assert(argc == 5); fixture f = {0}; f.mode = argv[1]; char pointer[64];
    ngx_cycle_t cycle = {0}; ngx_log_t log = {0}; cycle.log = &log; ngx_cycle = &cycle;
    snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_CSI_RECORD_FIXTURE", pointer, 1) == 0);
    if (!strcmp(f.mode, "invalid") || !strcmp(f.mode, "cap")) { check_invalid(f.mode); }
    else { check_flush(&f, argv[2], (unsigned) atoi(argv[3]), (unsigned) atoi(argv[4])); }
    assert(unsetenv("BRIX_CSI_RECORD_FIXTURE") == 0);
    puts("checksum record contract verified"); return 0;
}

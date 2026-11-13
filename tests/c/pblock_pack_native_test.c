/* Real packed arenas: durable admission, verified reads, and failed recovery. */
#include "fs/backend/pblock/pblock_store.h"
#include "fs/backend/pblock/pblock_pack.h"
#include "fs/backend/pblock/pblock_pack_internal.h"
#include "fs/backend/pblock/sd_pblock_catalog_internal.h"
#include "cache/cas_pack_format.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

void *__real_malloc(size_t size);
ssize_t __real_pread64(int fd, void *buf, size_t n, off_t off);
ssize_t __real_pwrite64(int fd, const void *buf, size_t n, off_t off);
int __real_fstat64(int fd, struct stat *st);
int __real_flock(int fd, int operation);
int __real_brix_plat_fsync_data(int fd);
int __real_brix_plat_anon_fd(const char *name, const char *dir);
int __real_sqlite3_prepare_v2(sqlite3 *db, const char *sql, int n,
                            sqlite3_stmt **stmt, const char **tail);

/* WHAT: Select the active operation fault.
 * WHY: Keep failure state local to this fixture process.
 * HOW: Compare the explicitly armed environment value. */
static int fault(const char *name)
{
    const char *value = getenv("BRIX_PACK_TEST_FAULT");
    return value != NULL && strcmp(value, name) == 0;
}

/* WHAT: Refuse the arena buffer allocation.
 * WHY: Allocation errors must preserve existing storage.
 * HOW: Inject ENOMEM only while armed; otherwise allocate normally. */
void *__wrap_malloc(size_t size)
{
    if (fault("allocation")) { errno = ENOMEM; return NULL; }
    return __real_malloc(size);
}

/* WHAT: Inject interrupted, partial or failed reads.
 * WHY: The packed-record reader must handle each libc outcome.
 * HOW: Consume one EINTR or limit the real read length, retaining real bytes. */
ssize_t __wrap_pread64(int fd, void *buf, size_t n, off_t off)
{
    if (fault("read")) { errno = EIO; return -1; }
    if (fault("read-eintr")) {
        assert(unsetenv("BRIX_PACK_TEST_FAULT") == 0);
        errno = EINTR; return -1;
    }
    if (fault("read-short") && n > 3) { n = 3; }
    return __real_pread64(fd, buf, n, off);
}

/* WHAT: Inject interrupted, partial or failed writes.
 * WHY: Admission must either persist a record or retain the source.
 * HOW: Consume one EINTR, limit the real write, or report ENOSPC. */
ssize_t __wrap_pwrite64(int fd, const void *buf, size_t n, off_t off)
{
    if (fault("write")) { errno = ENOSPC; return -1; }
    if (fault("write-eintr")) {
        assert(unsetenv("BRIX_PACK_TEST_FAULT") == 0);
        errno = EINTR; return -1;
    }
    if (fault("write-short") && n > 3) { n = 3; }
    return __real_pwrite64(fd, buf, n, off);
}

/* WHAT: Refuse segment metadata discovery.
 * WHY: A failed stat cannot establish a safe append position.
 * HOW: Inject EIO during admission; otherwise use the real descriptor. */
int __wrap_fstat64(int fd, struct stat *st)
{
    if (fault("stat")) { errno = EIO; return -1; }
    return __real_fstat64(fd, st);
}

/* WHAT: Refuse acquisition of the arena lock.
 * WHY: Unserialized admission must not modify a segment.
 * HOW: Inject EIO only for the selected lock failure. */
int __wrap_flock(int fd, int operation)
{
    if (fault("lock")) { errno = EIO; return -1; }
    return __real_flock(fd, operation);
}

/* WHAT: Refuse durable synchronization.
 * WHY: Unsynced records must not replace the striped source.
 * HOW: Report EIO at the existing PAL seam while armed. */
int __wrap_brix_plat_fsync_data(int fd)
{
    if (fault("sync")) { errno = EIO; return -1; }
    return __real_brix_plat_fsync_data(fd);
}

/* WHAT: Refuse the anonymous read handle.
 * WHY: Resource exhaustion must preserve the packed record.
 * HOW: Inject EMFILE at the PAL allocation boundary. */
int __wrap_brix_plat_anon_fd(const char *name, const char *dir)
{
    if (fault("anon")) { errno = EMFILE; return -1; }
    return __real_brix_plat_anon_fd(name, dir);
}

/* WHAT: Refuse preparation of the pack-row insertion.
 * WHY: An unindexed append must not remove the original stripes.
 * HOW: Match only the insert statement and retain all other SQL operations. */
int __wrap_sqlite3_prepare_v2(sqlite3 *db, const char *sql, int n,
                            sqlite3_stmt **stmt, const char **tail)
{
    if (fault("catalog-insert") && strstr(sql, "INSERT OR REPLACE INTO pack")) {
        *stmt = NULL; return SQLITE_IOERR;
    }
    return __real_sqlite3_prepare_v2(db, sql, n, stmt, tail);
}

/* WHAT: Create a known striped payload.
 * WHY: Every recovery check needs independently known bytes.
 * HOW: Create the real object directory and write through the block engine. */
static void seed(pblock_state_t *st, pblock_meta *meta)
{
    strcpy(meta->blob_id, "0123456789abcdef0123456789abcdef");
    meta->size = 7; meta->block_size = 4096;
    assert(pblock_ensure_obj_dir(st, meta->blob_id) == 0);
    assert(pblock_write_blocks(st, meta->blob_id, 4096, -1, "payload", 7, 0) == 7);
}

/* WHAT: Pack the seeded payload.
 * WHY: Later tests require a durable, indexed baseline record.
 * HOW: Call the production admission function and require success. */
static void admit(pblock_state_t *st, const pblock_meta *meta)
{
    assert(pblock_pack_admit(st, meta->blob_id, meta->size, 4096) == 0);
}

/* WHAT: Read and compare the complete packed payload.
 * WHY: A passing status alone cannot prove data preservation.
 * HOW: Open the real verified handle, read fully and compare every byte. */
static void verify(pblock_state_t *st, const pblock_meta *meta)
{
    char data[8] = {0};
    int fd = pblock_pack_open_memfd(st, meta);
    assert(fd >= 0 && pack_pread_full(fd, data, 7, 0) == 0);
    assert(memcmp(data, "payload", 7) == 0);
    assert(close(fd) == 0);
}

/* WHAT: Find the physical segment for a known record.
 * WHY: Corruption must affect exactly the record under test.
 * HOW: Resolve its real catalog row and format its arena path. */
static void segment(pblock_state_t *st, const pblock_meta *meta, char *path)
{
    pblock_pack_loc_t loc;
    assert(pblock_pack_find(st, meta->blob_id, &loc) == 0);
    assert(pack_seg_path(st, loc.seg, path, PATH_MAX) == 0);
}

/* WHAT: Check packed range boundaries.
 * WHY: Partial reads must clamp EOF and refuse negative offsets.
 * HOW: Read a middle suffix, EOF and an empty range against known bytes. */
static void read_ranges(pblock_state_t *st, const pblock_meta *meta)
{
    char data[20] = {0};
    assert(pblock_pack_or_block_read(st, meta->blob_id, 4096, data, 20, -1) == -1);
    assert(errno == EINVAL);
    assert(pblock_pack_or_block_read(st, meta->blob_id, 4096, data, 20, 2) == 5);
    assert(memcmp(data, "yload", 5) == 0);
    assert(pblock_pack_or_block_read(st, meta->blob_id, 4096, data, 20, 7) == 0);
    assert(pblock_pack_or_block_read(st, meta->blob_id, 4096, data, 0, 1) == 0);
}

/* WHAT: Exercise successful admission and materialization.
 * WHY: Interrupted or short I/O must not alter the payload.
 * HOW: Arm the fault at its intended phase, verify both layouts and ownership. */
static void roundtrip(pblock_state_t *st, const pblock_meta *meta, const char *kind)
{
    int read_fault = strncmp(kind, "read-", 5) == 0;
    if (read_fault) { admit(st, meta); }
    assert(setenv("BRIX_PACK_TEST_FAULT", kind, 1) == 0);
    if (!read_fault) { admit(st, meta); }
    verify(st, meta);
    read_ranges(st, meta);
    assert(unsetenv("BRIX_PACK_TEST_FAULT") == 0);
    assert(pblock_pack_materialize(st, meta) == 0);
    char data[8] = {0};
    assert(pblock_read_blocks(st, meta->blob_id, 4096, -1, data, 7, 0) == 7);
    assert(memcmp(data, "payload", 7) == 0);
    assert(pblock_pack_materialize(st, meta) == 0);
    assert(pblock_pack_open_memfd(st, meta) == -1 && errno == ENOENT);
}

/* WHAT: Verify refused admission preserves stripes.
 * WHY: The original remains authoritative until both storage and catalog succeed.
 * HOW: Inject one failure, inspect the source and absent row, and check torn-tail rollback. */
static void admission_failure(pblock_state_t *st, const pblock_meta *meta,
                              const char *kind)
{
    assert(setenv("BRIX_PACK_TEST_FAULT", kind, 1) == 0);
    assert(pblock_pack_admit(st, meta->blob_id, 7, 4096) == -1);
    assert(unsetenv("BRIX_PACK_TEST_FAULT") == 0);
    char data[8] = {0};
    pblock_pack_loc_t loc;
    assert(pblock_read_blocks(st, meta->blob_id, 4096, -1, data, 7, 0) == 7);
    assert(memcmp(data, "payload", 7) == 0);
    assert(pblock_pack_find(st, meta->blob_id, &loc) == 1);
    if (strcmp(kind, "write") == 0 || strcmp(kind, "sync") == 0) {
        char path[PATH_MAX]; struct stat sb;
        assert(pack_seg_path(st, 1, path, sizeof(path)) == 0);
        assert(stat(path, &sb) == 0 && sb.st_size == 0);
    }
}

/* WHAT: Verify failed handle creation preserves the record.
 * WHY: Read failures must not destroy a recoverable copy.
 * HOW: Fail one read operation, clear the fault and read the original bytes. */
static void read_failure(pblock_state_t *st, const pblock_meta *meta, const char *kind)
{
    admit(st, meta);
    assert(setenv("BRIX_PACK_TEST_FAULT", kind, 1) == 0);
    assert(pblock_pack_open_memfd(st, meta) == -1);
    assert(unsetenv("BRIX_PACK_TEST_FAULT") == 0);
    verify(st, meta);
}

/* WHAT: Damage an explicitly owned record component.
 * WHY: Header, key and checksum failures need independent fixtures.
 * HOW: Remove, truncate or flip one byte in the private arena file. */
static void corrupt_segment(const char *path, const char *kind)
{
    if (strcmp(kind, "missing") == 0) { assert(unlink(path) == 0); return; }
    int fd = open(path, O_RDWR);
    assert(fd >= 0);
    if (strcmp(kind, "short-header") == 0) { assert(ftruncate(fd, 1) == 0); }
    else if (strcmp(kind, "short-body") == 0) {
        assert(ftruncate(fd, SEG_HDR + 32 + 3) == 0);
    } else {
        off_t offset = 0;
        if (strcmp(kind, "key") == 0) { offset = SEG_HDR; }
        if (strcmp(kind, "crc") == 0) { offset = SEG_HDR + 32; }
        unsigned char value;
        assert(pread(fd, &value, 1, offset) == 1);
        value ^= 0xff;
        assert(pwrite(fd, &value, 1, offset) == 1);
    }
    assert(close(fd) == 0);
}

/* WHAT: Refuse corrupted bytes in both materialization paths.
 * WHY: Corruption must not become a readable handle or ordinary stripes.
 * HOW: Damage one record, require EIO and retain its catalog row. */
static void damaged_record(pblock_state_t *st, pblock_meta *meta, const char *kind)
{
    char path[PATH_MAX]; pblock_pack_loc_t loc;
    admit(st, meta); segment(st, meta, path);
    if (strcmp(kind, "size") == 0) { ++meta->size; }
    else { corrupt_segment(path, kind); }
    assert(pblock_pack_open_memfd(st, meta) == -1 && errno == EIO);
    assert(pblock_pack_materialize(st, meta) == -1 && errno == EIO);
    assert(pblock_pack_find(st, meta->blob_id, &loc) == 0);
    if (strcmp(kind, "missing") == 0 || strcmp(kind, "short-body") == 0) {
        char data[8];
        assert(pblock_pack_or_block_read(st, meta->blob_id, 4096, data, 7, 0) == -1);
        assert(errno == EIO);
    }
}

/* WHAT: Verify failed recovery keeps the packed copy.
 * WHY: A failed directory or block write cannot consume the source.
 * HOW: Block recovery, verify the packed bytes, then recover successfully. */
static void materialize_failure(pblock_state_t *st, const pblock_meta *meta,
                                const char *kind)
{
    admit(st, meta);
    char path[PATH_MAX];
    if (strcmp(kind, "directory") == 0) {
        assert(pblock_ensure_obj_dir(st, meta->blob_id) == 0);
        assert(pblock_obj_dir(st, meta->blob_id, path, sizeof(path)) == 0);
        assert(rmdir(path) == 0);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0 && close(fd) == 0);
    }
    assert(setenv("BRIX_PACK_TEST_FAULT", kind, 1) == 0);
    assert(pblock_pack_materialize(st, meta) == -1);
    assert(unsetenv("BRIX_PACK_TEST_FAULT") == 0);
    verify(st, meta);
    if (strcmp(kind, "directory") == 0) { assert(unlink(path) == 0); }
    assert(pblock_pack_materialize(st, meta) == 0);
}

/* WHAT: Reject invalid arena inputs and honor disabled packing.
 * WHY: Caller errors must not reach data mutation.
 * HOW: Pass absent keys, invalid sizes and an oversized key; check disabled no-ops. */
static void invalid_inputs(pblock_state_t *st, const pblock_meta *meta)
{
    pblock_pack_loc_t loc;
    char long_key[300]; memset(long_key, 'x', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = 0;
    assert(pblock_pack_find(st, meta->blob_id, NULL) == -1 && errno == EINVAL);
    assert(pblock_pack_find(NULL, meta->blob_id, &loc) == -1 && errno == EINVAL);
    assert(pblock_pack_find(st, NULL, &loc) == -1 && errno == EINVAL);
    assert(pblock_pack_find(st, "", &loc) == -1 && errno == EINVAL);
    assert(pblock_pack_admit(st, meta->blob_id, 0, 4096) == -1 && errno == EINVAL);
    assert(pblock_pack_admit(st, "", 7, 4096) == -1 && errno == EINVAL);
    assert(pblock_pack_admit(st, long_key, 7, 4096) == -1 && errno == EINVAL);
    st->pack = 0;
    assert(pblock_pack_materialize(st, meta) == 0);
    pblock_pack_del(st, meta->blob_id);
}

/* WHAT: Reject corrupt or unavailable pack metadata.
 * WHY: A malformed row cannot safely locate bytes.
 * HOW: Damage the real SQLite table and require each reader to fail closed. */
static void catalog_failure(pblock_state_t *st, const pblock_meta *meta,
                            const char *statement)
{
    admit(st, meta);
    assert(cat_exec(st->cat, statement) == 0);
    pblock_pack_loc_t loc; char data[8];
    assert(pblock_pack_find(st, meta->blob_id, &loc) == -1 && errno == EIO);
    assert(pblock_pack_open_memfd(st, meta) == -1 && errno == EIO);
    assert(pblock_pack_materialize(st, meta) == -1 && errno == EIO);
    assert(pblock_pack_or_block_read(st, meta->blob_id, 4096, data, 7, 0) == -1);
    assert(errno == EIO);
    pblock_pack_del(st, meta->blob_id);
}

/* WHAT: Roll a full segment and reap the new unreferenced segment.
 * WHY: The append boundary must not overwrite existing segment contents.
 * HOW: Create a sparse full segment, admit into its successor, then delete its only row. */
static void rollover(pblock_state_t *st, const pblock_meta *meta)
{
    char path[PATH_MAX];
    assert(pack_seg_path(st, 1, path, sizeof(path)) == 0);
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    assert(fd >= 0 && ftruncate(fd, PBLOCK_PACK_SEG_BYTES) == 0 && close(fd) == 0);
    admit(st, meta);
    pblock_pack_loc_t loc;
    assert(pblock_pack_find(st, meta->blob_id, &loc) == 0 && loc.seg == 2 && loc.off == 0);
    verify(st, meta);
    pblock_pack_del(st, meta->blob_id);
    assert(pack_seg_path(st, 2, path, sizeof(path)) == 0);
    assert(access(path, F_OK) == -1 && errno == ENOENT);
}

/* WHAT: Run one isolated packed-arena contract.
 * WHY: Each fault needs its own real database and storage root.
 * HOW: Initialize the production driver, seed, dispatch and clean up its state. */
int main(int argc, char **argv)
{
    assert(argc == 4);
    brix_sd_instance_t inst = {.driver = &brix_sd_pblock_driver};
    brix_sd_pblock_conf_t conf = {.root = argv[1], .block_size = 4096,
                                .busy_timeout_ms = 1000};
    inst.caps = inst.driver->caps;
    assert(inst.driver->init(&inst, &conf) == NGX_OK);
    pblock_state_t *st = inst.state;
    pblock_meta meta = {0}; seed(st, &meta);
    if (!strcmp(argv[2], "roundtrip")) { roundtrip(st, &meta, argv[3]); }
    else if (!strcmp(argv[2], "admit-fail")) { admission_failure(st, &meta, argv[3]); }
    else if (!strcmp(argv[2], "read-fail")) { read_failure(st, &meta, argv[3]); }
    else if (!strcmp(argv[2], "damaged")) { damaged_record(st, &meta, argv[3]); }
    else if (!strcmp(argv[2], "materialize-fail")) { materialize_failure(st, &meta, argv[3]); }
    else if (!strcmp(argv[2], "invalid")) { invalid_inputs(st, &meta); }
    else if (!strcmp(argv[2], "catalog-fail")) { catalog_failure(st, &meta, argv[3]); }
    else { assert(!strcmp(argv[2], "rollover")); rollover(st, &meta); }
    inst.driver->cleanup(&inst);
    return 0;
}

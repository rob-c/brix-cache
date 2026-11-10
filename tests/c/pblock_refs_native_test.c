/* Real dedup catalogs: CRC candidates need byte equality and failed COW keeps owners. */
#include "fs/backend/pblock/pblock_store.h"
#include "fs/backend/pblock/pblock_refs.h"
#include "fs/backend/pblock/sd_pblock_catalog_internal.h"
#include <assert.h>

/* WHAT: Select a scoped fault. WHY: Catalog setup and verification remain real.
 * HOW: Match the test's active environment label. */
static int fault(const char *name)
{
    const char *active = getenv("BRIX_REFS_TEST_FAULT"); return active && !strcmp(active, name);
}

int __real_sqlite3_step(sqlite3_stmt *);
ssize_t __real_pblock_copy_one_block(const char *, const char *);
brix_wverify_t *__real_brix_wverify_begin(void);
ssize_t __real_pblock_pack_or_block_read(const pblock_state_t *, const char *, int64_t,
                                        void *, size_t, off_t);

/* WHAT: Refuse one SQL operation class. WHY: Counts and repointing must fail closed.
 * HOW: Keep the prepared statement real and return I/O failure before its step. */
int __wrap_sqlite3_step(sqlite3_stmt *query)
{
    const char *sql = sqlite3_sql(query);
    if ((fault("repoint") && strstr(sql, "UPDATE objects SET blob_id"))
        || (fault("count") && strstr(sql, "SELECT refcount FROM blobs"))
        || (fault("hash") && strstr(sql, "SELECT content_hash FROM blobs"))) { return SQLITE_IOERR; }
    return __real_sqlite3_step(query);
}

/* WHAT: Refuse cloning one block. WHY: Partial COW must retain the shared original.
 * HOW: Inject ENOSPC at the existing storage copy seam. */
ssize_t __wrap_pblock_copy_one_block(const char *source, const char *destination)
{
    if (fault("copy")) { errno = ENOSPC; return -1; }
    return __real_pblock_copy_one_block(source, destination);
}

/* WHAT: Refuse a verifier allocation. WHY: Explicit dedup must never trust an absent digest.
 * HOW: Fail only the selected hash recomputation. */
brix_wverify_t *__wrap_brix_wverify_begin(void)
{
    if (fault("verify")) { return NULL; }
    return __real_brix_wverify_begin();
}

/* WHAT: Refuse stored-byte hashing. WHY: Unreadable bytes cannot identify shared content.
 * HOW: Supply a finite I/O error or unexpected EOF at the real storage seam. */
ssize_t __wrap_pblock_pack_or_block_read(const pblock_state_t *store, const char *blob,
                                        int64_t blocksize, void *bytes, size_t length, off_t offset)
{
    if (fault("read")) { errno = EIO; return -1; }
    if (fault("short")) { return 0; }
    return __real_pblock_pack_or_block_read(store, blob, blocksize, bytes, length, offset);
}

/* WHAT: Publish a known object. WHY: Refcount tests require real independent block owners.
 * HOW: Use the driver's actual staged writer while dedup is disabled. */
static void publish(brix_sd_instance_t *instance, const char *path, unsigned char value, size_t length)
{
    unsigned char *bytes = malloc(length); assert(bytes); memset(bytes, value, length);
    brix_sd_staged_t *staged = instance->driver->staged_open(instance, path, 0600, length, NULL);
    assert(staged && instance->driver->staged_write(staged, bytes, length, 0) == (ssize_t) length);
    assert(instance->driver->staged_commit(staged, NULL) == NGX_OK); free(bytes);
}

/* WHAT: Verify a catalog name and all its bytes. WHY: A successful result alone cannot prove COW.
 * HOW: Read the real object fully and check its expected byte pattern. */
static void verify(brix_sd_instance_t *instance, const char *path, unsigned char expected, size_t length)
{
    int error = 0; brix_sd_obj_t *object = instance->driver->open(instance, path, BRIX_SD_O_READ, 0, &error);
    assert(object); unsigned char *bytes = malloc(length + 1); assert(bytes);
    assert(instance->driver->pread(object, bytes, length + 1, 0) == (ssize_t) length);
    for (size_t index = 0; index < length; index++) { assert(bytes[index] == expected); }
    assert(instance->driver->close(object) == NGX_OK); free(object); free(bytes);
}

/* WHAT: Load metadata with cache invalidation honored. WHY: Refcount ownership follows the catalog.
 * HOW: Query the real lookup API and require the name to exist. */
static pblock_meta metadata(pblock_state_t *store, const char *path)
{
    pblock_meta meta; assert(pblock_catalog_lookup(store->cat, path, &meta) == 0); return meta;
}

/* WHAT: Verify CRC candidate admission. WHY: Identical hashes alone cannot establish equal bytes.
 * HOW: Nominate equal-length blobs with a deliberately common CRC identity. */
static void check_fold(brix_sd_instance_t *instance, const char *mode, size_t length)
{
    pblock_state_t *store = instance->state;
    pblock_meta source = metadata(store, "/source"), target = metadata(store, "/target");
    char original[PBLOCK_BLOB_ID_CAP]; strcpy(original, target.blob_id);
    assert(pblock_refs_track(store, source.blob_id, length, 4096, "crc32:12345678") == 0);
    if (!strcmp(mode, "fold-repoint")) { assert(setenv("BRIX_REFS_TEST_FAULT", "repoint", 1) == 0); }
    int rc = pblock_refs_dedup_publish(store, "/target", &target, "crc32:12345678");
    assert(unsetenv("BRIX_REFS_TEST_FAULT") == 0);
    if (!strcmp(mode, "fold-equal")) {
        assert(rc == 1 && !strcmp(target.blob_id, source.blob_id));
        assert(pblock_refs_count(store, source.blob_id) == 2);
    } else {
        assert(rc == (!strcmp(mode, "fold-repoint") ? -1 : 0));
        assert(!strcmp(target.blob_id, original) && pblock_refs_count(store, source.blob_id) == 1);
    }
    pblock_meta persisted = metadata(store, "/target"); assert(!strcmp(persisted.blob_id, target.blob_id));
    verify(instance, "/source", 'A', length);
    verify(instance, "/target", !strcmp(mode, "fold-collision") ? 'B' : 'A', length);
}

/* WHAT: Verify copy-on-write rollback. WHY: Failed private copies cannot alter shared owners.
 * HOW: Share real blobs, inject one failure, then assert identity, counts and bytes. */
static void check_break(brix_sd_instance_t *instance, const char *mode, size_t length)
{
    pblock_state_t *store = instance->state;
    pblock_meta source = metadata(store, "/source"), target = metadata(store, "/target");
    assert(pblock_refs_track(store, source.blob_id, length, 4096, "crc32:12345678") == 0);
    assert(pblock_refs_dedup_publish(store, "/target", &target, "crc32:12345678") == 1);
    const char *fault_name = mode + strlen("break-");
    int failed = strcmp(fault_name, "success") != 0;
    if (failed) { assert(setenv("BRIX_REFS_TEST_FAULT", fault_name, 1) == 0); }
    int rc = pblock_refs_break_share(store, "/target", &target, 0);
    assert(unsetenv("BRIX_REFS_TEST_FAULT") == 0);
    assert(rc == (failed ? -1 : 0));
    assert((strcmp(target.blob_id, source.blob_id) == 0) == failed);
    assert(pblock_refs_count(store, source.blob_id) == (failed ? 2 : 1));
    pblock_meta persisted = metadata(store, "/target"); assert(!strcmp(persisted.blob_id, target.blob_id));
    verify(instance, "/source", 'A', length); verify(instance, "/target", 'A', length);
}

/* WHAT: Refuse unverifiable explicit dedup. WHY: Missing hashes require successful recomputation.
 * HOW: Start from legacy untracked objects and fail the selected hash step. */
static void check_hash(brix_sd_instance_t *instance, const char *mode, size_t length)
{
    pblock_state_t *store = instance->state; pblock_meta before = metadata(store, "/target");
    const char *fault_name = mode + strlen("hash-");
    assert(setenv("BRIX_REFS_TEST_FAULT", fault_name, 1) == 0);
    assert(pblock_refs_dedup_existing(store, "/target") == -1);
    assert(unsetenv("BRIX_REFS_TEST_FAULT") == 0);
    pblock_meta after = metadata(store, "/target"); assert(!strcmp(before.blob_id, after.blob_id));
    assert(pblock_refs_count(store, after.blob_id) == 1);
    verify(instance, "/source", 'A', length); verify(instance, "/target", 'A', length);
}

/* WHAT: Run one dedup ownership contract. WHY: Catalog and block fixtures must remain independent.
 * HOW: Seed legacy private objects, enable the real refs table, then execute the scenario. */
int main(int argc, char **argv)
{
    assert(argc == 4); size_t length = strtoull(argv[3], NULL, 10); assert(length > 0 && length < 100000);
    brix_sd_instance_t instance = {.driver = &brix_sd_pblock_driver};
    brix_sd_pblock_conf_t config = {.root = argv[1], .block_size = 4096, .busy_timeout_ms = 1000};
    instance.caps = instance.driver->caps; assert(instance.driver->init(&instance, &config) == NGX_OK);
    pblock_state_t *store = instance.state; store->refs = 0;
    publish(&instance, "/source", 'A', length);
    publish(&instance, "/target", !strcmp(argv[2], "fold-collision") ? 'B' : 'A', length);
    store->refs = 1; assert(pblock_refs_init(store) == 0);
    if (!strncmp(argv[2], "fold-", 5)) { check_fold(&instance, argv[2], length); }
    else if (!strncmp(argv[2], "break-", 6)) { check_break(&instance, argv[2], length); }
    else { assert(!strncmp(argv[2], "hash-", 5)); check_hash(&instance, argv[2], length); }
    instance.driver->cleanup(&instance); puts("dedup ownership verified"); return 0;
}

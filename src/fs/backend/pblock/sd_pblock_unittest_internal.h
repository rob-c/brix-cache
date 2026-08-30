/*
 * sd_pblock_unittest_internal.h — shared test-harness surface for the pblock
 * driver unit test, split across sd_pblock_unittest*.c. Carries the CHECK macro,
 * the shared globals (failures counter + driver pointer), the small vtable
 * helpers, and the per-group test entry-point prototypes that main() drives.
 *
 * All build wiring (the `cc ...` line) lives in the doc-block of the primary
 * sd_pblock_unittest.c translation unit.
 */
#ifndef SD_PBLOCK_UNITTEST_INTERNAL_H
#define SD_PBLOCK_UNITTEST_INTERNAL_H

#include "fs/backend/sd.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

extern int failures;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: ", __func__, __LINE__);              \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
            failures++;                                                        \
        }                                                                      \
    } while (0)

extern const brix_sd_driver_t *D;   /* = &brix_sd_pblock_driver */

/* ---- shared vtable helpers (defined in the primary/ block translation units) */
ngx_int_t pb_close(brix_sd_obj_t *o);
int       write_file(brix_sd_instance_t *inst, const char *path,
    const char *data, size_t len);
ssize_t   read_file(brix_sd_instance_t *inst, const char *path, char *buf,
    size_t cap);
int       open_block_export(brix_sd_instance_t *inst, char *root,
    int64_t block_size);
void      lab_write_sidecar(const char *root, const char *line);

/* ---- shared catalog (catalog.db) introspection primitives ----------------- *
 * The dedup / slot / defaults test groups all read the pblock catalog directly
 * (a second SQLite connection, as a pytest would). These wrap the identical
 * open/prepare/bind/step/finalize scaffolding so each group's queries are a
 * one-liner. `bind1` (and `bind2`) are bound as text to ?1 (and ?2) when
 * non-NULL. Defined in sd_pblock_unittest_core.c. */
void pbut_query_text(const char *root, const char *sql, const char *bind1,
    char *out, size_t cap);
int  pbut_query_int(const char *root, const char *sql, const char *bind1);
void pbut_exec(const char *root, const char *sql, const char *bind1,
    const char *bind2);

/* ---- core POSIX + concurrency group ---- */
void test_write_read_fstat(brix_sd_instance_t *inst);
void test_truncate_and_stat(brix_sd_instance_t *inst);
void test_preadv(brix_sd_instance_t *inst);
void test_dirs(brix_sd_instance_t *inst);
void test_mkdir_trailing_slash(brix_sd_instance_t *inst);
void test_rename(brix_sd_instance_t *inst);
void test_server_copy(brix_sd_instance_t *inst);
void test_xattr(brix_sd_instance_t *inst);
void test_staged(brix_sd_instance_t *inst);
void test_unlink(brix_sd_instance_t *inst);
void test_fsync_durability(const char *root);
void test_threads(brix_sd_instance_t *inst);
void test_processes(const char *root, brix_sd_instance_t *inst);

/* ---- block striping group ---- */
void test_block_striping(void);
void test_block_size_configurable(void);
void test_block_sparse(void);
void test_block_truncate(void);
void test_block_read_advise(void);
void test_block_copy_and_unlink(void);

/* ---- identity enforcement group ---- */
void test_identity(void);

/* ---- Phase-83 lab features group ---- */
void test_lab_fault_inject(void);
void test_lab_gate_closed(void);
void test_lab_caps_mask(void);
void test_lab_enumerate(void);

/* ---- F10 dedup / F6 snapshot / F11 versioning group ---- */
void test_dedup_refs(void);
void test_dedup_forged_hash(void);
void test_dedup_gate_closed(void);
void test_dedup_slot(void);         /* phase-88 W1 driver->dedup_publish */
void test_pack_arena(void);         /* phase-88 W2 packed small-blob arena */
void test_standard_defaults(void);  /* phase-88 W5 default-on csi + nsidx  */
void test_snapshot(void);
void test_versioning(void);

#endif /* SD_PBLOCK_UNITTEST_INTERNAL_H */

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

/* ---- core POSIX + concurrency group ---- */
void test_write_read_fstat(brix_sd_instance_t *inst);
void test_truncate_and_stat(brix_sd_instance_t *inst);
void test_preadv(brix_sd_instance_t *inst);
void test_dirs(brix_sd_instance_t *inst);
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
void test_snapshot(void);
void test_versioning(void);

#endif /* SD_PBLOCK_UNITTEST_INTERNAL_H */

/* Real disk, CSI records and VFS sync: publication precedes reader snapshots. */
#include "core/ngx_brix_module.h"
#include "fs/backend/csi_tagstore.h"
#include "fs/meta/xmeta_path.h"
#include <assert.h>

/* WHAT: Verify through a new read handle. WHY: New opens snapshot persisted tags.
 * HOW: Use the actual carrier and CRC checker, then release the snapshot. */
static int verify(const char *path, const unsigned char *bytes, size_t length)
{
    brix_csi_t reader;
    assert(brix_csi_open(&reader, path, 4096, 0) == BRIX_CSI_OK);
    int result = brix_csi_verify_read(&reader, bytes, 0, length);
    brix_csi_close(&reader);
    return result;
}

/* WHAT: Commit bytes through an existing writer. WHY: Folded CRCs and raw data
 * must describe the same write. HOW: Write the fd, then call the CSI fold API. */
static void write_bytes(brix_csi_t *writer, int fd, unsigned char *bytes, size_t length)
{
    assert(pwrite(fd, bytes, length, 0) == (ssize_t) length);
    assert(brix_csi_write_update(writer, bytes, 0, length) == BRIX_CSI_OK);
}

/* WHAT: Run the real sync job. WHY: Policy, durability and tags share one seam.
 * HOW: Carry the writer's policy and descriptor into the canonical executor. */
static int sync_writer(brix_csi_t *writer, int fd, int allowed)
{
    brix_vfs_job_t job;
    brix_vfs_job_sync_init(&job, fd);
    job.csi = writer;
    job.mutation_policy = brix_vfs_policy_from_write_enable(allowed);
    brix_vfs_io_execute(&job);
    assert(job.nio == (job.io_errno ? -1 : 0));
    return job.io_errno;
}

/* WHAT: Keep replacement metadata independent of an old open descriptor.
 * WHY: Unlink must not redirect checksum publication to another inode.
 * HOW: Rename the original, create and tag a replacement, then sync the old fd. */
static void replaced(brix_csi_t *writer, int fd, const char *path,
                     unsigned char *bytes, int missing)
{
    char moved[PATH_MAX]; snprintf(moved, sizeof(moved), "%s.old", path);
    assert(rename(path, moved) == 0);
    if (!missing) {
        int fresh = open(path, O_CREAT | O_EXCL | O_RDWR, 0600); assert(fresh >= 0);
        brix_csi_t replacement; memset(bytes, 'R', 4096);
        assert(brix_csi_open(&replacement, path, 4096, 1) == BRIX_CSI_OK);
        write_bytes(&replacement, fresh, bytes, 4096);
        assert(brix_csi_flush(&replacement) == BRIX_CSI_OK);
        brix_csi_close(&replacement); close(fresh);
    }
    assert(sync_writer(writer, fd, 1) == 0);
    if (!missing) { assert(verify(path, bytes, 4096) == BRIX_CSI_OK); }
    assert(writer->dirty); /* Refused publication retains pending state. */
}

/* WHAT: Exercise success, I/O refusal and integrity boundaries.
 * WHY: A successful fsync must not leave newly opened readers with stale tags.
 * HOW: Seed a record, update in place and inspect actual on-disk verification. */
int main(int argc, char **argv)
{
    assert(argc == 3); const char *mode = argv[1], *path = argv[2];
    ngx_cycle_t cycle = {0}; ngx_log_t log = {0}; cycle.log = &log; ngx_cycle = &cycle;
    unsigned char bytes[4096]; memset(bytes, 'A', sizeof(bytes));
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600); assert(fd >= 0);
    brix_csi_t writer;
    assert(brix_csi_open(&writer, path, 4096, 1) == BRIX_CSI_OK);
    write_bytes(&writer, fd, bytes, sizeof(bytes));
    assert(brix_csi_flush(&writer) == BRIX_CSI_OK);
    brix_csi_close(&writer);
    assert(brix_csi_open(&writer, path, 4096, 1) == BRIX_CSI_OK);
    memset(bytes, 'B', sizeof(bytes)); write_bytes(&writer, fd, bytes, sizeof(bytes));
    if (!strcmp(mode, "readonly")) {
        assert(sync_writer(&writer, -1, 0) == EROFS);
        assert(verify(path, bytes, sizeof(bytes)) == BRIX_CSI_MISMATCH);
    } else if (!strcmp(mode, "bad-fd")) {
        close(fd); assert(sync_writer(&writer, fd, 1) == EBADF); fd = -1;
        assert(writer.dirty);
    } else if (!strcmp(mode, "replaced") || !strcmp(mode, "unlinked")) {
        replaced(&writer, fd, path, bytes, !strcmp(mode, "unlinked"));
    } else {
        assert(sync_writer(&writer, fd, 1) == 0);
        assert(verify(path, bytes, sizeof(bytes)) == BRIX_CSI_OK);
        if (!strcmp(mode, "partial")) {
            memset(bytes, 'C', 7); write_bytes(&writer, fd, bytes, 7);
            assert(sync_writer(&writer, fd, 1) == 0);
            assert(verify(path, bytes, sizeof(bytes)) == BRIX_CSI_OK);
        }
        if (!strcmp(mode, "corrupt")) {
            bytes[0] ^= 1;
            assert(verify(path, bytes, sizeof(bytes)) == BRIX_CSI_MISMATCH);
        }
    }
    /* Test only the sync boundary; do not perform a second close-time publish. */
    writer.dirty = 0; brix_csi_close(&writer); if (fd >= 0) { close(fd); }
    puts("sync contract preserved"); return 0;
}

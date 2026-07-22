#ifndef BRIX_FS_VFS_IO_CORE_INTERNAL_H
#define BRIX_FS_VFS_IO_CORE_INTERNAL_H

/*
 * vfs_io_core_internal.h — cross-unit glue for the split vfs_io_core.c body.
 *
 * WHAT: Declares the handful of symbols shared between vfs_io_core.c (the
 *       dispatch + read/write/vector/sync/truncate executors) and its
 *       vfs_io_core_dirlist.c sibling (the kXR_dirlist OPENDIR builder), plus
 *       the wire-chunk cap the dirlist body sizes against.
 *
 * WHY:  Splitting the single execution core across two .c units for the
 *       file-size guard means two callees that were file-local statics must now
 *       cross the file boundary: brix_vfs_io_set_error_message (defined in
 *       vfs_io_core.c, used by the dirlist builder) and
 *       brix_vfs_io_execute_opendir (defined in vfs_io_core_dirlist.c, called
 *       from the dispatcher). Both lose `static` and are declared here.
 *
 * HOW:  Both units include this header (after vfs_io_core.h for the job type).
 *       Single-file-only helpers stay static in their own unit.
 */

#include "vfs_io_core.h"   /* brix_vfs_job_t */

/* Maximum wire-response payload per kXR_oksofar / kXR_ok dirlist chunk. */
#define BRIX_VFS_DIRLIST_CHUNK_CAP  65536UL

/* Copy `message` into job->err_msg when the caller supplied a bounded error
 * buffer. Defined in vfs_io_core.c; used by the dirlist builder. */
void brix_vfs_io_set_error_message(brix_vfs_job_t *job, const char *message);

/* Build the complete kXR_dirlist flat response in job->buf. Defined in
 * vfs_io_core_dirlist.c; dispatched from brix_vfs_io_execute in vfs_io_core.c. */
void brix_vfs_io_execute_opendir(brix_vfs_job_t *job);

#endif /* BRIX_FS_VFS_IO_CORE_INTERNAL_H */

/*
 * frm_zip.h — store-only ZIP container for tape dataset archives (phase-115 W3.1)
 *
 * WHAT: a minimal ZIP32 writer/reader pair used by the OssArc-style dataset
 *       archiver (sd_frm_arc.c): many small online files become ONE archive
 *       object on the MSS, and single members are read back by offset without
 *       inflating the whole container.
 *
 * WHY:  tape systems bill per file; HEP datasets are thousands of small
 *       files. Stock XRootD solves this with OssArc (a zip per dataset with an
 *       index sidecar); we keep the container format compatible enough that a
 *       plain `unzip` or Python's `zipfile` reads what we write.
 *
 * HOW:  method 0 (store) only — members are never compressed, so extraction is
 *       a pread at a known offset plus a CRC-32 check. Names are validated by
 *       brix_zip_name_ok() on BOTH sides: the writer refuses to seal an unsafe
 *       name and the reader skips (and counts) entries a foreign tool may have
 *       planted, so an archive can never place a file outside its dataset.
 *       ngx-free: the standalone unit test (frm_zip_unittest.c) compiles this
 *       file with core/compat/crc32_ieee.c alone.
 */

#ifndef BRIX_FS_BACKEND_FRM_FRM_ZIP_H
#define BRIX_FS_BACKEND_FRM_FRM_ZIP_H

#include <stddef.h>
#include <stdint.h>

#define BRIX_ZIP_NAME_MAX      1024u    /* member name incl. NUL */
#define BRIX_ZIP_MAX_ENTRIES   65535u   /* ZIP32 central-directory count */

typedef struct {
    char      name[BRIX_ZIP_NAME_MAX];  /* '/'-separated, relative, validated */
    uint64_t  size;                     /* member bytes (stored, so also csize) */
    uint64_t  lfh_off;                  /* offset of the member's local header */
    uint32_t  crc;                      /* CRC-32/IEEE of the member bytes */
} brix_zip_entry_t;

/* 1 when `name` is a safe relative member name: non-empty, < BRIX_ZIP_NAME_MAX,
 * no leading or trailing '/', no empty, "." or ".." segment, no backslash,
 * no control byte. 0 otherwise. */
int brix_zip_name_ok(const char *name);

/* ---- writer ------------------------------------------------------------ */

typedef struct brix_zip_writer_s brix_zip_writer_t;

/* `fd` is an empty, writable, seekable file positioned at 0; the writer
 * appends to it. NULL with errno on allocation failure. */
brix_zip_writer_t *brix_zip_writer_open(int fd);

/* Append one stored member from `src_fd` (read from its current position,
 * exactly `size` bytes). 0 on success and `*out` (optional) filled; -1 with
 * errno: EINVAL bad name, EFBIG member/entry-count/offset beyond ZIP32,
 * EIO short source read, or the write(2) errno. After -1 the archive is
 * inconsistent: call brix_zip_writer_close() and discard the file. */
int brix_zip_writer_add(brix_zip_writer_t *w, const char *name, int src_fd,
                        uint64_t size, brix_zip_entry_t *out);

/* Write the central directory + end record. 0 / -1 with errno. The writer
 * stays valid (entries readable) until brix_zip_writer_close(). */
int brix_zip_writer_finish(brix_zip_writer_t *w);

unsigned                brix_zip_writer_count(const brix_zip_writer_t *w);
const brix_zip_entry_t *brix_zip_writer_entry(const brix_zip_writer_t *w, unsigned i);

/* Free the writer; never touches the fd. */
void brix_zip_writer_close(brix_zip_writer_t *w);

/* ---- reader ------------------------------------------------------------ */

/* Called once per usable central-directory entry, in directory order.
 * Return non-zero to stop the walk early (brix_zip_index still returns 0). */
typedef int (*brix_zip_index_cb)(void *ud, const brix_zip_entry_t *e);

/* Walk the central directory of the archive open on `fd`. Entries whose name
 * fails brix_zip_name_ok(), or that are not method 0, are skipped and counted
 * into `*skipped_out` (optional). -1 with errno: EINVAL not a ZIP archive or a
 * malformed directory, EFBIG directory too large, EIO short read. */
int brix_zip_index(int fd, brix_zip_index_cb cb, void *ud, unsigned *skipped_out);

/* Copy member `e` (from a brix_zip_index() walk of the same archive) to
 * `dst_fd`, verifying the CRC. 0 / -1 with errno: EINVAL bad local header,
 * ENOTSUP not stored, EIO short read or CRC mismatch, or the write errno. */
int brix_zip_extract(int fd, const brix_zip_entry_t *e, int dst_fd);

#endif /* BRIX_FS_BACKEND_FRM_FRM_ZIP_H */

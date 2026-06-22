/*
 * zip.h — clean-room ZIP archive member reader (phase-42 W3).
 *
 * WHAT: Parse a ZIP archive's End-of-Central-Directory + central directory
 *       (ZIP64-aware), locate a member, and stream its fully-inflated bytes.
 *       Supports the two methods real archives use: STORE (0) and DEFLATE (8) —
 *       matching XRootD's XrdCl ZipArchive reader. The archive is accessed only
 *       through a caller-supplied pread callback, so it works equally over a
 *       remote root:// handle or a local fd.
 * WHY:  XRootD's only at-rest data compression is client-side ZIP member reads
 *       (?xrdcl.unzip=<member> / xrdcp --zip). The server serves the raw .zip
 *       bytes; ALL ZIP logic is here, client-side, zlib-only (no libXrdCl, no
 *       libzip) — keeping libxrdc clean-room.
 * HOW:  zlib raw-inflate (windowBits -15) for DEFLATE members, direct copy for
 *       STORE; CRC-32 verified against the central-directory value.
 *
 * SECURITY: the archive is untrusted input. Every offset/size is bounds-checked
 * against the archive size; the entry count and central-directory size are
 * capped; a member's inflated output is bounded (absolute cap + the declared
 * uncompressed size) so a zip-bomb cannot exhaust memory/disk. Unsupported
 * methods are rejected. The caller is responsible for sanitising member names
 * before using them as local filesystem paths.
 */
#ifndef XRDC_ZIP_H
#define XRDC_ZIP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */

/* Read exactly `len` bytes at archive offset `off` into `buf`. Returns the count
 * read (short read or -1 = error). ctx is the caller's archive handle. */
typedef ssize_t (*xrdc_zip_pread_fn)(void *ctx, uint64_t off, void *buf, size_t len);

/* Sink for streamed inflated member bytes. Returns 0 to continue, <0 to abort. */
typedef int (*xrdc_zip_sink_fn)(void *sink_ctx, const uint8_t *data, size_t len);

typedef struct {
    char     *name;          /* heap; NUL-terminated member name             */
    uint16_t  method;        /* 0 = STORE, 8 = DEFLATE                       */
    uint64_t  comp_size;
    uint64_t  uncomp_size;
    uint64_t  lfh_off;       /* local-file-header offset in the archive      */
    uint32_t  crc32;         /* expected CRC-32 of the inflated member       */
    uint64_t  archive_size;  /* total archive size (for bounds checks)       */
} xrdc_zip_entry;

typedef struct {
    xrdc_zip_entry *entries;
    size_t          n;
    uint64_t        archive_size;
} xrdc_zip_dir;

/* Result codes (negative = error). */
#define XRDC_ZIP_OK         0
#define XRDC_ZIP_ENOTZIP   -1   /* no End-of-Central-Directory found        */
#define XRDC_ZIP_EBADF     -2   /* malformed structure / failed bounds check */
#define XRDC_ZIP_EIO       -3   /* pread callback failure                   */
#define XRDC_ZIP_ENOMEM    -4
#define XRDC_ZIP_ENOENT    -5   /* member not found                         */
#define XRDC_ZIP_EMETHOD   -6   /* unsupported compression method           */
#define XRDC_ZIP_EBOMB     -7   /* output size/ratio guard tripped          */
#define XRDC_ZIP_ECRC      -8   /* CRC-32 mismatch                          */
#define XRDC_ZIP_EINFLATE  -9   /* corrupt deflate stream                   */

/* Safety caps. */
#define XRDC_ZIP_MAX_ENTRIES   1000000u
#define XRDC_ZIP_MAX_CD_SIZE   (256u * 1024u * 1024u)
#define XRDC_ZIP_MAX_NAME      4096u
#define XRDC_ZIP_MAX_OUTPUT    (64ULL * 1024 * 1024 * 1024)   /* 64 GiB ceiling */

/* Parse the archive directory. archive_size is the total .zip size. On success
 * fills *out (free with xrdc_zip_dir_free). Returns XRDC_ZIP_OK or a negative code. */
int xrdc_zip_open(xrdc_zip_pread_fn pread, void *ctx, uint64_t archive_size,
                  xrdc_zip_dir *out);

/* Find a member by exact name, or NULL. */
const xrdc_zip_entry *xrdc_zip_find(const xrdc_zip_dir *d, const char *name);

void xrdc_zip_dir_free(xrdc_zip_dir *d);

/* Stream the fully-inflated member to sink(); verifies CRC-32 + declared size.
 * Returns XRDC_ZIP_OK or a negative code. */
int xrdc_zip_member_extract(xrdc_zip_pread_fn pread, void *ctx,
                            const xrdc_zip_entry *e,
                            xrdc_zip_sink_fn sink, void *sink_ctx);

/* ---- STORE-only ZIP writer (phase-42 W3 write side) ----------------------- *
 *
 * Emits a standards-compliant ZIP archive (method 0 / STORE, matching XRootD's
 * XrdCl write side which never compresses) through a sequential write callback,
 * so it streams equally to a local fd or a remote root:// handle.  Members are
 * added from a local fd in two passes (CRC-32 + size, then data) so no data
 * descriptors are needed and the result is readable by stock `unzip` and XrdCl.
 * ZIP64 records are emitted automatically when a size/offset exceeds 32 bits or
 * the entry count exceeds 0xFFFF.
 */

/* Sequential write sink: write exactly `len` bytes; return 0 ok, <0 on error. */
typedef int (*xrdc_zip_write_fn)(void *ctx, const void *data, size_t len);

typedef struct xrdc_zip_writer xrdc_zip_writer;

/* New empty-archive writer.  base_offset is the byte offset at which the first
 * local file header is written (0 for a fresh archive; the old central-directory
 * offset for append — see xrdc_zip_writer_new_append). */
xrdc_zip_writer *xrdc_zip_writer_new(xrdc_zip_write_fn wr, void *ctx);

/* Append-mode writer: seeds the central directory with `seed_cd` (the verbatim
 * existing CD bytes, `seed_n` entries) and starts writing new local headers at
 * base_offset (the existing archive's old CD offset, which the new member data
 * overwrites).  Used by `xrdcp --zip-append`.  Rejects ZIP64 seed archives
 * (caller checks via xrdc_zip_read_eocd) — returns NULL on allocation failure. */
xrdc_zip_writer *xrdc_zip_writer_new_append(xrdc_zip_write_fn wr, void *ctx,
                                            uint64_t base_offset,
                                            const uint8_t *seed_cd,
                                            size_t seed_cd_len, size_t seed_n);

/* Add one STORE member named `name`, data streamed from `fd` (pread, two-pass).
 * Returns XRDC_ZIP_OK or a negative code. */
int xrdc_zip_writer_add_fd(xrdc_zip_writer *w, const char *name, int fd);

/* Emit the central directory + (ZIP64) EOCD.  Returns XRDC_ZIP_OK or negative. */
int xrdc_zip_writer_finish(xrdc_zip_writer *w);

void xrdc_zip_writer_free(xrdc_zip_writer *w);

/* Read just the EOCD of an existing archive (for append): yields the central-
 * directory offset/size, entry count, and whether the archive is ZIP64.
 * Returns XRDC_ZIP_OK or a negative code. */
int xrdc_zip_read_eocd(xrdc_zip_pread_fn pread, void *ctx, uint64_t archive_size,
                       uint64_t *cd_off, uint64_t *cd_size, uint64_t *n_entries,
                       int *is_zip64);

#endif /* XRDC_ZIP_H */

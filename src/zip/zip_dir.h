/*
 * zip_dir.h — ZIP central-directory reader for member access (phase-57 W2).
 *
 * WHAT: Resolves a single member of a ZIP archive (by name) to its on-disk byte
 *       range and metadata, by reading the End-Of-Central-Directory, optional
 *       ZIP64 records, the central directory, and the member's local file header.
 * WHY:  ZIP member access (the xrdcl.unzip= opaque) serves one file inside an
 *       archive as a standalone object across root://, WebDAV and S3 GET. This is
 *       the read-only locator; byte serving lives in zip_member.c. Matches the
 *       XrdZip semantics (stored + deflate members).
 * HOW:  Pure C (no nginx, no OpenSSL): pread-only, fully bounds-checked against
 *       the archive size. Tail-scan for the EOCD signature; promote to ZIP64 when
 *       the 32-bit fields are saturated (0xFFFFFFFF / 0xFFFF); walk
 *       signature-checked CDFH records; reject data-descriptor entries (size
 *       unknown at open); read the LFH to compute the true first-data offset.
 *       The caller (zip_member.c) maps the int result to wire/HTTP errors and
 *       does all logging at the edge.
 */
#ifndef XROOTD_ZIP_DIR_H
#define XROOTD_ZIP_DIR_H

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define XROOTD_ZIP_METHOD_STORE    0
#define XROOTD_ZIP_METHOD_DEFLATE  8

/* Resolved metadata for one archive member. */
typedef struct {
    char      name[PATH_MAX];   /* member file name (from the central directory) */
    uint16_t  method;           /* compression method: 0 store / 8 deflate       */
    uint64_t  comp_size;        /* compressed size in the archive (ZIP64-aware)  */
    uint64_t  uncomp_size;      /* uncompressed size = logical file size          */
    uint64_t  data_off;         /* archive offset of the first data byte          */
    uint32_t  crc32;            /* expected IEEE CRC-32 of the uncompressed data  */
} xrootd_zip_member_t;

/* Result codes (plain C — the nginx wrapper maps these to NGX_ / kXR_ / HTTP). */
#define XROOTD_ZIP_OK        0   /* found; *out filled                            */
#define XROOTD_ZIP_NOMEMBER  1   /* archive parsed, no such member                */
#define XROOTD_ZIP_ECORRUPT (-1) /* not a zip / corrupt / oversize / unsupported  */
#define XROOTD_ZIP_EIO      (-2) /* pread / allocation failure                    */

/*
 * Resolve `member` within the archive open on `fd` (size `archive_size`).
 * `cd_max` caps the central-directory read (bomb guard on a hostile directory).
 * Never reads outside [0, archive_size). Returns one of XROOTD_ZIP_*.
 * Rejects (XROOTD_ZIP_ECORRUPT): encrypted entries, methods other than 0/8,
 * data-descriptor entries (size not known at open), and any out-of-bounds field.
 * On duplicate names the LAST central-directory entry wins (XrdZip semantics).
 */
int xrootd_zip_find_member(int fd, off_t archive_size, const char *member,
                           size_t cd_max, xrootd_zip_member_t *out);

/*
 * Extract the member's FULL uncompressed content into out[outcap] (outcap must be
 * >= m->uncomp_size).  Stored members are pread directly; deflate members are
 * raw-inflated (windowBits -15).  Bounded by the declared sizes (no bomb).
 * Returns the number of bytes produced (== m->uncomp_size on success) or -1 on a
 * pread/inflate/allocation error.  Intended for one-shot serving (HTTP/S3 GET);
 * the streaming reader in zip_member.c is used for the root:// handle path.
 */
ssize_t xrootd_zip_extract_full(int fd, const xrootd_zip_member_t *m,
                                unsigned char *out, size_t outcap);

#endif /* XROOTD_ZIP_DIR_H */

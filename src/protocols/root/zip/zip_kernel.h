/*
 * zip_kernel.h — shared ZIP central-directory parsing kernel.
 *
 * WHAT: The security-critical, read-only ZIP locator shared by the server's
 *       member-access path (src/zip/zip_dir.c) and the native client's archive
 *       reader/writer (client/lib/zip.c): little-endian field readers, a
 *       bounds-checked archive read, End-Of-Central-Directory + ZIP64 location,
 *       the CDFH ZIP64-extra-field decoder, and the Local-File-Header → first-
 *       data-byte resolver.
 * WHY:  Both consumers previously carried byte-for-byte copies of this parser.
 *       The archive is untrusted input and every offset/length must be validated
 *       against the archive size; keeping one audited, unit-tested copy removes
 *       the risk of the two diverging. The higher-level directory walk differs
 *       between the two (the client builds a full listing; the server resolves a
 *       single member, last-match-wins) so that loop stays with each consumer —
 *       only the genuinely-identical leaf parsers live here.
 * HOW:  Pure C — no nginx, no OpenSSL, no fixed I/O source. The archive is read
 *       solely through a caller-supplied `zip_pread_fn`, so the same code serves
 *       a local fd (server, via an SD-backed adapter) and a remote root:// handle
 *       (client). Every read is bounds-checked against the archive size before it
 *       is issued; a hostile or truncated archive yields a clean error code,
 *       never an out-of-bounds access.
 */
#ifndef BRIX_ZIP_KERNEL_H
#define BRIX_ZIP_KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>   /* ssize_t */

/*
 * Read exactly `len` bytes at archive offset `off` into `buf`. Returns the
 * number of bytes read (a short read or -1 signals failure). `ctx` is the
 * caller's opaque archive handle (an fd box, a remote-handle struct, ...).
 */
typedef ssize_t (*zip_pread_fn)(void *ctx, uint64_t off, void *buf, size_t len);

/* Kernel result codes (consumers map these onto their own error enums). */
#define ZIP_K_OK         0
#define ZIP_K_ENOTZIP   (-1)   /* no End-Of-Central-Directory record found     */
#define ZIP_K_ECORRUPT  (-2)   /* malformed / failed bounds check / cap exceeded */
#define ZIP_K_EIO       (-3)   /* the pread callback failed                    */

/* Little-endian field readers (operate on a caller-bounds-checked buffer). */
uint16_t zip_rd16le(const uint8_t *p);
uint32_t zip_rd32le(const uint8_t *p);
uint64_t zip_rd64le(const uint8_t *p);

/*
 * Bounds-checked exact read: rejects any range not fully inside [0,
 * archive_size) before calling `pread`. Returns ZIP_K_OK, ZIP_K_ECORRUPT (the
 * range is out of bounds) or ZIP_K_EIO (the callback failed / short read).
 */
int zip_read_at(zip_pread_fn pread, void *ctx, uint64_t archive_size,
                uint64_t off, void *buf, size_t len);

/*
 * Locate the central directory, following the ZIP64 records when any classic
 * 32-bit field is saturated. `cd_max` / `max_entries` are anti-bomb caps (pass 0
 * to disable a cap). On success fills *cd_off / *cd_size / *n_entries and
 * guarantees [cd_off, cd_off+cd_size) lies within the archive. Returns ZIP_K_OK,
 * ZIP_K_ENOTZIP (no EOCD), ZIP_K_ECORRUPT (malformed / cap exceeded / OOB) or
 * ZIP_K_EIO.
 */
int zip_locate_cd(zip_pread_fn pread, void *ctx, uint64_t archive_size,
                  uint64_t cd_max, uint64_t max_entries,
                  uint64_t *cd_off, uint64_t *cd_size, uint64_t *n_entries);

/*
 * Apply a CDFH's ZIP64 extended-information extra field: override each of
 * *uncomp / *comp / *lhdr_off, in ZIP spec order, but only for the fields whose
 * classic value is saturated (0xFFFFFFFF). A malformed extra blob stops parsing
 * (leaving the not-yet-overridden values unchanged). `extra` need not be NUL-
 * terminated; `extra_len` bounds it.
 */
void zip_apply_zip64_extra(const uint8_t *extra, size_t extra_len,
                           uint64_t *uncomp, uint64_t *comp, uint64_t *lhdr_off);

/*
 * Resolve a member's first data byte by reading its Local File Header (whose own
 * filename/extra lengths can differ from the CDFH's). Validates the LFH
 * signature and that [data_off, data_off+comp_size) lies within the archive. On
 * success stores the offset in *data_off. Returns ZIP_K_OK, ZIP_K_ECORRUPT (bad
 * signature / out of bounds) or ZIP_K_EIO.
 */
int zip_resolve_data_off(zip_pread_fn pread, void *ctx, uint64_t archive_size,
                         uint64_t lhdr_off, uint64_t comp_size,
                         uint64_t *data_off);

#endif /* BRIX_ZIP_KERNEL_H */

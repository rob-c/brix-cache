/*
 * zip_kernel.c — shared ZIP central-directory parsing kernel. See zip_kernel.h.
 *
 * Pure C, callback-driven, fully bounds-checked. No nginx / OpenSSL / fixed I/O
 * source so it can be unit-tested standalone and linked into both the module and
 * the native client (libxrdproto). Every offset and length is validated against
 * the archive size before use; a hostile or truncated archive yields a clean
 * error, never an out-of-bounds read.
 */
#include "zip_kernel.h"

#include <stdlib.h>
#include <string.h>

/* ZIP record signatures (little-endian on disk). */
#define ZIPK_EOCD_SIG    0x06054b50u   /* End Of Central Directory            */
#define ZIPK_EOCD_BASE   22
#define ZIPK_Z64LOC_SIG  0x07064b50u   /* ZIP64 EOCD locator                  */
#define ZIPK_Z64LOC_SIZE 20
#define ZIPK_Z64EOCD_SIG 0x06064b50u   /* ZIP64 EOCD                          */
#define ZIPK_Z64EOCD_SZ  56
#define ZIPK_LFH_SIG     0x04034b50u   /* Local File Header                   */
#define ZIPK_LFH_BASE    30

#define ZIPK_U32_MAX     0xFFFFFFFFu
#define ZIPK_U16_MAX     0xFFFFu

#define ZIPK_MAX_COMMENT 65535         /* EOCD comment length cap (u16)        */

/* ---- little-endian field readers ---------------------------------------- */

uint16_t zip_rd16le(const uint8_t *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}

uint32_t zip_rd32le(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

uint64_t zip_rd64le(const uint8_t *p)
{
    return (uint64_t) zip_rd32le(p) | ((uint64_t) zip_rd32le(p + 4) << 32);
}

/* ---- bounds-checked archive read ---------------------------------------- */

int
zip_read_at(zip_pread_fn pread, void *ctx, uint64_t archive_size,
            uint64_t off, void *buf, size_t len)
{
    ssize_t n;

    if (len == 0) {
        return ZIP_K_OK;
    }
    if (off > archive_size || (uint64_t) len > archive_size - off) {
        return ZIP_K_ECORRUPT;            /* out-of-bounds read attempt */
    }
    n = pread(ctx, off, buf, len);
    if (n < 0 || (size_t) n != len) {
        return ZIP_K_EIO;
    }
    return ZIP_K_OK;
}

/* ---- central-directory location (ZIP64-aware) --------------------------- */

/*
 * Promote the classic EOCD fields to their ZIP64 values when any of them is
 * saturated. Returns ZIP_K_OK (promoted or no promotion needed) or
 * ZIP_K_ECORRUPT (the ZIP64 locator / EOCD is malformed).
 */
static int
zip_promote_zip64(zip_pread_fn pread, void *ctx, uint64_t archive_size,
                  uint64_t eocd_pos, uint64_t *cd_off, uint64_t *cd_size,
                  uint64_t *n_entries)
{
    uint8_t  loc[ZIPK_Z64LOC_SIZE];
    uint8_t  z64[ZIPK_Z64EOCD_SZ];
    uint64_t z64_off;
    int      rc;

    if (*cd_off != ZIPK_U32_MAX && *cd_size != ZIPK_U32_MAX
        && *n_entries != ZIPK_U16_MAX) {
        return ZIP_K_OK;                  /* nothing saturated */
    }
    if (eocd_pos < ZIPK_Z64LOC_SIZE) {
        return ZIP_K_ECORRUPT;
    }

    rc = zip_read_at(pread, ctx, archive_size, eocd_pos - ZIPK_Z64LOC_SIZE,
                     loc, sizeof(loc));
    if (rc != ZIP_K_OK || zip_rd32le(loc) != ZIPK_Z64LOC_SIG) {
        return ZIP_K_ECORRUPT;
    }

    z64_off = zip_rd64le(loc + 8);
    rc = zip_read_at(pread, ctx, archive_size, z64_off, z64, sizeof(z64));
    if (rc != ZIP_K_OK || zip_rd32le(z64) != ZIPK_Z64EOCD_SIG) {
        return ZIP_K_ECORRUPT;
    }

    *n_entries = zip_rd64le(z64 + 32);
    *cd_size   = zip_rd64le(z64 + 40);
    *cd_off    = zip_rd64le(z64 + 48);
    return ZIP_K_OK;
}

int
zip_locate_cd(zip_pread_fn pread, void *ctx, uint64_t archive_size,
              uint64_t cd_max, uint64_t max_entries,
              uint64_t *cd_off, uint64_t *cd_size, uint64_t *n_entries)
{
    size_t    tail_len;
    uint64_t  tail_off, eocd_pos = 0;
    uint8_t  *tail;
    int       found = 0, rc;

    if (archive_size < ZIPK_EOCD_BASE) {
        return ZIP_K_ENOTZIP;
    }

    /* The EOCD lives in the last 22 + comment(<=65535) bytes. */
    tail_len = (size_t) ZIPK_EOCD_BASE + ZIPK_MAX_COMMENT;
    if ((uint64_t) tail_len > archive_size) {
        tail_len = (size_t) archive_size;
    }
    tail_off = archive_size - tail_len;

    tail = malloc(tail_len);
    if (tail == NULL) {
        return ZIP_K_EIO;
    }
    rc = zip_read_at(pread, ctx, archive_size, tail_off, tail, tail_len);
    if (rc != ZIP_K_OK) {
        free(tail);
        return rc;
    }

    /* Scan backward for the EOCD signature. */
    for (size_t i = tail_len - ZIPK_EOCD_BASE + 1; i-- > 0; ) {
        if (zip_rd32le(tail + i) == ZIPK_EOCD_SIG) {
            eocd_pos = tail_off + i;
            found = 1;
            break;
        }
    }
    if (!found) {
        free(tail);
        return ZIP_K_ENOTZIP;
    }

    {
        const uint8_t *e = tail + (eocd_pos - tail_off);
        *n_entries = zip_rd16le(e + 10);
        *cd_size   = zip_rd32le(e + 12);
        *cd_off    = zip_rd32le(e + 16);
    }
    free(tail);

    rc = zip_promote_zip64(pread, ctx, archive_size, eocd_pos,
                           cd_off, cd_size, n_entries);
    if (rc != ZIP_K_OK) {
        return rc;
    }

    /* Anti-bomb caps + final bounds check against the archive. */
    if ((cd_max != 0 && *cd_size > cd_max)
        || (max_entries != 0 && *n_entries > max_entries)) {
        return ZIP_K_ECORRUPT;
    }
    if (*cd_off > archive_size || *cd_size > archive_size - *cd_off) {
        return ZIP_K_ECORRUPT;
    }
    return ZIP_K_OK;
}

/* ---- CDFH ZIP64 extra-field decode -------------------------------------- */

void
zip_apply_zip64_extra(const uint8_t *extra, size_t extra_len,
                      uint64_t *uncomp, uint64_t *comp, uint64_t *lhdr_off)
{
    size_t p = 0;

    while (p + 4 <= extra_len) {
        uint16_t id  = zip_rd16le(extra + p);
        uint16_t len = zip_rd16le(extra + p + 2);
        if ((size_t) len > extra_len - p - 4) {
            return;                       /* malformed extra → stop */
        }
        if (id == 0x0001) {               /* ZIP64 extended info */
            const uint8_t *d = extra + p + 4;
            size_t         q = 0;
            if (*uncomp == ZIPK_U32_MAX && len - q >= 8) {
                *uncomp = zip_rd64le(d + q); q += 8;
            }
            if (*comp == ZIPK_U32_MAX && len - q >= 8) {
                *comp = zip_rd64le(d + q); q += 8;
            }
            if (*lhdr_off == ZIPK_U32_MAX && len - q >= 8) {
                *lhdr_off = zip_rd64le(d + q);
            }
            return;
        }
        p += 4 + len;
    }
}

/* ---- Local File Header → first-data-byte resolver ----------------------- */

int
zip_resolve_data_off(zip_pread_fn pread, void *ctx, uint64_t archive_size,
                     uint64_t lhdr_off, uint64_t comp_size, uint64_t *data_off)
{
    uint8_t  lfh[ZIPK_LFH_BASE];
    uint64_t off;
    int      rc;

    rc = zip_read_at(pread, ctx, archive_size, lhdr_off, lfh, sizeof(lfh));
    if (rc != ZIP_K_OK) {
        return rc;
    }
    if (zip_rd32le(lfh) != ZIPK_LFH_SIG) {
        return ZIP_K_ECORRUPT;
    }

    off = lhdr_off + ZIPK_LFH_BASE
        + zip_rd16le(lfh + 26)            /* LFH filename length */
        + zip_rd16le(lfh + 28);           /* LFH extra length    */

    if (off > archive_size || comp_size > archive_size - off) {
        return ZIP_K_ECORRUPT;
    }
    *data_off = off;
    return ZIP_K_OK;
}

/*
 * zip_dir.c — ZIP central-directory reader (phase-57 W2). See zip_dir.h.
 *
 * Pure C, pread-only, fully bounds-checked. No nginx / OpenSSL deps so it can be
 * unit-tested standalone. Every offset and length is validated against the
 * archive size before use; a hostile or truncated archive yields a clean error,
 * never an out-of-bounds read.
 */
#include "zip_dir.h"
#include "../fs/backend/sd.h"   /* route ZIP directory byte reads through the SD backend */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <zlib.h>

/* ZIP record signatures (little-endian on disk). */
#define ZIP_EOCD_SIG    0x06054b50u   /* End Of Central Directory            */
#define ZIP_EOCD_BASE   22
#define ZIP_Z64LOC_SIG  0x07064b50u   /* ZIP64 EOCD locator                  */
#define ZIP_Z64LOC_SIZE 20
#define ZIP_Z64EOCD_SIG 0x06064b50u   /* ZIP64 EOCD                          */
#define ZIP_CDFH_SIG    0x02014b50u   /* Central Directory File Header       */
#define ZIP_CDFH_BASE   46
#define ZIP_LFH_SIG     0x04034b50u   /* Local File Header                   */
#define ZIP_LFH_BASE    30

#define ZIP_U32_MAX     0xFFFFFFFFu
#define ZIP_U16_MAX     0xFFFFu

#define ZIP_GPF_ENCRYPTED  0x0001u    /* general-purpose bit 0               */
#define ZIP_GPF_DATADESC   0x0008u    /* general-purpose bit 3               */

#define ZIP_MAX_COMMENT 65535         /* EOCD comment length cap (u16)        */

/* ---- little-endian field readers (operate on a bounds-checked buffer) ---- */

static uint16_t rd16le(const unsigned char *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}

static uint32_t rd32le(const unsigned char *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static uint64_t rd64le(const unsigned char *p)
{
    return (uint64_t) rd32le(p) | ((uint64_t) rd32le(p + 4) << 32);
}

/* Read exactly n bytes at off into buf; 0 on success, -1 on short read/error. */
static int pread_full(int fd, void *buf, size_t n, off_t off)
{
    unsigned char  *p = buf;
    xrootd_sd_obj_t obj;
    xrootd_sd_posix_wrap(&obj, fd);
    while (n > 0) {
        ssize_t r = obj.driver->pread(&obj, p, n, off);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            return -1;   /* unexpected EOF */
        }
        p += r;
        off += r;
        n -= (size_t) r;
    }
    return 0;
}

/*
 * Locate the central directory: fill *cd_off, *cd_size, *nrec, handling ZIP64.
 * Returns XROOTD_ZIP_OK / _ECORRUPT / _EIO.
 */
static int
zip_locate_cd(int fd, off_t archive_size, uint64_t *cd_off, uint64_t *cd_size,
              uint64_t *nrec)
{
    size_t          tail;
    unsigned char  *buf;
    ssize_t         eo = -1;          /* EOCD offset within buf */
    off_t           tail_base;

    if (archive_size < ZIP_EOCD_BASE) {
        return XROOTD_ZIP_ECORRUPT;
    }

    /* The EOCD lives in the last 22 + comment(<=65535) bytes. */
    tail = (size_t) ZIP_EOCD_BASE + ZIP_MAX_COMMENT;
    if ((off_t) tail > archive_size) {
        tail = (size_t) archive_size;
    }
    tail_base = archive_size - (off_t) tail;

    buf = malloc(tail);
    if (buf == NULL) {
        return XROOTD_ZIP_EIO;
    }
    if (pread_full(fd, buf, tail, tail_base) != 0) {
        free(buf);
        return XROOTD_ZIP_EIO;
    }

    /* Scan backward for the EOCD signature. */
    for (ssize_t o = (ssize_t) tail - ZIP_EOCD_BASE; o >= 0; --o) {
        if (rd32le(buf + o) == ZIP_EOCD_SIG) {
            eo = o;
            break;
        }
    }
    if (eo < 0) {
        free(buf);
        return XROOTD_ZIP_ECORRUPT;
    }

    *nrec    = rd16le(buf + eo + 10);
    *cd_size = rd32le(buf + eo + 12);
    *cd_off  = rd32le(buf + eo + 16);

    /* ZIP64 promotion when any 32-bit field is saturated. */
    if (*cd_off == ZIP_U32_MAX || *nrec == ZIP_U16_MAX || *cd_size == ZIP_U32_MAX) {
        off_t          loc_off = tail_base + eo - ZIP_Z64LOC_SIZE;
        unsigned char  loc[ZIP_Z64LOC_SIZE];
        unsigned char  z64[56];
        uint64_t       z64_off;

        if (loc_off < 0
            || pread_full(fd, loc, sizeof(loc), loc_off) != 0
            || rd32le(loc) != ZIP_Z64LOC_SIG)
        {
            free(buf);
            return XROOTD_ZIP_ECORRUPT;
        }
        z64_off = rd64le(loc + 8);
        if ((off_t) z64_off + (off_t) sizeof(z64) > archive_size
            || pread_full(fd, z64, sizeof(z64), (off_t) z64_off) != 0
            || rd32le(z64) != ZIP_Z64EOCD_SIG)
        {
            free(buf);
            return XROOTD_ZIP_ECORRUPT;
        }
        *nrec    = rd64le(z64 + 32);
        *cd_size = rd64le(z64 + 40);
        *cd_off  = rd64le(z64 + 48);
    }

    free(buf);
    return XROOTD_ZIP_OK;
}

/*
 * Parse the ZIP64 extra field of a CDFH for any saturated size/offset fields.
 * `extra`/`extra_len` is the raw extra blob; the three out params are updated
 * in-place only for the fields that were saturated, in ZIP spec order
 * (uncompressed, compressed, local-header offset).
 */
static void
zip_parse_zip64_extra(const unsigned char *extra, size_t extra_len,
                      uint64_t *uncomp, uint64_t *comp, uint64_t *lhdr_off)
{
    size_t p = 0;
    while (p + 4 <= extra_len) {
        uint16_t id  = rd16le(extra + p);
        uint16_t len = rd16le(extra + p + 2);
        if ((size_t) p + 4 + len > extra_len) {
            return;                       /* malformed extra → stop */
        }
        if (id == 0x0001) {               /* ZIP64 extended info */
            const unsigned char *d = extra + p + 4;
            size_t q = 0;
            if (*uncomp == ZIP_U32_MAX && q + 8 <= len) {
                *uncomp = rd64le(d + q); q += 8;
            }
            if (*comp == ZIP_U32_MAX && q + 8 <= len) {
                *comp = rd64le(d + q); q += 8;
            }
            if (*lhdr_off == ZIP_U32_MAX && q + 8 <= len) {
                *lhdr_off = rd64le(d + q); q += 8;
            }
            return;
        }
        p += 4 + len;
    }
}

/*
 * Resolve the member's first-data offset by reading its Local File Header
 * (its own filename/extra lengths can differ from the CDFH's). Validates the
 * LFH signature and that the data range lies within the archive.
 */
static int
zip_resolve_data_off(int fd, off_t archive_size, uint64_t lhdr_off,
                     xrootd_zip_member_t *out)
{
    unsigned char lfh[ZIP_LFH_BASE];
    uint64_t      data_off;

    if ((off_t) lhdr_off + ZIP_LFH_BASE > archive_size
        || pread_full(fd, lfh, sizeof(lfh), (off_t) lhdr_off) != 0)
    {
        return XROOTD_ZIP_ECORRUPT;
    }
    if (rd32le(lfh) != ZIP_LFH_SIG) {
        return XROOTD_ZIP_ECORRUPT;
    }

    data_off = lhdr_off + ZIP_LFH_BASE
             + rd16le(lfh + 26)            /* LFH filename length */
             + rd16le(lfh + 28);           /* LFH extra length    */

    if (data_off + out->comp_size > (uint64_t) archive_size) {
        return XROOTD_ZIP_ECORRUPT;
    }

    out->data_off = data_off;
    return XROOTD_ZIP_OK;
}

int
xrootd_zip_find_member(int fd, off_t archive_size, const char *member,
                       size_t cd_max, xrootd_zip_member_t *out)
{
    uint64_t        cd_off, cd_size, nrec;
    unsigned char  *cd;
    size_t          mlen, p;
    int             rc;
    int             found = XROOTD_ZIP_NOMEMBER;
    xrootd_zip_member_t last;

    if (fd < 0 || member == NULL || out == NULL) {
        return XROOTD_ZIP_ECORRUPT;
    }
    mlen = strlen(member);
    if (mlen == 0 || mlen >= PATH_MAX) {
        return XROOTD_ZIP_ECORRUPT;
    }

    rc = zip_locate_cd(fd, archive_size, &cd_off, &cd_size, &nrec);
    if (rc != XROOTD_ZIP_OK) {
        return rc;
    }

    /* Bounds + bomb guard on the central directory. */
    if (cd_size == 0 || cd_size > cd_max
        || cd_off + cd_size > (uint64_t) archive_size)
    {
        return XROOTD_ZIP_ECORRUPT;
    }

    cd = malloc((size_t) cd_size);
    if (cd == NULL) {
        return XROOTD_ZIP_EIO;
    }
    if (pread_full(fd, cd, (size_t) cd_size, (off_t) cd_off) != 0) {
        free(cd);
        return XROOTD_ZIP_EIO;
    }

    /* Walk CDFH records. On a duplicate name the LAST entry wins (XrdZip). */
    p = 0;
    for (uint64_t i = 0; i < nrec; ++i) {
        uint16_t bits, method, fn, ex, cm;
        uint64_t uncomp, comp, lhdr_off;

        if (p + ZIP_CDFH_BASE > cd_size || rd32le(cd + p) != ZIP_CDFH_SIG) {
            free(cd);
            return XROOTD_ZIP_ECORRUPT;
        }
        bits     = rd16le(cd + p + 8);
        method   = rd16le(cd + p + 10);
        comp     = rd32le(cd + p + 20);
        uncomp   = rd32le(cd + p + 24);
        fn       = rd16le(cd + p + 28);
        ex       = rd16le(cd + p + 30);
        cm       = rd16le(cd + p + 32);
        lhdr_off = rd32le(cd + p + 42);

        if (p + ZIP_CDFH_BASE + (uint64_t) fn + ex + cm > cd_size) {
            free(cd);
            return XROOTD_ZIP_ECORRUPT;
        }

        if (fn == mlen && memcmp(cd + p + ZIP_CDFH_BASE, member, fn) == 0) {
            /* Unsupported entry kinds → reject (matches plan W2 edge matrix). */
            if ((bits & ZIP_GPF_ENCRYPTED) || (bits & ZIP_GPF_DATADESC)) {
                free(cd);
                return XROOTD_ZIP_ECORRUPT;
            }
            if (method != XROOTD_ZIP_METHOD_STORE
                && method != XROOTD_ZIP_METHOD_DEFLATE) {
                free(cd);
                return XROOTD_ZIP_ECORRUPT;
            }

            zip_parse_zip64_extra(cd + p + ZIP_CDFH_BASE + fn, ex,
                                  &uncomp, &comp, &lhdr_off);

            memset(&last, 0, sizeof(last));
            memcpy(last.name, member, fn);
            last.name[fn]    = '\0';
            last.method      = method;
            last.comp_size   = comp;
            last.uncomp_size = uncomp;
            last.crc32       = rd32le(cd + p + 16);

            rc = zip_resolve_data_off(fd, archive_size, lhdr_off, &last);
            if (rc != XROOTD_ZIP_OK) {
                free(cd);
                return rc;
            }
            found = XROOTD_ZIP_OK;   /* keep scanning: last match wins */
        }

        p += ZIP_CDFH_BASE + (uint64_t) fn + ex + cm;
    }

    free(cd);
    if (found == XROOTD_ZIP_OK) {
        *out = last;
    }
    return found;
}

ssize_t
xrootd_zip_extract_full(int fd, const xrootd_zip_member_t *m,
                        unsigned char *out, size_t outcap)
{
    if (m == NULL || out == NULL || outcap < m->uncomp_size) {
        return -1;
    }

    if (m->method == XROOTD_ZIP_METHOD_STORE) {
        if (pread_full(fd, out, (size_t) m->uncomp_size,
                       (off_t) m->data_off) != 0) {
            return -1;
        }
        return (ssize_t) m->uncomp_size;
    }

    if (m->method == XROOTD_ZIP_METHOD_DEFLATE) {
        unsigned char *comp;
        z_stream       zs;
        int            zr;

        if (m->comp_size == 0) {
            return (m->uncomp_size == 0) ? 0 : -1;
        }
        comp = malloc((size_t) m->comp_size);
        if (comp == NULL) {
            return -1;
        }
        if (pread_full(fd, comp, (size_t) m->comp_size,
                       (off_t) m->data_off) != 0) {
            free(comp);
            return -1;
        }

        memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, -15) != Z_OK) {   /* raw deflate */
            free(comp);
            return -1;
        }
        zs.next_in   = comp;
        zs.avail_in  = (uInt) m->comp_size;
        zs.next_out  = out;
        zs.avail_out = (uInt) m->uncomp_size;
        zr = inflate(&zs, Z_FINISH);
        {
            size_t produced = (size_t) m->uncomp_size - zs.avail_out;
            inflateEnd(&zs);
            free(comp);
            if (zr != Z_STREAM_END || produced != m->uncomp_size) {
                return -1;
            }
            return (ssize_t) produced;
        }
    }

    return -1;   /* unsupported method (find_member already rejects these) */
}

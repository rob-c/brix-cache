/*
 * zip_dir.c — ZIP central-directory reader (phase-57 W2). See zip_dir.h.
 *
 * Pure C, pread-only, fully bounds-checked. No nginx / OpenSSL deps so it can be
 * unit-tested standalone. The security-critical parsing (EOCD/ZIP64 location,
 * ZIP64-extra decode, local-header data-offset resolution) lives in the shared
 * zip_kernel.c — the single audited copy linked into both this module and the
 * native client. This file is the server-side adapter: it wraps the open fd in
 * the kernel's pread callback (via the SD backend), walks the central directory
 * to resolve ONE member (last-match-wins, XrdZip semantics), and serves bytes.
 */
#include "zip_dir.h"
#include "zip_kernel.h"
#include "fs/backend/sd.h"   /* route ZIP directory byte reads through the SD backend */
#include "core/compat/safe_size.h"   /* overflow-checked size arithmetic */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <zlib.h>

/* CDFH layout (the directory walk lives here; the leaf parsers are in the kernel). */
#define ZIP_CDFH_SIG    0x02014b50u   /* Central Directory File Header       */
#define ZIP_CDFH_BASE   46

#define ZIP_GPF_ENCRYPTED  0x0001u    /* general-purpose bit 0               */
#define ZIP_GPF_DATADESC   0x0008u    /* general-purpose bit 3               */

/* Read exactly n bytes at off into buf; 0 on success, -1 on short read/error. */
static int pread_full(int fd, void *buf, size_t n, off_t off)
{
    unsigned char  *p = buf;
    brix_sd_obj_t obj;
    brix_sd_posix_wrap(&obj, fd);
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

/* Kernel pread adapter: read exactly `len` bytes from the open fd boxed in ctx. */
static ssize_t zip_fd_pread(void *ctx, uint64_t off, void *buf, size_t len)
{
    int fd = *(int *) ctx;
    if (pread_full(fd, buf, len, (off_t) off) != 0) {
        return -1;
    }
    return (ssize_t) len;
}

/* Map a kernel result code onto this module's BRIX_ZIP_* enum. */
static int zip_map_kernel_rc(int krc)
{
    switch (krc) {
    case ZIP_K_OK:   return BRIX_ZIP_OK;
    case ZIP_K_EIO:  return BRIX_ZIP_EIO;
    default:         return BRIX_ZIP_ECORRUPT;   /* ENOTZIP / ECORRUPT */
    }
}

int
brix_zip_find_member(int fd, off_t archive_size, const char *member,
                       size_t cd_max, brix_zip_member_t *out)
{
    uint64_t        cd_off, cd_size, nrec;
    unsigned char  *cd;
    size_t          mlen, p;
    int             rc;
    int             found = BRIX_ZIP_NOMEMBER;
    brix_zip_member_t last;

    if (fd < 0 || member == NULL || out == NULL) {
        return BRIX_ZIP_ECORRUPT;
    }
    mlen = strlen(member);
    if (mlen == 0 || mlen >= PATH_MAX) {
        return BRIX_ZIP_ECORRUPT;
    }

    rc = zip_locate_cd(zip_fd_pread, &fd, (uint64_t) archive_size,
                       (uint64_t) cd_max, 0, &cd_off, &cd_size, &nrec);
    if (rc != ZIP_K_OK) {
        return zip_map_kernel_rc(rc);
    }
    if (cd_size == 0) {
        return BRIX_ZIP_ECORRUPT;   /* empty directory — no member to find */
    }

    /* cd_size is read from the (untrusted) EOCD record; guard against a value
     * so close to SIZE_MAX that the +1 sentinel byte allocation would wrap. */
    size_t cd_alloc;
    if (brix_size_add((size_t) cd_size, 1, &cd_alloc) != NGX_OK) {
        return BRIX_ZIP_ECORRUPT;
    }
    cd = malloc(cd_alloc);
    if (cd == NULL) {
        return BRIX_ZIP_EIO;
    }
    if (pread_full(fd, cd, (size_t) cd_size, (off_t) cd_off) != 0) {
        free(cd);
        return BRIX_ZIP_EIO;
    }

    /* Walk CDFH records. On a duplicate name the LAST entry wins (XrdZip). */
    p = 0;
    for (uint64_t i = 0; i < nrec; ++i) {
        uint16_t bits, method, fn, ex, cm;
        uint64_t uncomp, comp, lhdr_off;

        if (p + ZIP_CDFH_BASE > cd_size || zip_rd32le(cd + p) != ZIP_CDFH_SIG) {
            free(cd);
            return BRIX_ZIP_ECORRUPT;
        }
        bits     = zip_rd16le(cd + p + 8);
        method   = zip_rd16le(cd + p + 10);
        comp     = zip_rd32le(cd + p + 20);
        uncomp   = zip_rd32le(cd + p + 24);
        fn       = zip_rd16le(cd + p + 28);
        ex       = zip_rd16le(cd + p + 30);
        cm       = zip_rd16le(cd + p + 32);
        lhdr_off = zip_rd32le(cd + p + 42);

        if (p + ZIP_CDFH_BASE + (uint64_t) fn + ex + cm > cd_size) {
            free(cd);
            return BRIX_ZIP_ECORRUPT;
        }

        if (fn == mlen && memcmp(cd + p + ZIP_CDFH_BASE, member, fn) == 0) {
            /* Unsupported entry kinds → reject (matches plan W2 edge matrix). */
            if ((bits & ZIP_GPF_ENCRYPTED) || (bits & ZIP_GPF_DATADESC)) {
                free(cd);
                return BRIX_ZIP_ECORRUPT;
            }
            if (method != BRIX_ZIP_METHOD_STORE
                && method != BRIX_ZIP_METHOD_DEFLATE) {
                free(cd);
                return BRIX_ZIP_ECORRUPT;
            }

            zip_apply_zip64_extra(cd + p + ZIP_CDFH_BASE + fn, ex,
                                  &uncomp, &comp, &lhdr_off);

            memset(&last, 0, sizeof(last));
            memcpy(last.name, member, fn);
            last.name[fn]    = '\0';
            last.method      = method;
            last.comp_size   = comp;
            last.uncomp_size = uncomp;
            last.crc32       = zip_rd32le(cd + p + 16);

            rc = zip_resolve_data_off(zip_fd_pread, &fd, (uint64_t) archive_size,
                                      lhdr_off, comp, &last.data_off);
            if (rc != ZIP_K_OK) {
                free(cd);
                return zip_map_kernel_rc(rc);
            }
            found = BRIX_ZIP_OK;   /* keep scanning: last match wins */
        }

        p += ZIP_CDFH_BASE + (uint64_t) fn + ex + cm;
    }

    free(cd);
    if (found == BRIX_ZIP_OK) {
        *out = last;
    }
    return found;
}

ssize_t
brix_zip_extract_full(int fd, const brix_zip_member_t *m,
                        unsigned char *out, size_t outcap)
{
    if (m == NULL || out == NULL || outcap < m->uncomp_size) {
        return -1;
    }

    if (m->method == BRIX_ZIP_METHOD_STORE) {
        if (pread_full(fd, out, (size_t) m->uncomp_size,
                       (off_t) m->data_off) != 0) {
            return -1;
        }
        return (ssize_t) m->uncomp_size;
    }

    if (m->method == BRIX_ZIP_METHOD_DEFLATE) {
        unsigned char *comp;
        z_stream       zs;
        int            zr;

        if (m->comp_size == 0) {
            return (m->uncomp_size == 0) ? 0 : -1;
        }
        /* comp_size comes from the (untrusted) central directory; reject a
         * value that would cause the +1 guard byte allocation to overflow. */
        size_t comp_alloc;
        if (brix_size_add((size_t) m->comp_size, 1, &comp_alloc) != NGX_OK) {
            return -1;
        }
        comp = malloc(comp_alloc);
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

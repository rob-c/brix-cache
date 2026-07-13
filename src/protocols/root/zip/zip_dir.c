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

/*
 * One decoded CDFH record: the fields the walk needs plus the record's total
 * on-directory span. Keeps the per-record locals out of the loop body so the
 * scan reads as parse → match → advance.
 */
typedef struct {
    uint16_t  bits;       /* general-purpose flags   */
    uint16_t  method;     /* compression method      */
    uint16_t  fn;         /* file-name length        */
    uint16_t  ex;         /* extra-field length      */
    uint16_t  cm;         /* comment length          */
    uint32_t  crc32;      /* stored CRC-32           */
    uint64_t  uncomp;     /* uncompressed size       */
    uint64_t  comp;       /* compressed size         */
    uint64_t  lhdr_off;   /* local-header offset      */
    uint64_t  span;       /* ZIP_CDFH_BASE+fn+ex+cm  */
} brix_zip_cdfh_t;

/* The open archive: its fd and total size, threaded to the kernel pread. */
typedef struct {
    int    fd;
    off_t  size;
} brix_zip_arc_t;

/*
 * WHAT: Decode and bounds-check the CDFH record at offset `p` in the central
 *       directory buffer `cd` of length `cd_size`.
 * WHY:  The record header, the variable-length trailer (name/extra/comment),
 *       and the derived `span` are all derived from untrusted directory bytes;
 *       every field must be validated before the walk reads them.
 * HOW:  Verify the fixed header fits and carries the CDFH signature, decode the
 *       fields, then verify the full variable-length record fits in `cd_size`.
 *       Returns 0 on success, -1 on any malformed/overrunning record.
 */
static int
zip_parse_cdfh(const unsigned char *cd, uint64_t p, uint64_t cd_size,
               brix_zip_cdfh_t *rec)
{
    if (p + ZIP_CDFH_BASE > cd_size || zip_rd32le(cd + p) != ZIP_CDFH_SIG) {
        return -1;
    }
    rec->bits     = zip_rd16le(cd + p + 8);
    rec->method   = zip_rd16le(cd + p + 10);
    rec->crc32    = zip_rd32le(cd + p + 16);
    rec->comp     = zip_rd32le(cd + p + 20);
    rec->uncomp   = zip_rd32le(cd + p + 24);
    rec->fn       = zip_rd16le(cd + p + 28);
    rec->ex       = zip_rd16le(cd + p + 30);
    rec->cm       = zip_rd16le(cd + p + 32);
    rec->lhdr_off = zip_rd32le(cd + p + 42);

    rec->span = (uint64_t) ZIP_CDFH_BASE + rec->fn + rec->ex + rec->cm;
    if (p + rec->span > cd_size) {
        return -1;
    }
    return 0;
}

/*
 * WHAT: Build the resolved member `last` for a CDFH record whose name matched.
 * WHY:  A matched entry must reject unsupported kinds, apply the ZIP64 extra
 *       overrides, and resolve the local-header data offset before it can be
 *       served — this is the security-critical leaf of the walk.
 * HOW:  Reject encrypted / data-descriptor / non-store-non-deflate entries,
 *       apply the ZIP64 extra to the size/offset triple, populate `last`, then
 *       resolve the data offset via the kernel. Returns a BRIX_ZIP_* code:
 *       BRIX_ZIP_OK on success, an error code otherwise.
 */
static int
zip_build_member(const brix_zip_arc_t *arc, const unsigned char *base,
                 const brix_zip_cdfh_t *rec, brix_zip_member_t *last)
{
    uint64_t  uncomp = rec->uncomp, comp = rec->comp, lhdr_off = rec->lhdr_off;
    int       fd = arc->fd;
    int       rc;

    /* Unsupported entry kinds → reject (matches plan W2 edge matrix). */
    if ((rec->bits & ZIP_GPF_ENCRYPTED) || (rec->bits & ZIP_GPF_DATADESC)) {
        return BRIX_ZIP_ECORRUPT;
    }
    if (rec->method != BRIX_ZIP_METHOD_STORE
        && rec->method != BRIX_ZIP_METHOD_DEFLATE) {
        return BRIX_ZIP_ECORRUPT;
    }

    zip_apply_zip64_extra(base + ZIP_CDFH_BASE + rec->fn, rec->ex,
                          &uncomp, &comp, &lhdr_off);

    memset(last, 0, sizeof(*last));
    memcpy(last->name, base + ZIP_CDFH_BASE, rec->fn);
    last->name[rec->fn]  = '\0';
    last->method         = rec->method;
    last->comp_size      = comp;
    last->uncomp_size    = uncomp;
    last->crc32          = rec->crc32;

    rc = zip_resolve_data_off(zip_fd_pread, &fd, (uint64_t) arc->size,
                              lhdr_off, comp, &last->data_off);
    if (rc != ZIP_K_OK) {
        return zip_map_kernel_rc(rc);
    }
    return BRIX_ZIP_OK;
}

/*
 * The central directory loaded into memory: the owned buffer, its byte length,
 * and the record count from the EOCD. Bundling these keeps the loader's and the
 * scanner's parameter lists within budget while making ownership explicit.
 */
typedef struct {
    unsigned char  *buf;      /* owned; caller frees                    */
    uint64_t        size;     /* directory byte length                  */
    uint64_t        nrec;     /* CDFH record count (from EOCD)          */
} brix_zip_cd_t;

/* The member key to match: name bytes + precomputed length. */
typedef struct {
    const char  *name;
    size_t       len;
} brix_zip_key_t;

/*
 * WHAT: Locate the central directory, allocate a +1-sentinel buffer, and read
 *       the whole directory into `cd`. On success the caller owns `cd->buf`.
 * WHY:  Isolates the untrusted-size overflow guard and the two-step
 *       locate-then-read from the record walk, keeping each concern testable.
 * HOW:  zip_locate_cd → reject empty directory → overflow-checked malloc →
 *       pread the directory. Returns a BRIX_ZIP_* code; on error `cd->buf`=NULL.
 */
static int
zip_load_cd(int fd, off_t archive_size, size_t cd_max, brix_zip_cd_t *cd)
{
    uint64_t  cd_off;
    size_t    cd_alloc;
    int       rc;

    cd->buf = NULL;
    rc = zip_locate_cd(zip_fd_pread, &fd, (uint64_t) archive_size,
                       (uint64_t) cd_max, 0, &cd_off, &cd->size, &cd->nrec);
    if (rc != ZIP_K_OK) {
        return zip_map_kernel_rc(rc);
    }
    if (cd->size == 0) {
        return BRIX_ZIP_ECORRUPT;   /* empty directory — no member to find */
    }

    /* cd size is read from the (untrusted) EOCD record; guard against a value
     * so close to SIZE_MAX that the +1 sentinel byte allocation would wrap. */
    if (brix_size_add((size_t) cd->size, 1, &cd_alloc) != NGX_OK) {
        return BRIX_ZIP_ECORRUPT;
    }
    cd->buf = malloc(cd_alloc);
    if (cd->buf == NULL) {
        return BRIX_ZIP_EIO;
    }
    if (pread_full(fd, cd->buf, (size_t) cd->size, (off_t) cd_off) != 0) {
        free(cd->buf);
        cd->buf = NULL;
        return BRIX_ZIP_EIO;
    }
    return BRIX_ZIP_OK;
}

/*
 * WHAT: Walk the CDFH records in `cd`, resolving the last record whose name
 *       equals `key` into `last`.
 * WHY:  The last-match-wins scan is the core XrdZip semantic; keeping it in its
 *       own function bounds the caller's complexity and localises the walk.
 * HOW:  For each record: parse+bounds-check, compare the name, and on a match
 *       build the member (may overwrite an earlier match). Returns BRIX_ZIP_OK
 *       with `*found` = whether any match was resolved, or an error code.
 */
static int
zip_scan_directory(const brix_zip_arc_t *arc, const brix_zip_cd_t *cd,
                   const brix_zip_key_t *key, brix_zip_member_t *last,
                   int *found)
{
    uint64_t  p = 0;

    *found = BRIX_ZIP_NOMEMBER;
    for (uint64_t i = 0; i < cd->nrec; ++i) {
        brix_zip_cdfh_t  rec = {0};
        int              rc;

        if (zip_parse_cdfh(cd->buf, p, cd->size, &rec) != 0) {
            return BRIX_ZIP_ECORRUPT;
        }
        if (rec.fn == key->len
            && memcmp(cd->buf + p + ZIP_CDFH_BASE, key->name, rec.fn) == 0) {
            rc = zip_build_member(arc, cd->buf + p, &rec, last);
            if (rc != BRIX_ZIP_OK) {
                return rc;
            }
            *found = BRIX_ZIP_OK;   /* keep scanning: last match wins */
        }
        p += rec.span;
    }
    return BRIX_ZIP_OK;
}

int
brix_zip_find_member(int fd, off_t archive_size, const char *member,
                       size_t cd_max, brix_zip_member_t *out)
{
    brix_zip_arc_t     arc = { fd, archive_size };
    brix_zip_cd_t      cd = {0};
    brix_zip_key_t     key;
    int                rc, found;
    brix_zip_member_t  last = {0};

    if (fd < 0 || member == NULL || out == NULL) {
        return BRIX_ZIP_ECORRUPT;
    }
    key.name = member;
    key.len  = strlen(member);
    if (key.len == 0 || key.len >= PATH_MAX) {
        return BRIX_ZIP_ECORRUPT;
    }

    rc = zip_load_cd(fd, archive_size, cd_max, &cd);
    if (rc != BRIX_ZIP_OK) {
        return rc;
    }

    rc = zip_scan_directory(&arc, &cd, &key, &last, &found);
    free(cd.buf);
    if (rc != BRIX_ZIP_OK) {
        return rc;
    }

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

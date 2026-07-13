/*
 * zip_write.c - extracted concern
 * Phase-38 split of zip.c; behavior-identical.
 */
#include "zip_internal.h"



/* Append `len` bytes to the in-memory central directory buffer. */
int
cd_append(brix_zip_writer *w, const uint8_t *p, size_t len)
{
    if (w->cd_len + len > w->cd_cap) {
        size_t ncap = w->cd_cap ? w->cd_cap * 2 : 4096;
        uint8_t *np;
        while (ncap < w->cd_len + len) {
            ncap *= 2;
        }
        np = realloc(w->cd, ncap);
        if (np == NULL) {
            return XRDC_ZIP_ENOMEM;
        }
        w->cd = np;
        w->cd_cap = ncap;
    }
    memcpy(w->cd + w->cd_len, p, len);
    w->cd_len += len;
    return XRDC_ZIP_OK;
}


brix_zip_writer *
brix_zip_writer_new(brix_zip_write_fn wr, void *ctx)
{
    if (wr == NULL) {
        return NULL;
    }
    brix_zip_writer *w = calloc(1, sizeof(*w));
    if (w == NULL) {
        return NULL;
    }
    w->wr  = wr;
    w->ctx = ctx;
    return w;
}


brix_zip_writer *
brix_zip_writer_new_append(brix_zip_write_fn wr, void *ctx, uint64_t base_offset,
                           const brix_zip_seed *seed)
{
    brix_zip_writer *w = brix_zip_writer_new(wr, ctx);
    if (w == NULL) {
        return NULL;
    }
    w->offset = base_offset;
    w->n      = seed->n;
    if (seed->cd_len > 0 && cd_append(w, seed->cd, seed->cd_len) != XRDC_ZIP_OK) {
        brix_zip_writer_free(w);
        return NULL;
    }
    return w;
}


/* Emit raw bytes through the sink, advancing the offset and latching errors. */
int
w_emit(brix_zip_writer *w, const void *p, size_t len)
{
    if (w->err != XRDC_ZIP_OK) {
        return w->err;
    }
    if (w->wr(w->ctx, p, len) != 0) {
        w->err = XRDC_ZIP_EIO;
        return w->err;
    }
    w->offset += len;
    return XRDC_ZIP_OK;
}


/*
 * zw_entry - per-entry layout facts shared across the add-fd phases.
 *
 * WHAT: bundles the values computed once in the CRC pass (name, size, crc,
 *       local-header offset, zip64 flag) so each layout-emitting helper takes
 *       one struct instead of a long parameter list.
 * WHY:  keeps the helper signatures ≤5 params and makes the frozen ZIP byte
 *       layout the single source of truth passed down the phase sequence.
 * HOW:  filled by zw_crc_pass(), then read-only for the header/data/central-dir
 *       emitters — no phase mutates it after the CRC pass.
 */
typedef struct {
    const char *name;
    size_t      namelen;
    uint64_t    size;       /* bytes actually CRC'd and written (STORE) */
    uint64_t    lfh_off;    /* offset of this entry's local file header */
    uint32_t    crc;        /* CRC-32 of the file data */
    int         zip64;      /* wide fields needed for size/offset */
} zw_entry;


/*
 * zw_crc_pass - CRC-32 the source file and freeze the entry's layout facts.
 *
 * WHAT: reads the whole fd once, accumulates the CRC-32, records the number of
 *       bytes actually read (the file may shrink), and derives lfh_off/zip64.
 * WHY:  STORE means comp == uncomp == the bytes we CRC'd, so this single pass
 *       fixes every size/offset field the later phases emit.
 * HOW:  streaming pread into `buf`; EINTR retried, short read ends the pass.
 *       Latches w->any_zip64 exactly as the original inline code did.
 * RETURNS: XRDC_ZIP_OK, or XRDC_ZIP_EIO on a read error.
 */
static int
zw_crc_pass(brix_zip_writer *w, int fd, zw_entry *e,
            unsigned char *buf, size_t bufsz)
{
    off_t pos;

    e->crc = (uint32_t) crc32(0L, Z_NULL, 0);
    for (pos = 0; (uint64_t) pos < e->size; ) {
        ssize_t n = pread(fd, buf, bufsz, pos); /* vfs-seam-allow: local zip-archive assembly, not export data */
        if (n < 0) {
            if (errno == EINTR) { continue; }
            return XRDC_ZIP_EIO;
        }
        if (n == 0) {
            break;                       /* file shrank under us */
        }
        e->crc = (uint32_t) crc32(e->crc, buf, (uInt) n);
        pos += n;
    }
    e->size    = (uint64_t) pos;         /* the bytes we actually CRC'd/will write */
    e->lfh_off = w->offset;
    e->zip64   = (e->size > 0xfffffffeULL) || (e->lfh_off > 0xfffffffeULL);
    if (e->zip64) {
        w->any_zip64 = 1;
    }
    return XRDC_ZIP_OK;
}


/*
 * zw_write_local_header - emit the local file header, name and zip64 extra.
 *
 * WHAT: builds the 30-byte LFH (STORE method, zeroed dates), appends the name,
 *       and, when zip64, the 20-byte zip64 extra field (uncomp,comp).
 * WHY:  first bytes of every archive member; layout is frozen wire format.
 * HOW:  put16/put32/put64 into fixed-size stack buffers, then w_emit each; any
 *       emit error latches into w->err and short-circuits.
 * RETURNS: XRDC_ZIP_OK, or the latched w->err on an emit failure.
 */
static int
zw_write_local_header(brix_zip_writer *w, const zw_entry *e)
{
    uint8_t  lfh[30];
    uint16_t extralen = e->zip64 ? 20 : 0;   /* 4 hdr + 16 (uncomp,comp) */

    put32(lfh + 0,  SIG_LFH);
    put16(lfh + 4,  e->zip64 ? 45 : 20);     /* version needed */
    put16(lfh + 6,  0);                      /* flags */
    put16(lfh + 8,  0);                      /* method = STORE */
    put16(lfh + 10, 0);                      /* mod time */
    put16(lfh + 12, 0);                      /* mod date */
    put32(lfh + 14, e->crc);
    put32(lfh + 18, e->zip64 ? ZIP_U32_MAX : (uint32_t) e->size);   /* comp */
    put32(lfh + 22, e->zip64 ? ZIP_U32_MAX : (uint32_t) e->size);   /* uncomp */
    put16(lfh + 26, (uint16_t) e->namelen);
    put16(lfh + 28, extralen);
    if (w_emit(w, lfh, sizeof(lfh)) != XRDC_ZIP_OK
        || w_emit(w, e->name, e->namelen) != XRDC_ZIP_OK) {
        return w->err;
    }
    if (e->zip64) {
        uint8_t ex[20];
        put16(ex + 0, 0x0001);
        put16(ex + 2, 16);
        put64(ex + 4,  e->size);             /* uncompressed */
        put64(ex + 12, e->size);             /* compressed   */
        if (w_emit(w, ex, sizeof(ex)) != XRDC_ZIP_OK) {
            return w->err;
        }
    }
    return XRDC_ZIP_OK;
}


/*
 * zw_stream_deflate - stream the file data verbatim (STORE, no compression).
 *
 * WHAT: copies exactly e->size bytes from fd to the sink in buffer-sized chunks.
 * WHY:  the archive stores files uncompressed, so the payload is the raw bytes
 *       already accounted for by the CRC pass — must match e->size exactly.
 * HOW:  streaming pread bounded by the remaining count; EINTR retried, a short
 *       read ends the copy; each chunk emitted via w_emit (latches w->err).
 * RETURNS: XRDC_ZIP_OK, or the latched w->err on a read/emit failure.
 */
static int
zw_stream_deflate(brix_zip_writer *w, int fd, const zw_entry *e,
                  unsigned char *buf, size_t bufsz)
{
    off_t pos;

    for (pos = 0; (uint64_t) pos < e->size; ) {
        size_t want = (e->size - (uint64_t) pos < bufsz)
                      ? (size_t) (e->size - (uint64_t) pos) : bufsz;
        ssize_t n = pread(fd, buf, want, pos); /* vfs-seam-allow: local zip-archive assembly, not export data */
        if (n < 0) {
            if (errno == EINTR) { continue; }
            w->err = XRDC_ZIP_EIO;
            return w->err;
        }
        if (n == 0) {
            break;
        }
        if (w_emit(w, buf, (size_t) n) != XRDC_ZIP_OK) {
            return w->err;
        }
        pos += n;
    }
    return XRDC_ZIP_OK;
}


/*
 * zw_update_central_dir - accumulate this entry's central-directory record.
 *
 * WHAT: builds the 46-byte CDFH, appends the name and (when zip64) the 28-byte
 *       zip64 extra (uncomp,comp,off) into the in-memory central directory.
 * WHY:  the central directory is written en bloc at finish; each add_fd must
 *       stage its record now with the frozen field layout.
 * HOW:  put16/put32/put64 into stack buffers, cd_append into w->cd; any append
 *       failure latches XRDC_ZIP_ENOMEM into w->err.
 * RETURNS: XRDC_ZIP_OK, or the latched w->err on an allocation failure.
 */
static int
zw_update_central_dir(brix_zip_writer *w, const zw_entry *e)
{
    uint8_t  cdfh[46];
    uint16_t extralen = e->zip64 ? 28 : 0;   /* 4 hdr + 24 (uncomp,comp,off) */

    put32(cdfh + 0,  SIG_CDFH);
    put16(cdfh + 4,  e->zip64 ? 45 : 20);    /* version made by */
    put16(cdfh + 6,  e->zip64 ? 45 : 20);    /* version needed */
    put16(cdfh + 8,  0);                     /* flags */
    put16(cdfh + 10, 0);                     /* method = STORE */
    put16(cdfh + 12, 0);                     /* mod time */
    put16(cdfh + 14, 0);                     /* mod date */
    put32(cdfh + 16, e->crc);
    put32(cdfh + 20, e->zip64 ? ZIP_U32_MAX : (uint32_t) e->size);   /* comp */
    put32(cdfh + 24, e->zip64 ? ZIP_U32_MAX : (uint32_t) e->size);   /* uncomp */
    put16(cdfh + 28, (uint16_t) e->namelen);
    put16(cdfh + 30, extralen);
    put16(cdfh + 32, 0);                     /* comment len */
    put16(cdfh + 34, 0);                     /* disk number start */
    put16(cdfh + 36, 0);                     /* internal attrs */
    put32(cdfh + 38, 0);                     /* external attrs */
    put32(cdfh + 42, e->zip64 ? ZIP_U32_MAX : (uint32_t) e->lfh_off);
    if (cd_append(w, cdfh, sizeof(cdfh)) != XRDC_ZIP_OK
        || cd_append(w, (const uint8_t *) e->name, e->namelen) != XRDC_ZIP_OK) {
        w->err = XRDC_ZIP_ENOMEM;
        return w->err;
    }
    if (e->zip64) {
        uint8_t ex[28];
        put16(ex + 0, 0x0001);
        put16(ex + 2, 24);
        put64(ex + 4,  e->size);             /* uncompressed */
        put64(ex + 12, e->size);             /* compressed   */
        put64(ex + 20, e->lfh_off);          /* LFH offset    */
        if (cd_append(w, ex, sizeof(ex)) != XRDC_ZIP_OK) {
            w->err = XRDC_ZIP_ENOMEM;
            return w->err;
        }
    }
    return XRDC_ZIP_OK;
}


int
brix_zip_writer_add_fd(brix_zip_writer *w, const char *name, int fd)
{
    struct stat   stbuf;
    zw_entry      e = { 0 };
    unsigned char buf[64 * 1024];
    int           rc;

    if (w == NULL || name == NULL) {
        return XRDC_ZIP_EBADF;
    }
    if (w->err != XRDC_ZIP_OK) {
        return w->err;
    }
    e.name    = name;
    e.namelen = strlen(name);
    if (e.namelen == 0 || e.namelen > XRDC_ZIP_MAX_NAME) {
        return XRDC_ZIP_EBADF;
    }
    if (fstat(fd, &stbuf) != 0) {
        return XRDC_ZIP_EIO;
    }
    e.size = (uint64_t) stbuf.st_size;

    /* Pass 1: CRC-32 over the whole file (STORE: comp == uncomp == size). */
    rc = zw_crc_pass(w, fd, &e, buf, sizeof(buf));
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }

    if (zw_write_local_header(w, &e) != XRDC_ZIP_OK) {
        return w->err;
    }
    if (zw_stream_deflate(w, fd, &e, buf, sizeof(buf)) != XRDC_ZIP_OK) {
        return w->err;
    }
    if (zw_update_central_dir(w, &e) != XRDC_ZIP_OK) {
        return w->err;
    }

    w->n++;
    return XRDC_ZIP_OK;
}


int
brix_zip_writer_finish(brix_zip_writer *w)
{
    uint64_t cd_off, cd_size;
    int      zip64_eocd;

    if (w == NULL) {
        return XRDC_ZIP_EBADF;
    }
    if (w->err != XRDC_ZIP_OK) {
        return w->err;
    }

    cd_off  = w->offset;
    cd_size = w->cd_len;

    if (w->cd_len > 0 && w_emit(w, w->cd, w->cd_len) != XRDC_ZIP_OK) {
        return w->err;
    }

    zip64_eocd = w->any_zip64 || cd_off > 0xfffffffeULL
              || cd_size > 0xfffffffeULL || w->n > 0xfffeu;

    if (zip64_eocd) {
        uint8_t  z64[56];
        uint8_t  loc[20];
        uint64_t z64_off = w->offset;

        put32(z64 + 0,  SIG_Z64EOCD_W);
        put64(z64 + 4,  44);                  /* size of remaining record */
        put16(z64 + 12, 45);                  /* version made by */
        put16(z64 + 14, 45);                  /* version needed */
        put32(z64 + 16, 0);                   /* this disk */
        put32(z64 + 20, 0);                   /* disk with CD start */
        put64(z64 + 24, w->n);                /* entries this disk */
        put64(z64 + 32, w->n);                /* entries total */
        put64(z64 + 40, cd_size);
        put64(z64 + 48, cd_off);
        if (w_emit(w, z64, sizeof(z64)) != XRDC_ZIP_OK) {
            return w->err;
        }

        put32(loc + 0,  SIG_Z64LOC_W);
        put32(loc + 4,  0);                    /* disk with ZIP64 EOCD */
        put64(loc + 8,  z64_off);
        put32(loc + 16, 1);                    /* total disks */
        if (w_emit(w, loc, sizeof(loc)) != XRDC_ZIP_OK) {
            return w->err;
        }
    }

    {
        uint8_t  eocd[22];
        uint16_t n16    = (w->n > 0xffffu) ? 0xffffu : (uint16_t) w->n;
        uint32_t csz32  = (cd_size > 0xfffffffeULL) ? ZIP_U32_MAX : (uint32_t) cd_size;
        uint32_t coff32 = (cd_off  > 0xfffffffeULL) ? ZIP_U32_MAX : (uint32_t) cd_off;

        put32(eocd + 0,  SIG_EOCD);
        put16(eocd + 4,  0);                   /* this disk */
        put16(eocd + 6,  0);                   /* disk with CD start */
        put16(eocd + 8,  n16);                 /* entries this disk */
        put16(eocd + 10, n16);                 /* entries total */
        put32(eocd + 12, csz32);
        put32(eocd + 16, coff32);
        put16(eocd + 20, 0);                   /* comment len */
        if (w_emit(w, eocd, sizeof(eocd)) != XRDC_ZIP_OK) {
            return w->err;
        }
    }
    return XRDC_ZIP_OK;
}


void
brix_zip_writer_free(brix_zip_writer *w)
{
    if (w == NULL) {
        return;
    }
    free(w->cd);
    free(w);
}

/*
 * zip_write.c - extracted concern
 * Phase-38 split of zip.c; behavior-identical.
 */
#include "zip_internal.h"



/* Append `len` bytes to the in-memory central directory buffer. */
int
cd_append(xrdc_zip_writer *w, const uint8_t *p, size_t len)
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


xrdc_zip_writer *
xrdc_zip_writer_new(xrdc_zip_write_fn wr, void *ctx)
{
    if (wr == NULL) {
        return NULL;
    }
    xrdc_zip_writer *w = calloc(1, sizeof(*w));
    if (w == NULL) {
        return NULL;
    }
    w->wr  = wr;
    w->ctx = ctx;
    return w;
}


xrdc_zip_writer *
xrdc_zip_writer_new_append(xrdc_zip_write_fn wr, void *ctx, uint64_t base_offset,
                           const uint8_t *seed_cd, size_t seed_cd_len,
                           size_t seed_n)
{
    xrdc_zip_writer *w = xrdc_zip_writer_new(wr, ctx);
    if (w == NULL) {
        return NULL;
    }
    w->offset = base_offset;
    w->n      = seed_n;
    if (seed_cd_len > 0 && cd_append(w, seed_cd, seed_cd_len) != XRDC_ZIP_OK) {
        xrdc_zip_writer_free(w);
        return NULL;
    }
    return w;
}


/* Emit raw bytes through the sink, advancing the offset and latching errors. */
int
w_emit(xrdc_zip_writer *w, const void *p, size_t len)
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


int
xrdc_zip_writer_add_fd(xrdc_zip_writer *w, const char *name, int fd)
{
    struct stat   stbuf;
    uint64_t      size, lfh_off;
    uint32_t      crc = (uint32_t) crc32(0L, Z_NULL, 0);
    size_t        namelen;
    int           zip64;
    unsigned char buf[64 * 1024];
    off_t         pos;

    if (w == NULL || name == NULL) {
        return XRDC_ZIP_EBADF;
    }
    if (w->err != XRDC_ZIP_OK) {
        return w->err;
    }
    namelen = strlen(name);
    if (namelen == 0 || namelen > XRDC_ZIP_MAX_NAME) {
        return XRDC_ZIP_EBADF;
    }
    if (fstat(fd, &stbuf) != 0) {
        return XRDC_ZIP_EIO;
    }
    size = (uint64_t) stbuf.st_size;

    /* Pass 1: CRC-32 over the whole file (STORE: comp == uncomp == size). */
    for (pos = 0; (uint64_t) pos < size; ) {
        ssize_t n = pread(fd, buf, sizeof(buf), pos);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            return XRDC_ZIP_EIO;
        }
        if (n == 0) {
            break;                       /* file shrank under us */
        }
        crc = (uint32_t) crc32(crc, buf, (uInt) n);
        pos += n;
    }
    size = (uint64_t) pos;               /* the bytes we actually CRC'd/will write */

    lfh_off = w->offset;
    zip64   = (size > 0xfffffffeULL) || (lfh_off > 0xfffffffeULL);
    if (zip64) {
        w->any_zip64 = 1;
    }

    /* Local file header */    {
        uint8_t  lfh[30];
        uint16_t extralen = zip64 ? 20 : 0;   /* 4 hdr + 16 (uncomp,comp) */

        put32(lfh + 0,  SIG_LFH);
        put16(lfh + 4,  zip64 ? 45 : 20);     /* version needed */
        put16(lfh + 6,  0);                   /* flags */
        put16(lfh + 8,  0);                   /* method = STORE */
        put16(lfh + 10, 0);                   /* mod time */
        put16(lfh + 12, 0);                   /* mod date */
        put32(lfh + 14, crc);
        put32(lfh + 18, zip64 ? ZIP_U32_MAX : (uint32_t) size);   /* comp */
        put32(lfh + 22, zip64 ? ZIP_U32_MAX : (uint32_t) size);   /* uncomp */
        put16(lfh + 26, (uint16_t) namelen);
        put16(lfh + 28, extralen);
        if (w_emit(w, lfh, sizeof(lfh)) != XRDC_ZIP_OK
            || w_emit(w, name, namelen) != XRDC_ZIP_OK) {
            return w->err;
        }
        if (zip64) {
            uint8_t ex[20];
            put16(ex + 0, 0x0001);
            put16(ex + 2, 16);
            put64(ex + 4,  size);            /* uncompressed */
            put64(ex + 12, size);            /* compressed   */
            if (w_emit(w, ex, sizeof(ex)) != XRDC_ZIP_OK) {
                return w->err;
            }
        }
    }

    /* File data (STORE: verbatim) */    for (pos = 0; (uint64_t) pos < size; ) {
        size_t want = (size - (uint64_t) pos < sizeof(buf))
                      ? (size_t) (size - (uint64_t) pos) : sizeof(buf);
        ssize_t n = pread(fd, buf, want, pos);
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

    /* Central-directory file header (accumulated, written at finish) */    {
        uint8_t  cdfh[46];
        uint16_t extralen = zip64 ? 28 : 0;   /* 4 hdr + 24 (uncomp,comp,off) */

        put32(cdfh + 0,  SIG_CDFH);
        put16(cdfh + 4,  zip64 ? 45 : 20);    /* version made by */
        put16(cdfh + 6,  zip64 ? 45 : 20);    /* version needed */
        put16(cdfh + 8,  0);                  /* flags */
        put16(cdfh + 10, 0);                  /* method = STORE */
        put16(cdfh + 12, 0);                  /* mod time */
        put16(cdfh + 14, 0);                  /* mod date */
        put32(cdfh + 16, crc);
        put32(cdfh + 20, zip64 ? ZIP_U32_MAX : (uint32_t) size);   /* comp */
        put32(cdfh + 24, zip64 ? ZIP_U32_MAX : (uint32_t) size);   /* uncomp */
        put16(cdfh + 28, (uint16_t) namelen);
        put16(cdfh + 30, extralen);
        put16(cdfh + 32, 0);                  /* comment len */
        put16(cdfh + 34, 0);                  /* disk number start */
        put16(cdfh + 36, 0);                  /* internal attrs */
        put32(cdfh + 38, 0);                  /* external attrs */
        put32(cdfh + 42, zip64 ? ZIP_U32_MAX : (uint32_t) lfh_off);
        if (cd_append(w, cdfh, sizeof(cdfh)) != XRDC_ZIP_OK
            || cd_append(w, (const uint8_t *) name, namelen) != XRDC_ZIP_OK) {
            w->err = XRDC_ZIP_ENOMEM;
            return w->err;
        }
        if (zip64) {
            uint8_t ex[28];
            put16(ex + 0, 0x0001);
            put16(ex + 2, 24);
            put64(ex + 4,  size);            /* uncompressed */
            put64(ex + 12, size);            /* compressed   */
            put64(ex + 20, lfh_off);         /* LFH offset    */
            if (cd_append(w, ex, sizeof(ex)) != XRDC_ZIP_OK) {
                w->err = XRDC_ZIP_ENOMEM;
                return w->err;
            }
        }
    }

    w->n++;
    return XRDC_ZIP_OK;
}


int
xrdc_zip_writer_finish(xrdc_zip_writer *w)
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
xrdc_zip_writer_free(xrdc_zip_writer *w)
{
    if (w == NULL) {
        return;
    }
    free(w->cd);
    free(w);
}

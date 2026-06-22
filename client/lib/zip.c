/*
 * zip.c — clean-room ZIP member reader (see zip.h).
 *
 * Parses EOCD (+ ZIP64 EOCD locator/record) and the central directory, then
 * streams a member's inflated bytes (STORE copy / DEFLATE raw-inflate), verifying
 * CRC-32 and declared size. zlib-only; every archive offset/size is bounds-checked
 * against the archive size; output is bounded against zip-bombs.
 */

#include "zip.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <unistd.h>      /* pread (writer add_fd) */
#include <sys/stat.h>    /* fstat (writer add_fd) */
#include <errno.h>

/* ---- little-endian readers (buffer bounds are the caller's responsibility) ---- */

static uint16_t le16(const uint8_t *p) { return (uint16_t) (p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}
static uint64_t le64(const uint8_t *p)
{
    return (uint64_t) le32(p) | ((uint64_t) le32(p + 4) << 32);
}

#define SIG_EOCD     0x06054b50u
#define SIG_Z64LOC   0x07064b50u
#define SIG_Z64EOCD  0x06064b50u
#define SIG_CDFH     0x02014b50u
#define SIG_LFH      0x04034b50u

/* pread exactly len bytes; returns 0 on success, XRDC_ZIP_EIO/EBADF otherwise. */
static int
read_exact(xrdc_zip_pread_fn pread, void *ctx, uint64_t off, uint64_t archive_size,
           void *buf, size_t len)
{
    ssize_t n;

    if (len == 0) {
        return XRDC_ZIP_OK;
    }
    if (off > archive_size || (uint64_t) len > archive_size - off) {
        return XRDC_ZIP_EBADF;            /* out-of-bounds read attempt */
    }
    n = pread(ctx, off, buf, len);
    if (n < 0 || (size_t) n != len) {
        return XRDC_ZIP_EIO;
    }
    return XRDC_ZIP_OK;
}

/* Locate the EOCD record and return its offset + total-entries / CD size / CD
 * offset, applying ZIP64 overrides when the classic fields are saturated. */
static int
find_eocd(xrdc_zip_pread_fn pread, void *ctx, uint64_t asize,
          uint64_t *cd_off, uint64_t *cd_size, uint64_t *n_entries)
{
    uint64_t  tail_off, eocd_pos = 0;
    size_t    tail_len, i;
    uint8_t  *tail;
    int       found = 0, rc;

    /* EOCD lives in the final 22 + comment(<=65535) bytes. */
    tail_len = (asize < 65557u) ? (size_t) asize : 65557u;
    if (tail_len < 22) {
        return XRDC_ZIP_ENOTZIP;
    }
    tail_off = asize - tail_len;
    tail = malloc(tail_len);
    if (tail == NULL) {
        return XRDC_ZIP_ENOMEM;
    }
    rc = read_exact(pread, ctx, tail_off, asize, tail, tail_len);
    if (rc != XRDC_ZIP_OK) {
        free(tail);
        return rc;
    }

    /* Scan backward for the EOCD signature. */
    for (i = tail_len - 22 + 1; i-- > 0; ) {
        if (le32(tail + i) == SIG_EOCD) {
            eocd_pos = tail_off + i;
            found = 1;
            break;
        }
    }
    if (!found) {
        free(tail);
        return XRDC_ZIP_ENOTZIP;
    }

    {
        const uint8_t *e = tail + (eocd_pos - tail_off);
        *n_entries = le16(e + 10);
        *cd_size   = le32(e + 12);
        *cd_off    = le32(e + 16);
    }

    /* ZIP64: if any classic field is saturated, follow the locator. */
    if (*n_entries == 0xffffu || *cd_size == 0xffffffffu || *cd_off == 0xffffffffu) {
        uint8_t  loc[20], z64[56];
        uint64_t z64_off;

        if (eocd_pos < 20) {
            free(tail);
            return XRDC_ZIP_EBADF;
        }
        rc = read_exact(pread, ctx, eocd_pos - 20, asize, loc, sizeof(loc));
        if (rc == XRDC_ZIP_OK && le32(loc) == SIG_Z64LOC) {
            z64_off = le64(loc + 8);
            rc = read_exact(pread, ctx, z64_off, asize, z64, sizeof(z64));
            if (rc == XRDC_ZIP_OK && le32(z64) == SIG_Z64EOCD) {
                *n_entries = le64(z64 + 32);
                *cd_size   = le64(z64 + 40);
                *cd_off    = le64(z64 + 48);
            }
        }
    }

    free(tail);
    if (*cd_size > XRDC_ZIP_MAX_CD_SIZE || *n_entries > XRDC_ZIP_MAX_ENTRIES) {
        return XRDC_ZIP_EBADF;
    }
    if (*cd_off > asize || *cd_size > asize - *cd_off) {
        return XRDC_ZIP_EBADF;
    }
    return XRDC_ZIP_OK;
}

/* Apply a CDFH ZIP64 extra field, overriding saturated 32-bit fields in order. */
static void
apply_zip64_extra(xrdc_zip_entry *ent, const uint8_t *extra, size_t extra_len)
{
    size_t pos = 0;

    while (pos + 4 <= extra_len) {
        uint16_t id   = le16(extra + pos);
        uint16_t dlen = le16(extra + pos + 2);
        if ((size_t) dlen > extra_len - pos - 4) {
            return;
        }
        if (id == 0x0001) {
            const uint8_t *d = extra + pos + 4;
            size_t         dp = 0;
            if (ent->uncomp_size == 0xffffffffu && dlen - dp >= 8) {
                ent->uncomp_size = le64(d + dp); dp += 8;
            }
            if (ent->comp_size == 0xffffffffu && dlen - dp >= 8) {
                ent->comp_size = le64(d + dp); dp += 8;
            }
            if (ent->lfh_off == 0xffffffffu && dlen - dp >= 8) {
                ent->lfh_off = le64(d + dp); dp += 8;
            }
            return;
        }
        pos += 4 + dlen;
    }
}

int
xrdc_zip_open(xrdc_zip_pread_fn pread, void *ctx, uint64_t archive_size,
              xrdc_zip_dir *out)
{
    uint64_t  cd_off, cd_size, n_entries;
    uint8_t  *cd;
    size_t    pos = 0, idx = 0;
    int       rc;

    if (out == NULL || pread == NULL) {
        return XRDC_ZIP_EBADF;
    }
    memset(out, 0, sizeof(*out));
    out->archive_size = archive_size;

    rc = find_eocd(pread, ctx, archive_size, &cd_off, &cd_size, &n_entries);
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }

    cd = malloc(cd_size ? (size_t) cd_size : 1);
    if (cd == NULL) {
        return XRDC_ZIP_ENOMEM;
    }
    rc = read_exact(pread, ctx, cd_off, archive_size, cd, (size_t) cd_size);
    if (rc != XRDC_ZIP_OK) {
        free(cd);
        return rc;
    }

    out->entries = calloc(n_entries ? (size_t) n_entries : 1,
                          sizeof(xrdc_zip_entry));
    if (out->entries == NULL) {
        free(cd);
        return XRDC_ZIP_ENOMEM;
    }

    while (idx < n_entries && pos + 46 <= cd_size) {
        const uint8_t *h = cd + pos;
        uint16_t       namelen, extralen, commentlen;
        xrdc_zip_entry *ent;

        if (le32(h) != SIG_CDFH) {
            break;
        }
        namelen    = le16(h + 28);
        extralen   = le16(h + 30);
        commentlen = le16(h + 32);
        if ((uint64_t) 46 + namelen + extralen + commentlen > cd_size - pos
            || namelen > XRDC_ZIP_MAX_NAME) {
            free(cd);
            xrdc_zip_dir_free(out);
            return XRDC_ZIP_EBADF;
        }

        ent = &out->entries[idx];
        ent->method        = le16(h + 10);
        ent->crc32         = le32(h + 16);
        ent->comp_size     = le32(h + 20);
        ent->uncomp_size   = le32(h + 24);
        ent->lfh_off       = le32(h + 42);
        ent->archive_size  = archive_size;

        ent->name = malloc((size_t) namelen + 1);
        if (ent->name == NULL) {
            free(cd);
            xrdc_zip_dir_free(out);
            return XRDC_ZIP_ENOMEM;
        }
        memcpy(ent->name, h + 46, namelen);
        ent->name[namelen] = '\0';

        apply_zip64_extra(ent, h + 46 + namelen, extralen);

        /* Member data extent must fit inside the archive (best-effort: lfh + data). */
        if (ent->lfh_off >= archive_size
            || ent->comp_size > archive_size - ent->lfh_off) {
            /* ent->name is allocated but this entry is not yet counted in out->n
             * (bumped below), so xrdc_zip_dir_free would not reach it — free it
             * here to avoid leaking the name on this reject path. */
            free(ent->name);
            ent->name = NULL;
            free(cd);
            xrdc_zip_dir_free(out);
            return XRDC_ZIP_EBADF;
        }

        out->n = ++idx;
        pos += (size_t) 46 + namelen + extralen + commentlen;
    }

    free(cd);
    return XRDC_ZIP_OK;
}

const xrdc_zip_entry *
xrdc_zip_find(const xrdc_zip_dir *d, const char *name)
{
    size_t i;

    if (d == NULL || name == NULL) {
        return NULL;
    }
    for (i = 0; i < d->n; i++) {
        if (strcmp(d->entries[i].name, name) == 0) {
            return &d->entries[i];
        }
    }
    return NULL;
}

void
xrdc_zip_dir_free(xrdc_zip_dir *d)
{
    size_t i;

    if (d == NULL || d->entries == NULL) {
        return;
    }
    for (i = 0; i < d->n; i++) {
        free(d->entries[i].name);
    }
    free(d->entries);
    d->entries = NULL;
    d->n = 0;
}

/* Compute a member's data offset by reading its local file header. */
static int
member_data_offset(xrdc_zip_pread_fn pread, void *ctx, uint64_t asize,
                   const xrdc_zip_entry *e, uint64_t *data_off)
{
    uint8_t  lfh[30];
    uint64_t off;
    int      rc;

    rc = read_exact(pread, ctx, e->lfh_off, asize, lfh, sizeof(lfh));
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }
    if (le32(lfh) != SIG_LFH) {
        return XRDC_ZIP_EBADF;
    }
    off = e->lfh_off + 30 + le16(lfh + 26) + le16(lfh + 28);
    if (off > asize || e->comp_size > asize - off) {
        return XRDC_ZIP_EBADF;
    }
    *data_off = off;
    return XRDC_ZIP_OK;
}

/* Feed produced plaintext to the sink while accumulating CRC + the size cap. */
static int
sink_output(xrdc_zip_sink_fn sink, void *sink_ctx, const uint8_t *data, size_t len,
            uLong *crc, uint64_t *produced, uint64_t uncomp_size)
{
    if (len == 0) {
        return XRDC_ZIP_OK;
    }
    *produced += len;
    if (*produced > uncomp_size || *produced > XRDC_ZIP_MAX_OUTPUT) {
        return XRDC_ZIP_EBOMB;          /* more output than declared = corrupt/bomb */
    }
    *crc = crc32(*crc, data, (uInt) len);
    if (sink(sink_ctx, data, len) != 0) {
        return XRDC_ZIP_EIO;
    }
    return XRDC_ZIP_OK;
}

int
xrdc_zip_member_extract(xrdc_zip_pread_fn pread, void *ctx,
                        const xrdc_zip_entry *e,
                        xrdc_zip_sink_fn sink, void *sink_ctx)
{
    enum { CHUNK = 64 * 1024 };
    uint64_t  data_off, remaining, produced = 0;
    uint8_t  *inbuf, *outbuf = NULL;
    uLong     crc = crc32(0L, Z_NULL, 0);
    z_stream  zs;
    int       rc;

    if (e->method != 0 && e->method != 8) {
        return XRDC_ZIP_EMETHOD;
    }
    if (e->uncomp_size > XRDC_ZIP_MAX_OUTPUT) {
        return XRDC_ZIP_EBOMB;
    }
    rc = member_data_offset(pread, ctx, e->archive_size, e, &data_off);
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }

    inbuf = malloc(CHUNK);
    if (inbuf == NULL) {
        return XRDC_ZIP_ENOMEM;
    }
    if (e->method == 8) {
        outbuf = malloc(CHUNK);
        if (outbuf == NULL) { free(inbuf); return XRDC_ZIP_ENOMEM; }
        memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, -15) != Z_OK) {   /* raw deflate, no header */
            free(inbuf); free(outbuf);
            return XRDC_ZIP_EINFLATE;
        }
    }

    remaining = e->comp_size;
    rc = XRDC_ZIP_OK;
    while (remaining > 0) {
        size_t want = (remaining < CHUNK) ? (size_t) remaining : CHUNK;

        rc = read_exact(pread, ctx, data_off, e->archive_size, inbuf, want);
        if (rc != XRDC_ZIP_OK) {
            break;
        }
        data_off  += want;
        remaining -= want;

        if (e->method == 0) {            /* STORE: raw copy */
            rc = sink_output(sink, sink_ctx, inbuf, want, &crc, &produced,
                             e->uncomp_size);
            if (rc != XRDC_ZIP_OK) {
                break;
            }
            continue;
        }

        /* DEFLATE: inflate this chunk, draining output. */
        zs.next_in  = inbuf;
        zs.avail_in = (uInt) want;
        do {
            int zr;
            zs.next_out  = outbuf;
            zs.avail_out = CHUNK;
            zr = inflate(&zs, Z_NO_FLUSH);
            if (zr != Z_OK && zr != Z_STREAM_END && zr != Z_BUF_ERROR) {
                rc = XRDC_ZIP_EINFLATE;
                break;
            }
            rc = sink_output(sink, sink_ctx, outbuf, CHUNK - zs.avail_out,
                             &crc, &produced, e->uncomp_size);
            if (rc != XRDC_ZIP_OK) {
                break;
            }
            if (zr == Z_STREAM_END) {
                break;
            }
        } while (zs.avail_in > 0 || zs.avail_out == 0);
        if (rc != XRDC_ZIP_OK) {
            break;
        }
    }

    if (e->method == 8) {
        inflateEnd(&zs);
        free(outbuf);
    }
    free(inbuf);

    if (rc != XRDC_ZIP_OK) {
        return rc;
    }
    if (produced != e->uncomp_size) {
        return XRDC_ZIP_EBADF;           /* short/over: truncated or corrupt */
    }
    if ((uint32_t) crc != e->crc32) {
        return XRDC_ZIP_ECRC;
    }
    return XRDC_ZIP_OK;
}

/* ====================================================================== *
 * STORE-only ZIP writer (phase-42 W3 write side)                          *
 * ====================================================================== */

#define SIG_Z64EOCD_W  0x06064b50u
#define SIG_Z64LOC_W   0x07064b50u
#define ZIP_U32_MAX    0xffffffffu

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t) v; p[1] = (uint8_t) (v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) v;        p[1] = (uint8_t) (v >> 8);
    p[2] = (uint8_t) (v >> 16); p[3] = (uint8_t) (v >> 24);
}
static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t) (v >> (8 * i));
    }
}

struct xrdc_zip_writer {
    xrdc_zip_write_fn wr;
    void             *ctx;
    uint64_t          offset;    /* next byte offset to write */
    uint8_t          *cd;        /* accumulated central directory records */
    size_t            cd_len;
    size_t            cd_cap;
    size_t            n;         /* entry count */
    int               any_zip64; /* a member needed a ZIP64 CD entry */
    int               err;       /* sticky negative error code */
};

/* Append `len` bytes to the in-memory central directory buffer. */
static int
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
static int
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

    /* ---- Local file header ---- */
    {
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

    /* ---- File data (STORE: verbatim) ---- */
    for (pos = 0; (uint64_t) pos < size; ) {
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

    /* ---- Central-directory file header (accumulated, written at finish) ---- */
    {
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

int
xrdc_zip_read_eocd(xrdc_zip_pread_fn pread_cb, void *ctx, uint64_t archive_size,
                   uint64_t *cd_off, uint64_t *cd_size, uint64_t *n_entries,
                   int *is_zip64)
{
    uint64_t off, size, n;
    int      rc = find_eocd(pread_cb, ctx, archive_size, &off, &size, &n);
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }
    if (cd_off)    { *cd_off = off; }
    if (cd_size)   { *cd_size = size; }
    if (n_entries) { *n_entries = n; }
    if (is_zip64)  {
        *is_zip64 = (off > 0xfffffffeULL || size > 0xfffffffeULL || n > 0xfffeu);
    }
    return XRDC_ZIP_OK;
}

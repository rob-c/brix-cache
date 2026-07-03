/*
 * zip.c - (kept) routing + shared helpers
 * Phase-38 split of zip.c; behavior-identical.
 *
 * The security-critical leaf parsers (LE field readers, EOCD/ZIP64 location,
 * ZIP64-extra decode, local-header data-offset resolution) live in the shared,
 * unit-tested zip_kernel.c (src/protocols/root/zip/) — the single copy linked into both the
 * native client and the nginx module. The functions below are thin client-side
 * adapters that keep the existing zip_internal.h signatures stable (so
 * zip_write.c / copy_zip.c are untouched) and map the kernel's ZIP_K_* codes
 * onto the client's XRDC_ZIP_* enum.
 */
#include "zip_internal.h"
#include "protocols/root/zip/zip_kernel.h"

/* Map a shared-kernel result code onto the client's XRDC_ZIP_* enum. */
static int
zip_map_kernel_rc(int krc)
{
    switch (krc) {
    case ZIP_K_OK:      return XRDC_ZIP_OK;
    case ZIP_K_ENOTZIP: return XRDC_ZIP_ENOTZIP;
    case ZIP_K_EIO:     return XRDC_ZIP_EIO;
    default:            return XRDC_ZIP_EBADF;   /* ECORRUPT / bounds */
    }
}

uint16_t le16(const uint8_t *p) { return zip_rd16le(p); }

uint32_t le32(const uint8_t *p) { return zip_rd32le(p); }

uint64_t le64(const uint8_t *p) { return zip_rd64le(p); }



/* pread exactly len bytes; returns 0 on success, XRDC_ZIP_EIO/EBADF otherwise. */
int
read_exact(brix_zip_pread_fn pread, void *ctx, uint64_t off, uint64_t archive_size,
           void *buf, size_t len)
{
    return zip_map_kernel_rc(
        zip_read_at(pread, ctx, archive_size, off, buf, len));
}


/* Locate the EOCD record and return its offset + total-entries / CD size / CD
 * offset, applying ZIP64 overrides when the classic fields are saturated. */
int
find_eocd(brix_zip_pread_fn pread, void *ctx, uint64_t asize,
          uint64_t *cd_off, uint64_t *cd_size, uint64_t *n_entries)
{
    return zip_map_kernel_rc(
        zip_locate_cd(pread, ctx, asize,
                      XRDC_ZIP_MAX_CD_SIZE, XRDC_ZIP_MAX_ENTRIES,
                      cd_off, cd_size, n_entries));
}


/* Apply a CDFH ZIP64 extra field, overriding saturated 32-bit fields in order. */
void
apply_zip64_extra(brix_zip_entry *ent, const uint8_t *extra, size_t extra_len)
{
    zip_apply_zip64_extra(extra, extra_len,
                          &ent->uncomp_size, &ent->comp_size, &ent->lfh_off);
}


int
brix_zip_open(brix_zip_pread_fn pread, void *ctx, uint64_t archive_size,
              brix_zip_dir *out)
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
                          sizeof(brix_zip_entry));
    if (out->entries == NULL) {
        free(cd);
        return XRDC_ZIP_ENOMEM;
    }

    while (idx < n_entries && pos + 46 <= cd_size) {
        const uint8_t *h = cd + pos;
        uint16_t       namelen, extralen, commentlen;
        brix_zip_entry *ent;

        if (le32(h) != SIG_CDFH) {
            break;
        }
        namelen    = le16(h + 28);
        extralen   = le16(h + 30);
        commentlen = le16(h + 32);
        if ((uint64_t) 46 + namelen + extralen + commentlen > cd_size - pos
            || namelen > XRDC_ZIP_MAX_NAME) {
            free(cd);
            brix_zip_dir_free(out);
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
            brix_zip_dir_free(out);
            return XRDC_ZIP_ENOMEM;
        }
        memcpy(ent->name, h + 46, namelen);
        ent->name[namelen] = '\0';

        apply_zip64_extra(ent, h + 46 + namelen, extralen);

        /* Member data extent must fit inside the archive (best-effort: lfh + data). */
        if (ent->lfh_off >= archive_size
            || ent->comp_size > archive_size - ent->lfh_off) {
            /* ent->name is allocated but this entry is not yet counted in out->n
             * (bumped below), so brix_zip_dir_free would not reach it — free it
             * here to avoid leaking the name on this reject path. */
            free(ent->name);
            ent->name = NULL;
            free(cd);
            brix_zip_dir_free(out);
            return XRDC_ZIP_EBADF;
        }

        out->n = ++idx;
        pos += (size_t) 46 + namelen + extralen + commentlen;
    }

    free(cd);
    return XRDC_ZIP_OK;
}


const brix_zip_entry *
brix_zip_find(const brix_zip_dir *d, const char *name)
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
brix_zip_dir_free(brix_zip_dir *d)
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
int
member_data_offset(brix_zip_pread_fn pread, void *ctx, uint64_t asize,
                   const brix_zip_entry *e, uint64_t *data_off)
{
    return zip_map_kernel_rc(
        zip_resolve_data_off(pread, ctx, asize, e->lfh_off, e->comp_size,
                             data_off));
}


/* Feed produced plaintext to the sink while accumulating CRC + the size cap. */
int
sink_output(brix_zip_sink_fn sink, void *sink_ctx, const uint8_t *data, size_t len,
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
brix_zip_member_extract(brix_zip_pread_fn pread, void *ctx,
                        const brix_zip_entry *e,
                        brix_zip_sink_fn sink, void *sink_ctx)
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


void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t) v; p[1] = (uint8_t) (v >> 8); }

void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) v;        p[1] = (uint8_t) (v >> 8);
    p[2] = (uint8_t) (v >> 16); p[3] = (uint8_t) (v >> 24);
}

void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t) (v >> (8 * i));
    }
}


int
brix_zip_read_eocd(brix_zip_pread_fn pread_cb, void *ctx, uint64_t archive_size,
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

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


/*
 * WHAT: The central directory as slurped from the archive — its malloc'd bytes,
 *       byte size, and declared entry count.
 * WHY:  Bundles the three outputs of zip_read_central_dir so it stays at/under
 *       the 5-param cap (§8.2) while keeping a single named result object.
 */
typedef struct {
    uint8_t  *bytes;      /* malloc'd copy of the whole CD; caller frees */
    uint64_t  size;       /* CD byte length */
    uint64_t  n_entries;  /* declared entry count from the EOCD */
} zip_cd_t;


/*
 * WHAT: Locate + read the whole central directory into a freshly malloc'd
 *       buffer, reporting its byte size and declared entry count in *cd.
 * WHY:  Splits the EOCD-locate + CD-slurp preamble out of brix_zip_open so the
 *       orchestrator reads as a flat sequence of named steps (coding-standards
 *       §8.5), keeping the CDFH parse loop as the only complex region.
 * HOW:  find_eocd() → malloc(size) → read_exact(). On any failure the buffer is
 *       freed here and cd->bytes is left NULL so the caller has nothing to
 *       release. Byte layout unchanged — same kernel calls, order, rc mapping.
 */
static int
zip_read_central_dir(brix_zip_pread_fn pread, void *ctx, uint64_t archive_size,
                     zip_cd_t *cd)
{
    uint64_t  cd_off = 0;
    uint8_t  *buf;
    int       rc;

    cd->bytes = NULL;
    cd->size = 0;
    cd->n_entries = 0;

    rc = find_eocd(pread, ctx, archive_size, &cd_off, &cd->size,
                   &cd->n_entries);
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }

    buf = malloc(cd->size ? (size_t) cd->size : 1);
    if (buf == NULL) {
        return XRDC_ZIP_ENOMEM;
    }
    rc = read_exact(pread, ctx, cd_off, archive_size, buf, (size_t) cd->size);
    if (rc != XRDC_ZIP_OK) {
        free(buf);
        return rc;
    }
    cd->bytes = buf;
    return XRDC_ZIP_OK;
}


/*
 * WHAT: Parse + validate ONE central-directory file header at cd[pos] into
 *       out->entries[idx], and advance *pos past this record on success.
 * WHY:  The per-entry CDFH decode (field reads, bounds/name-length checks,
 *       ZIP64-extra apply, in-archive extent check, name copy) is the sole
 *       complexity source in brix_zip_open; extracting it makes each check
 *       independently reviewable (§8.1) without changing any wire read.
 * HOW:  Reads the 46-byte fixed CDFH via le16/le32 at the frozen offsets, copies
 *       the name, applies the ZIP64 extra, then bounds-checks lfh + comp_size.
 *       On reject the freshly-allocated name (not yet counted in out->n) is freed
 *       here to avoid a leak, mirroring the original inline logic exactly.
 *       Returns XRDC_ZIP_OK to keep parsing, ZIP_CD_STOP to end the loop cleanly
 *       (non-CDFH signature), or a negative XRDC_ZIP_* error on a malformed entry.
 */
enum {
    ZIP_CDFH_FIXED = 46,   /* fixed-length prefix of a central-directory header */
    ZIP_CD_STOP    = 1     /* file-local: clean end of directory (positive, so it
                            * never collides with the 0/negative XRDC_ZIP_* set) */
};

static int
zip_parse_cd_entry(const uint8_t *cd, uint64_t cd_size, size_t *pos,
                   uint64_t archive_size, brix_zip_entry *ent)
{
    const uint8_t *h = cd + *pos;
    uint16_t       namelen, extralen, commentlen;

    if (le32(h) != SIG_CDFH) {
        return ZIP_CD_STOP;
    }
    namelen    = le16(h + 28);
    extralen   = le16(h + 30);
    commentlen = le16(h + 32);
    if ((uint64_t) ZIP_CDFH_FIXED + namelen + extralen + commentlen
            > cd_size - *pos
        || namelen > XRDC_ZIP_MAX_NAME) {
        return XRDC_ZIP_EBADF;
    }

    ent->method        = le16(h + 10);
    ent->crc32         = le32(h + 16);
    ent->comp_size     = le32(h + 20);
    ent->uncomp_size   = le32(h + 24);
    ent->lfh_off       = le32(h + 42);
    ent->archive_size  = archive_size;

    ent->name = malloc((size_t) namelen + 1);
    if (ent->name == NULL) {
        return XRDC_ZIP_ENOMEM;
    }
    memcpy(ent->name, h + ZIP_CDFH_FIXED, namelen);
    ent->name[namelen] = '\0';

    apply_zip64_extra(ent, h + ZIP_CDFH_FIXED + namelen, extralen);

    /* Member data extent must fit inside the archive (best-effort: lfh + data). */
    if (ent->lfh_off >= archive_size
        || ent->comp_size > archive_size - ent->lfh_off) {
        /* ent->name is allocated but this entry is not yet counted in out->n,
         * so brix_zip_dir_free would not reach it — free it here to avoid
         * leaking the name on this reject path. */
        free(ent->name);
        ent->name = NULL;
        return XRDC_ZIP_EBADF;
    }

    *pos += (size_t) ZIP_CDFH_FIXED + namelen + extralen + commentlen;
    return XRDC_ZIP_OK;
}


int
brix_zip_open(brix_zip_pread_fn pread, void *ctx, uint64_t archive_size,
              brix_zip_dir *out)
{
    zip_cd_t  cd = {0};
    size_t    pos = 0, idx = 0;
    int       rc;

    if (out == NULL || pread == NULL) {
        return XRDC_ZIP_EBADF;
    }
    memset(out, 0, sizeof(*out));
    out->archive_size = archive_size;

    rc = zip_read_central_dir(pread, ctx, archive_size, &cd);
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }

    out->entries = calloc(cd.n_entries ? (size_t) cd.n_entries : 1,
                          sizeof(brix_zip_entry));
    if (out->entries == NULL) {
        free(cd.bytes);
        return XRDC_ZIP_ENOMEM;
    }

    while (idx < cd.n_entries && pos + ZIP_CDFH_FIXED <= cd.size) {
        rc = zip_parse_cd_entry(cd.bytes, cd.size, &pos, archive_size,
                                &out->entries[idx]);
        if (rc == ZIP_CD_STOP) {
            break;
        }
        if (rc != XRDC_ZIP_OK) {
            free(cd.bytes);
            brix_zip_dir_free(out);
            return rc;
        }
        out->n = ++idx;
    }

    free(cd.bytes);
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


enum { ZIP_EXTRACT_CHUNK = 64 * 1024 };


/*
 * WHAT: Running state for a single member extraction — the decode buffers,
 *       inflate stream (DEFLATE only), CRC accumulator, output-size counter and
 *       the archive read cursor.
 * WHY:  Bundling the ~8 locals that member_extract threads through its inner
 *       loops lets each step take one `ctx` pointer instead of a long parameter
 *       list (§8.2), keeping the extracted helpers well under the 5-param cap.
 * HOW:  `inflating` records whether `zs` was initialised so teardown only ends a
 *       stream it actually started. Purely a container — no behaviour of its own.
 */
typedef struct {
    const brix_zip_entry *e;
    brix_zip_pread_fn     pread;
    void                 *pread_ctx;
    brix_zip_sink_fn      sink;
    void                 *sink_ctx;
    uint8_t              *inbuf;
    uint8_t              *outbuf;
    z_stream              zs;
    int                   inflating;
    uLong                 crc;
    uint64_t              produced;
    uint64_t              data_off;
} zip_extract_t;


/*
 * WHAT: Allocate the decode buffers and, for DEFLATE members, initialise the
 *       raw-inflate stream inside `ex`.
 * WHY:  Isolates the resource-acquisition preamble so the orchestrator is a flat
 *       sequence and each early-return frees exactly what it owns (§4 Recipe 1),
 *       no goto.
 * HOW:  Always allocates `inbuf`; for method 8 also allocates `outbuf` and calls
 *       inflateInit2(-15) (raw deflate, no header). Frees partially-acquired
 *       buffers on failure and sets `ex->inflating` only once the stream is live.
 */
static int
zip_extract_setup(zip_extract_t *ex)
{
    ex->inbuf = malloc(ZIP_EXTRACT_CHUNK);
    if (ex->inbuf == NULL) {
        return XRDC_ZIP_ENOMEM;
    }
    if (ex->e->method == 8) {
        ex->outbuf = malloc(ZIP_EXTRACT_CHUNK);
        if (ex->outbuf == NULL) {
            free(ex->inbuf);
            ex->inbuf = NULL;
            return XRDC_ZIP_ENOMEM;
        }
        memset(&ex->zs, 0, sizeof(ex->zs));
        if (inflateInit2(&ex->zs, -15) != Z_OK) {   /* raw deflate, no header */
            free(ex->inbuf);
            free(ex->outbuf);
            ex->inbuf = ex->outbuf = NULL;
            return XRDC_ZIP_EINFLATE;
        }
        ex->inflating = 1;
    }
    return XRDC_ZIP_OK;
}


/*
 * WHAT: Release everything zip_extract_setup acquired (inflate stream + buffers).
 * WHY:  One owner for teardown keeps the orchestrator's exits linear (§4).
 * HOW:  Ends the inflate stream only if it was started, then frees both buffers.
 */
static void
zip_extract_teardown(zip_extract_t *ex)
{
    if (ex->inflating) {
        inflateEnd(&ex->zs);
    }
    free(ex->outbuf);
    free(ex->inbuf);
}


/*
 * WHAT: Inflate one already-read compressed chunk of `len` bytes, draining all
 *       produced plaintext to the sink.
 * WHY:  The nested inflate/drain loop is the dominant complexity of member
 *       extraction; extracting it makes the outer read loop trivial (§8.5) and
 *       leaves this loop the single testable unit for the DEFLATE path.
 * HOW:  Feeds `ex->inbuf[0..len)` into the stream, then loops filling `outbuf`
 *       and sinking `CHUNK - avail_out` bytes until input is drained (or output
 *       stops filling). Treats Z_BUF_ERROR as benign (no progress) exactly as the
 *       original; any other non-OK/non-STREAM_END code is a corrupt stream.
 */
static int
zip_extract_inflate_chunk(zip_extract_t *ex, size_t len)
{
    ex->zs.next_in  = ex->inbuf;
    ex->zs.avail_in = (uInt) len;
    do {
        int rc;
        int zr;

        ex->zs.next_out  = ex->outbuf;
        ex->zs.avail_out = ZIP_EXTRACT_CHUNK;
        zr = inflate(&ex->zs, Z_NO_FLUSH);
        if (zr != Z_OK && zr != Z_STREAM_END && zr != Z_BUF_ERROR) {
            return XRDC_ZIP_EINFLATE;
        }
        rc = sink_output(ex->sink, ex->sink_ctx, ex->outbuf,
                         ZIP_EXTRACT_CHUNK - ex->zs.avail_out,
                         &ex->crc, &ex->produced, ex->e->uncomp_size);
        if (rc != XRDC_ZIP_OK) {
            return rc;
        }
        if (zr == Z_STREAM_END) {
            return XRDC_ZIP_OK;
        }
    } while (ex->zs.avail_in > 0 || ex->zs.avail_out == 0);
    return XRDC_ZIP_OK;
}


/*
 * WHAT: Read the member's compressed extent chunk-by-chunk and route each chunk
 *       to the STORE copy or the DEFLATE inflater.
 * WHY:  Separates the archive-read driver from buffer setup and final verify so
 *       each is a single responsibility (§8.1); STORE vs DEFLATE dispatch is one
 *       branch instead of being tangled with allocation and teardown.
 * HOW:  Reads up to CHUNK bytes per iteration via read_exact (bounds-checked in
 *       the kernel), advancing the read cursor, until comp_size is consumed.
 *       Method 0 copies straight to the sink; method 8 hands the chunk to
 *       zip_extract_inflate_chunk. Byte order and CRC accumulation unchanged.
 */
static int
zip_extract_stream(zip_extract_t *ex)
{
    uint64_t remaining = ex->e->comp_size;

    while (remaining > 0) {
        size_t want = (remaining < ZIP_EXTRACT_CHUNK)
                          ? (size_t) remaining : ZIP_EXTRACT_CHUNK;
        int    rc;

        rc = read_exact(ex->pread, ex->pread_ctx, ex->data_off,
                        ex->e->archive_size, ex->inbuf, want);
        if (rc != XRDC_ZIP_OK) {
            return rc;
        }
        ex->data_off += want;
        remaining    -= want;

        if (ex->e->method == 0) {            /* STORE: raw copy */
            rc = sink_output(ex->sink, ex->sink_ctx, ex->inbuf, want,
                             &ex->crc, &ex->produced, ex->e->uncomp_size);
        } else {                             /* DEFLATE */
            rc = zip_extract_inflate_chunk(ex, want);
        }
        if (rc != XRDC_ZIP_OK) {
            return rc;
        }
    }
    return XRDC_ZIP_OK;
}


/*
 * WHAT: Confirm the extracted output matches the entry's declared size and CRC.
 * WHY:  Final integrity gate kept separate from the streaming loop (§8.3, pure).
 * HOW:  produced != uncomp_size ⇒ truncated/over-run (EBADF); CRC mismatch ⇒ ECRC.
 */
static int
zip_extract_verify(const zip_extract_t *ex)
{
    if (ex->produced != ex->e->uncomp_size) {
        return XRDC_ZIP_EBADF;           /* short/over: truncated or corrupt */
    }
    if ((uint32_t) ex->crc != ex->e->crc32) {
        return XRDC_ZIP_ECRC;
    }
    return XRDC_ZIP_OK;
}


int
brix_zip_member_extract(brix_zip_pread_fn pread, void *ctx,
                        const brix_zip_entry *e,
                        brix_zip_sink_fn sink, void *sink_ctx)
{
    zip_extract_t ex = {0};
    int           rc;

    if (e->method != 0 && e->method != 8) {
        return XRDC_ZIP_EMETHOD;
    }
    if (e->uncomp_size > XRDC_ZIP_MAX_OUTPUT) {
        return XRDC_ZIP_EBOMB;
    }

    ex.e         = e;
    ex.pread     = pread;
    ex.pread_ctx = ctx;
    ex.sink      = sink;
    ex.sink_ctx  = sink_ctx;
    ex.crc       = crc32(0L, Z_NULL, 0);

    rc = member_data_offset(pread, ctx, e->archive_size, e, &ex.data_off);
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }

    rc = zip_extract_setup(&ex);
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }

    rc = zip_extract_stream(&ex);
    zip_extract_teardown(&ex);
    if (rc != XRDC_ZIP_OK) {
        return rc;
    }
    return zip_extract_verify(&ex);
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

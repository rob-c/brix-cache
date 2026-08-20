/* stargz.c — the eStargz writer (phase-104 D15.8).
 *
 * Reframes a layer: same tar bytes, new gzip framing. A member boundary is
 * opened at the head of every file payload and every metadata run, the TOC
 * is appended as the last tar entry, and the fixed 51-byte footer names the
 * offset the TOC member starts at. Nothing here parses the tar itself — the
 * D6 reader does that, and this TU only asks it WHERE each entry's bytes
 * begin, then copies them through untouched. */
#include "stargz_internal.h"

#include "oci/digest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#define SGZ_IOBUF   (64u * 1024u)
#define SGZ_BLOCK   512
#define SGZ_LANDMARK_BYTE 0x0f     /* the format's landmark file content */

/* The blob under construction: the output fd, how far into it we are (the
 * TOC's offsets ARE this counter), the live gzip member, and the two hashes
 * every caller needs — the blob's own digest and the diff_id of the tar it
 * decompresses to. */
typedef struct {
    int                   fd;
    long long             off;
    z_stream              zs;
    int                   live;
    unsigned char         zbuf[SGZ_IOBUF];
    brix_oci_sha256_ctx_t blob;
    brix_oci_sha256_ctx_t plain;
    char                 *err;
    size_t                errlen;
} sgz_out_t;

static int sgz_fail(sgz_out_t *o, const char *what, const char *detail) {
    snprintf(o->err, o->errlen, "estargz: %s%s%s", what,
             detail != NULL ? ": " : "", detail != NULL ? detail : "");
    return -1;
}

/* Raw bytes straight into the blob: framing (gzip headers, the footer) and
 * everything deflate hands back. Advances the offset the TOC quotes. */
static int sgz_raw(sgz_out_t *o, const unsigned char *b, size_t n) {
    size_t done = 0;

    if (brix_oci_sha256_update(&o->blob, b, n) != 0)
        return sgz_fail(o, "blob digest", "sha256 update failed");
    while (done < n) {
        ssize_t w = write(o->fd, b + done, n - done);

        if (w < 0) {
            if (errno == EINTR)
                continue;
            return sgz_fail(o, "write", strerror(errno));
        }
        done += (size_t) w;
    }
    o->off += (long long) n;
    return 0;
}

static int sgz_begin(sgz_out_t *o) {
    memset(&o->zs, 0, sizeof(o->zs));
    if (deflateInit2(&o->zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        return sgz_fail(o, "gzip", "cannot start a member");
    o->live = 1;
    return 0;
}

/* Drive deflate until it stops producing, emitting each full window. */
static int sgz_pump(sgz_out_t *o, int flush) {
    for (;;) {
        int zrc;

        o->zs.next_out  = o->zbuf;
        o->zs.avail_out = sizeof(o->zbuf);
        zrc = deflate(&o->zs, flush);
        if (zrc == Z_STREAM_ERROR)
            return sgz_fail(o, "gzip", "deflate failed");
        if (sgz_raw(o, o->zbuf, sizeof(o->zbuf) - o->zs.avail_out) != 0)
            return -1;
        if (zrc == Z_STREAM_END)
            return 0;
        if (o->zs.avail_out != 0 && o->zs.avail_in == 0)
            return 0;
    }
}

/* Tar bytes into the live member. These are also the bytes the diff_id is
 * taken over, so the hash lives here and nowhere else. */
static int sgz_data(sgz_out_t *o, const unsigned char *b, size_t n) {
    if (brix_oci_sha256_update(&o->plain, b, n) != 0)
        return sgz_fail(o, "diff-id", "sha256 update failed");
    o->zs.next_in  = (unsigned char *) b;
    o->zs.avail_in = (uInt) n;
    return sgz_pump(o, Z_NO_FLUSH);
}

static int sgz_end(sgz_out_t *o) {
    int rc;

    o->zs.next_in  = NULL;
    o->zs.avail_in = 0;
    rc = sgz_pump(o, Z_FINISH);
    deflateEnd(&o->zs);
    o->live = 0;
    return rc;
}

static int sgz_zeros(sgz_out_t *o, size_t n) {
    unsigned char z[SGZ_BLOCK] = { 0 };

    while (n > 0) {
        size_t chunk = n < sizeof(z) ? n : sizeof(z);

        if (sgz_data(o, z, chunk) != 0)
            return -1;
        n -= chunk;
    }
    return 0;
}

/* Copy [off, off+len) of the plain tar into the live member, optionally
 * hashing it — a file payload's content digest is taken on this one pass,
 * not a second read of the same bytes. */
static int sgz_copy(sgz_out_t *o, int fd, long long off, long long len,
                    brix_oci_sha256_ctx_t *content) {
    unsigned char buf[SGZ_IOBUF];

    while (len > 0) {
        size_t  want = len < (long long) sizeof(buf)
                           ? (size_t) len : sizeof(buf);
        ssize_t got = pread(fd, buf, want, (off_t) off);

        if (got < 0) {
            if (errno == EINTR)
                continue;
            return sgz_fail(o, "read", strerror(errno));
        }
        if (got == 0)
            return sgz_fail(o, "layer", "truncated while re-framing");
        if (content != NULL
            && brix_oci_sha256_update(content, buf, (size_t) got) != 0)
            return sgz_fail(o, "content digest", "sha256 update failed");
        if (sgz_data(o, buf, (size_t) got) != 0)
            return -1;
        off += got;
        len -= got;
    }
    return 0;
}

/* ---- synthetic entries --------------------------------------------------- */

static void sgz_octal(char *dst, size_t width, unsigned long long v) {
    size_t i = width - 1;

    dst[i] = '\0';
    while (i-- > 0) {
        dst[i] = (char) ('0' + (v & 7));
        v >>= 3;
    }
}

/* A plain ustar header for one of the two entries this writer invents. Both
 * names are short ASCII and both are regular files, so no pax record is
 * ever needed here — the entries copied from the source keep whatever
 * headers they arrived with. */
static void sgz_ustar(unsigned char h[SGZ_BLOCK], const char *name,
                      long long size) {
    unsigned sum = 0;
    int      i;

    memset(h, 0, SGZ_BLOCK);
    memcpy(h, name, strlen(name));
    sgz_octal((char *) h + 100, 8, 0644);
    sgz_octal((char *) h + 108, 8, 0);
    sgz_octal((char *) h + 116, 8, 0);
    sgz_octal((char *) h + 124, 12, (unsigned long long) size);
    sgz_octal((char *) h + 136, 12, 0);
    h[156] = '0';
    memcpy(h + 257, "ustar", 5);
    memcpy(h + 263, "00", 2);
    memset(h + 148, ' ', 8);
    for (i = 0; i < SGZ_BLOCK; i++)
        sum += h[i];
    sgz_octal((char *) h + 148, 7, sum);
    h[155] = ' ';
}

/* One tar entry emitted from memory: header in its own member, payload (and
 * its 512-padding, which no reader looks at) in the next. Returns the blob
 * offset of the payload member, which is what the TOC records. */
static int sgz_emit(sgz_out_t *o, const char *name, const unsigned char *body,
                    size_t len, long long *payload_off) {
    unsigned char hdr[SGZ_BLOCK];

    sgz_ustar(hdr, name, (long long) len);
    if (sgz_begin(o) != 0 || sgz_data(o, hdr, sizeof(hdr)) != 0
        || sgz_end(o) != 0)
        return -1;
    *payload_off = o->off;
    if (len == 0)
        return 0;
    if (sgz_begin(o) != 0 || sgz_data(o, body, len) != 0
        || sgz_zeros(o, (SGZ_BLOCK - (len % SGZ_BLOCK)) % SGZ_BLOCK) != 0
        || sgz_end(o) != 0)
        return -1;
    return 0;
}

/* The 51-byte footer: an empty gzip member whose Extra field carries the
 * TOC's offset. Its size is fixed by the format precisely so a reader can
 * find the TOC with one ranged read of the blob's tail, which means it is
 * written byte by byte here rather than through deflate — zlib's empty
 * member is two bytes shorter than the stored-block form the format pins. */
static int sgz_footer(sgz_out_t *o, long long toc_off) {
    unsigned char f[BRIX_STARGZ_FOOTER_LEN] = {
        0x1f, 0x8b, 0x08, 0x04, 0, 0, 0, 0, 0, 0xff,   /* gzip, FEXTRA */
        0x1a, 0x00,                                    /* XLEN = 26 */
        'S',  'G',                                     /* SI1, SI2 */
        0x16, 0x00                                     /* LEN = 22 */
    };
    char buf[24];

    snprintf(buf, sizeof(buf), "%016llxSTARGZ", (unsigned long long) toc_off);
    memcpy(f + 16, buf, 22);
    f[38] = 0x01;                     /* final stored block, length zero */
    f[39] = 0x00; f[40] = 0x00; f[41] = 0xff; f[42] = 0xff;
    memset(f + 43, 0, 8);             /* CRC32 and ISIZE of nothing */
    return sgz_raw(o, f, sizeof(f));
}

int brix_stargz_is_meta(const char *name) {
    return strcmp(name, BRIX_STARGZ_TOC_NAME) == 0
        || strcmp(name, BRIX_STARGZ_LANDMARK) == 0
        || strcmp(name, BRIX_STARGZ_NO_LANDMARK) == 0;
}

/* ---- the conversion ------------------------------------------------------ */

/* Does this entry sit at the archive root under a name the format reserves?
 * Converting a layer that is already eStargz must DROP those, not carry a
 * second TOC and a second landmark into the output. */
static int sgz_reserved(const char *path) {
    while (path[0] == '/' || (path[0] == '.' && path[1] == '/'))
        path += (path[0] == '/') ? 1 : 2;
    return strchr(path, '/') == NULL && brix_stargz_is_meta(path);
}

static long long sgz_round(long long n) {
    return n + (SGZ_BLOCK - (n % SGZ_BLOCK)) % SGZ_BLOCK;
}

/* One source entry: its metadata run, then its payload in a member of its
 * own, then its TOC row. */
static int sgz_entry(sgz_out_t *o, int tarfd, const brix_tar_entry_t *e,
                     sgz_toc_t *toc, long long region, long long payload) {
    brix_oci_sha256_ctx_t ctx;
    brix_oci_digest_t     dig;
    char                  hex[BRIX_OCI_DIGEST_STRLEN];
    long long             member;

    if (sgz_begin(o) != 0
        || sgz_copy(o, tarfd, region, payload - region, NULL) != 0
        || sgz_end(o) != 0)
        return -1;
    if (e->size == 0)
        return sgz_toc_add(toc, e, 0, NULL);

    member = o->off;
    if (brix_oci_sha256_init(&ctx) != 0)
        return sgz_fail(o, "content digest", "sha256 init failed");
    /* The 512-padding after the content rides in the SAME member, which is
     * where a tar writer that flushes per entry puts it — and is why the
     * next entry's header still lands on a member boundary. It is outside
     * the content digest: that covers the file's bytes, not its framing. */
    if (sgz_begin(o) != 0 || sgz_copy(o, tarfd, payload, e->size, &ctx) != 0
        || sgz_copy(o, tarfd, payload + e->size,
                    sgz_round(e->size) - e->size, NULL) != 0
        || sgz_end(o) != 0) {
        brix_oci_sha256_abort(&ctx);
        return -1;
    }
    if (brix_oci_sha256_final(&ctx, &dig) != 0
        || brix_oci_digest_format(&dig, hex, sizeof(hex)) < 0)
        return sgz_fail(o, "content digest", "sha256 final failed");
    return sgz_toc_add(toc, e, member, hex);
}

/* Walk the plain tar on tarfd, emitting the reframed blob. */
static int sgz_walk(sgz_out_t *o, int tarfd, sgz_toc_t *toc,
                    brix_stargz_stats_t *st) {
    brix_tar_entry_t e;
    brix_tar_t      *t;
    long long        region = 0;
    int              rc;

    t = brix_tar_open_fd(tarfd, o->err, o->errlen);
    if (t == NULL)
        return -1;
    while ((rc = brix_tar_next(t, &e)) == 1) {
        long long payload = brix_tar_stream_offset(t);
        long long end     = payload + sgz_round(e.size);

        if (sgz_reserved(e.path)) {
            st->dropped++;
        } else if (sgz_entry(o, tarfd, &e, toc, region, payload) != 0) {
            brix_tar_close(t);
            return -1;                        /* o->err already says what */
        }
        region = end;
        if (brix_tar_skip(t) != 0) {
            rc = -1;
            break;
        }
    }
    if (rc < 0)
        sgz_fail(o, "source layer", brix_tar_error(t));
    brix_tar_close(t);
    return rc;
}

/* The TOC, as the last tar entry, followed by the end-of-archive marker —
 * all inside one member, so a reader that fetched the blob's tail has the
 * whole document. *toc_off gets the offset that member starts at, which is
 * the number the footer exists to carry. */
static int sgz_toc_member(sgz_out_t *o, const sgz_toc_t *toc,
                          long long *toc_off) {
    unsigned char hdr[SGZ_BLOCK];

    sgz_ustar(hdr, BRIX_STARGZ_TOC_NAME, (long long) toc->len);
    *toc_off = o->off;
    if (sgz_begin(o) != 0 || sgz_data(o, hdr, sizeof(hdr)) != 0
        || sgz_data(o, (const unsigned char *) toc->buf, toc->len) != 0
        || sgz_zeros(o, (SGZ_BLOCK - (toc->len % SGZ_BLOCK)) % SGZ_BLOCK) != 0
        || sgz_zeros(o, 2 * SGZ_BLOCK) != 0
        || sgz_end(o) != 0)
        return -1;
    return 0;
}

/* Nothing this converter emits is prioritized for prefetch, and the format
 * requires that be stated rather than implied: with no prioritized files
 * there MUST be a .no.prefetch.landmark, and it leads the archive. */
static int sgz_landmark(sgz_out_t *o, sgz_toc_t *toc) {
    unsigned char     body = SGZ_LANDMARK_BYTE;
    brix_tar_entry_t  e;
    brix_oci_digest_t dig;
    char              hex[BRIX_OCI_DIGEST_STRLEN];
    long long         payload = 0;

    if (sgz_emit(o, BRIX_STARGZ_NO_LANDMARK, &body, 1, &payload) != 0)
        return -1;
    if (brix_oci_sha256(&body, 1, &dig) != 0
        || brix_oci_digest_format(&dig, hex, sizeof(hex)) < 0)
        return sgz_fail(o, "landmark digest", "sha256 failed");
    memset(&e, 0, sizeof(e));
    snprintf(e.path, sizeof(e.path), "%s", BRIX_STARGZ_NO_LANDMARK);
    e.type = BRIX_TAR_REG;
    e.size = 1;
    e.mode = 0644;
    return sgz_toc_add(toc, &e, payload, hex);
}

/* Decompress the source into a scratch file the walk can pread. The tar
 * bytes have to be visible twice — once to the parser that says where each
 * entry begins, once to the copier that moves it — and a layer arrives as a
 * stream, not as something seekable. The file is unlinked at birth, so a
 * torn run leaves nothing behind. */
static int sgz_scratch(char *err, size_t errlen) {
    const char *dir = getenv("TMPDIR");
    char        path[1100];
    int         fd;

    snprintf(path, sizeof(path), "%s/brix-estargz-XXXXXX",
             dir != NULL && dir[0] != '\0' ? dir : "/tmp");
    fd = mkstemp(path);
    if (fd < 0) {
        snprintf(err, errlen, "estargz: scratch file: %s", strerror(errno));
        return -1;
    }
    unlink(path);
    return fd;
}

static int sgz_decompress(int in_fd, int tarfd, char *err, size_t errlen) {
    brix_tar_t *src = brix_tar_open_fd(in_fd, err, errlen);
    int         rc;

    if (src == NULL)
        return -1;
    rc = brix_tar_drain(src, tarfd);
    if (rc != 0)
        snprintf(err, errlen, "estargz: source layer: %s",
                 brix_tar_error(src));
    brix_tar_close(src);
    if (rc == 0 && lseek(tarfd, 0, SEEK_SET) != 0) {
        snprintf(err, errlen, "estargz: scratch rewind: %s", strerror(errno));
        return -1;
    }
    return rc;
}

static int sgz_start(sgz_out_t *o, sgz_toc_t *toc) {
    if (sgz_toc_begin(toc) != 0 || brix_oci_sha256_init(&o->blob) != 0
        || brix_oci_sha256_init(&o->plain) != 0)
        return sgz_fail(o, "out of memory", NULL);
    return 0;
}

/* landmark, then every source entry, then the TOC and the footer. */
static int sgz_body(sgz_out_t *o, int tarfd, sgz_toc_t *toc,
                    brix_stargz_stats_t *st) {
    long long toc_off = 0;

    if (sgz_landmark(o, toc) != 0 || sgz_walk(o, tarfd, toc, st) != 0
        || sgz_toc_end(toc) != 0 || sgz_toc_member(o, toc, &toc_off) != 0
        || sgz_footer(o, toc_off) != 0)
        return -1;
    st->entries   = toc->n;
    st->blob_size = o->off;
    return 0;
}

static int sgz_hex(brix_oci_sha256_ctx_t *c, char *out, size_t outlen) {
    brix_oci_digest_t d;

    if (brix_oci_sha256_final(c, &d) != 0
        || brix_oci_digest_format(&d, out, outlen) < 0)
        return -1;
    return 0;
}

/* The three digests the caller rewrites the manifest and config from. */
static int sgz_seal(sgz_out_t *o, const sgz_toc_t *toc,
                    brix_stargz_stats_t *st) {
    brix_oci_digest_t d;

    if (brix_oci_sha256(toc->buf, toc->len, &d) != 0
        || brix_oci_digest_format(&d, st->toc_digest,
                                  sizeof(st->toc_digest)) < 0
        || sgz_hex(&o->plain, st->diffid, sizeof(st->diffid)) != 0
        || sgz_hex(&o->blob, st->blob_digest, sizeof(st->blob_digest)) != 0)
        return sgz_fail(o, "digest", "sha256 failed");
    return 0;
}

static void sgz_discard(sgz_out_t *o) {
    brix_oci_sha256_abort(&o->plain);
    brix_oci_sha256_abort(&o->blob);
    if (o->live)
        deflateEnd(&o->zs);
}

int brix_stargz_convert(int in_fd, int out_fd, brix_stargz_stats_t *st,
                        char *err, size_t errlen) {
    sgz_out_t *o;
    sgz_toc_t  toc;
    int        tarfd, rc;

    memset(st, 0, sizeof(*st));
    tarfd = sgz_scratch(err, errlen);
    if (tarfd < 0)
        return -1;
    if (sgz_decompress(in_fd, tarfd, err, errlen) != 0) {
        close(tarfd);
        return -1;
    }
    o = calloc(1, sizeof(*o));
    if (o == NULL) {
        snprintf(err, errlen, "estargz: out of memory");
        close(tarfd);
        return -1;
    }
    o->fd     = out_fd;
    o->err    = err;
    o->errlen = errlen;
    err[0]    = '\0';

    rc = sgz_start(o, &toc);
    if (rc == 0)
        rc = sgz_body(o, tarfd, &toc, st);
    if (rc == 0)
        rc = sgz_seal(o, &toc, st);
    if (rc != 0)
        sgz_discard(o);
    sgz_toc_free(&toc);
    close(tarfd);
    free(o);
    return rc;
}

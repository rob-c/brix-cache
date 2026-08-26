/* tar.c — streaming pull-parser for OCI layer archives (phase-104 D6).
 *
 * WHAT: the tar.h contract — iterate ustar/pax/GNU entries from an fd,
 *       transparently inflating gzip (and zstd, when built in), with pax and
 *       GNU-long overrides resolved before an entry is handed out. A layer is
 *       a CHAIN of members/frames when a lazy-pull converter made it
 *       (eStargz, zstd:chunked); the source follows it to the end (D15.7).
 * WHY:  layers must stream: an image layer can be gigabytes, so the reader
 *       holds one header block, one body window and the decompressor state —
 *       flat memory whatever the archive claims. Every count that comes off
 *       the wire is bounds-checked before it sizes anything.
 * HOW:  a byte source (raw fd / inflate / zstd) feeds an exact-fill helper;
 *       brix_tar_next() frames 512-byte headers over it, verifies the
 *       checksum (unsigned sum, signed-sum fallback), parses NUL/space-
 *       terminated octal and GNU base-256 numerics, and loops internally
 *       over metadata entries ('x'/'g'/'L'/'K', unknown typeflags) until a
 *       real entry or EOF. Body reads enforce the fully-consumed contract:
 *       advancing with unread body bytes is caller misuse, reported -1.
 */
#include "oci/tar_internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysmacros.h>

#include "cvmfs/catalog/catalog_write.h"   /* cvmfs_xattr_pack */

int brix_tar_fail(brix_tar_t *t, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(t->err, sizeof(t->err), fmt, ap);
    va_end(ap);
    return -1;
}

/* ---- byte source: raw / gzip / zstd ------------------------------------- */

/* Ensure at least `want` unconsumed compressed bytes are in the window, or
 * that the input is at EOF. Compacts first, so a caller that has to look at
 * the next two bytes is not defeated by a window boundary falling between
 * them. 0 ok (in_eof set at EOF), -1 on read error. */
static int src_topup(brix_tar_t *t, size_t want) {
    if (t->in_len - t->in_off >= want || t->in_eof)
        return 0;
    if (t->in_off > 0) {
        memmove(t->inbuf, t->inbuf + t->in_off, t->in_len - t->in_off);
        t->in_len -= t->in_off;
        t->in_off = 0;
    }
    while (t->in_len < want) {
        ssize_t got = read(t->fd, t->inbuf + t->in_len,
                           sizeof(t->inbuf) - t->in_len);
        if (got < 0)
            return brix_tar_fail(t, "read: input error");
        if (got == 0) {
            t->in_eof = 1;
            break;
        }
        t->in_len += (size_t) got;
    }
    return 0;
}

/* A zstd stream header: either a data frame or one of the sixteen skippable
 * frame magics (0x184D2A50..5F, little-endian) a zstd:chunked producer uses
 * to carry its TOC — which may lead the stream, so the sniff has to accept
 * it or the whole layer is mistaken for an uncompressed tar. */
static int zstd_magic(const unsigned char *b) {
    if (b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd)
        return b[0] == 0x28;
    return b[1] == 0x2a && b[2] == 0x4d && b[3] == 0x18
           && (b[0] & 0xf0) == 0x50;
}

/* At a gzip member boundary: does another member follow? A layer produced by
 * eStargz — or by any `cat a.gz b.gz` — is a chain of members, and stopping
 * at the first one truncates the tar mid-stream. Trailing padding is not a
 * member and ends the source instead. 1 / 0 / -1. */
static int gz_more_members(brix_tar_t *t) {
    if (src_topup(t, 2) != 0)
        return -1;
    return t->in_len - t->in_off >= 2
           && t->inbuf[t->in_off] == 0x1f && t->inbuf[t->in_off + 1] == 0x8b;
}

/*
 * WHAT: Copy raw archive bytes from the buffered input into the caller window.
 * WHY:  Raw input has no codec state and should not share decompressor control
 *       flow.
 * HOW:  Top up once, cap the available span, copy it, and advance the offset.
 */
static int src_produce_raw(brix_tar_t *t, unsigned char *dst, size_t cap) {
    size_t n;

    if (src_topup(t, 1) != 0)
        return -1;
    if (t->in_off == t->in_len)
        return 0;
    n = t->in_len - t->in_off;
    if (n > cap)
        n = cap;
    memcpy(dst, t->inbuf + t->in_off, n);
    t->in_off += n;
    return (int) n;
}

/*
 * WHAT: Finish one gzip member and prepare the decoder for a following member.
 * WHY:  eStargz and concatenated gzip layers contain multiple members.
 * HOW:  Sniff the next member marker, mark final completion, or reset inflate.
 */
static int src_gzip_member_end(brix_tar_t *t) {
    int more = gz_more_members(t);

    if (more < 0)
        return -1;
    if (!more) {
        t->z_done = 1;
        return 0;
    }
    if (inflateReset(&t->zs) != Z_OK)
        return brix_tar_fail(t, "gzip: cannot start next member");
    return 1;
}

/*
 * WHAT: Produce decompressed bytes from a possibly concatenated gzip stream.
 * WHY:  A single output request may cross gzip member and input boundaries.
 * HOW:  Feed inflate until output appears or the final member terminates.
 */
static int src_produce_gzip(brix_tar_t *t, unsigned char *dst, size_t cap) {
    if (t->z_done)
        return 0;
    t->zs.next_out  = dst;
    t->zs.avail_out = (uInt) cap;
    while (t->zs.avail_out == cap) {
        int zrc;

        if (src_topup(t, 1) != 0)
            return -1;
        t->zs.next_in  = t->inbuf + t->in_off;
        t->zs.avail_in = (uInt) (t->in_len - t->in_off);
        if (t->zs.avail_in == 0 && t->in_eof)
            return brix_tar_fail(t, "gzip: truncated stream");
        zrc = inflate(&t->zs, Z_NO_FLUSH);
        t->in_off = t->in_len - t->zs.avail_in;
        if (zrc == Z_STREAM_END) {
            int member = src_gzip_member_end(t);

            if (member < 0)
                return -1;
            if (member == 0)
                break;
            continue;
        }
        if (zrc != Z_OK && zrc != Z_BUF_ERROR)
            return brix_tar_fail(t, "gzip: corrupt stream (zlib %d)", zrc);
    }
    return (int) (cap - t->zs.avail_out);
}

#ifdef BRIX_HAVE_ZSTD
/*
 * WHAT: Produce bytes across all frames in a zstd archive stream.
 * WHY:  zstd:chunked layers use independent data and metadata frames.
 * HOW:  Refill and drive the streaming decoder until it yields output or EOF.
 */
static int src_produce_zstd(brix_tar_t *t, unsigned char *dst, size_t cap) {
    ZSTD_outBuffer zo = { dst, cap, 0 };

    while (zo.pos == 0) {
        ZSTD_inBuffer zi;
        size_t        zrc;

        if (src_topup(t, 1) != 0)
            return -1;
        zi.src  = t->inbuf + t->in_off;
        zi.size = t->in_len - t->in_off;
        zi.pos  = 0;
        if (zi.size == 0 && t->in_eof)
            return 0;
        zrc = ZSTD_decompressStream(t->zds, &zo, &zi);
        t->in_off += zi.pos;
        if (ZSTD_isError(zrc))
            return brix_tar_fail(t, "zstd: %s", ZSTD_getErrorName(zrc));
        /* A zero return ends one frame, not a zstd:chunked source. */
        if (zi.pos == 0 && zo.pos == 0)
            return brix_tar_fail(t, "zstd: decoder made no progress");
    }
    return (int) zo.pos;
}
#endif

/*
 * WHAT: Produce up to cap uncompressed archive bytes into dst.
 * WHY:  Tar framing must be independent of the layer compression format.
 * HOW:  Dispatch to the isolated raw, gzip, or zstd source implementation.
 */
static int src_produce(brix_tar_t *t, unsigned char *dst, size_t cap) {
    if (t->comp == TAR_COMP_RAW)
        return src_produce_raw(t, dst, cap);
    if (t->comp == TAR_COMP_GZ)
        return src_produce_gzip(t, dst, cap);
#ifdef BRIX_HAVE_ZSTD
    return src_produce_zstd(t, dst, cap);
#else
    return brix_tar_fail(t, "zstd: reader built without zstd support");
#endif
}

int brix_tar_src(brix_tar_t *t, unsigned char *dst, size_t cap) {
    int got = src_produce(t, dst, cap);

    if (got > 0 && t->dig_on
        && brix_oci_sha256_update(&t->dig, dst, (size_t) got) != 0)
        return brix_tar_fail(t, "diff-id: sha256 update failed");
    if (got > 0)
        t->stream_off += got;
    return got;
}

int brix_tar_fill(brix_tar_t *t, unsigned char *dst, size_t n) {
    size_t done = 0;

    while (done < n) {
        int got = brix_tar_src(t, dst + done, n - done);

        if (got < 0)
            return -1;
        if (got == 0) {
            if (done == 0)
                return 0;
            return brix_tar_fail(t, "truncated archive: wanted %zu more bytes",
                                 n - done);
        }
        done += (size_t) got;
    }
    return 1;
}

/* Discard exactly n bytes through the body window. */
#include "tar_parse.c"

int brix_tar_next(brix_tar_t *t, brix_tar_entry_t *e) {
    if (entry_finish(t) != 0)
        return -1;

    for (;;) {
        unsigned char typeflag;
        int           rc = header_next(t);

        if (rc <= 0)
            return rc;

        typeflag = t->hdr[156];
        if (typeflag == 'x' || typeflag == 'g') {
            if (metadata_pax(t, typeflag) != 0)
                return -1;
            continue;
        }
        if (typeflag == 'L' || typeflag == 'K') {
            if (metadata_gnu_long(t, typeflag) != 0)
                return -1;
            continue;
        }
        if (typeflag_is_entry(typeflag)) {
            if (entry_build(t, typeflag, e) != 0)
                return -1;
            brix_tar_pax_reset_next(t);
            t->have_entry = 1;
            return 1;
        }
        if (metadata_unknown(t, typeflag) != 0)
            return -1;
    }
}

int brix_tar_read(brix_tar_t *t, void *buf, size_t n) {
    if (!t->have_entry)
        return brix_tar_fail(t, "API misuse: no current entry");
    if (t->remaining == 0)
        return 0;
    if (n > (uint64_t) t->remaining)
        n = (size_t) t->remaining;
    if (n > TAR_BODY_CAP)
        n = TAR_BODY_CAP;
    if (brix_tar_fill(t, (unsigned char *) buf, n) != 1)
        return -1;
    t->remaining -= (int64_t) n;
    return (int) n;
}

int brix_tar_skip(brix_tar_t *t) {
    if (!t->have_entry)
        return brix_tar_fail(t, "API misuse: no current entry");
    if (tar_discard(t, t->remaining) != 0)
        return -1;
    t->remaining = 0;
    return 0;
}

int64_t brix_tar_stream_offset(const brix_tar_t *t) {
    return t->stream_off;
}

int brix_tar_drain(brix_tar_t *t, int out_fd) {
    unsigned char buf[TAR_BODY_CAP];
    int           got;

    if (t->stream_off != 0)
        return brix_tar_fail(t, "API misuse: drain after the walk started");
    while ((got = brix_tar_src(t, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;

        while (off < got) {
            ssize_t w = write(out_fd, buf + off, (size_t) (got - off));

            if (w < 0) {
                if (errno == EINTR)
                    continue;
                return brix_tar_fail(t, "drain: write: %s", strerror(errno));
            }
            off += w;
        }
    }
    return got;                      /* 0 = clean end of stream, -1 = error */
}

/* ---- open/close ---------------------------------------------------------- */

brix_tar_t *brix_tar_open_fd(int fd, char *err, size_t errlen) {
    brix_tar_t *t = calloc(1, sizeof(*t));
    ssize_t     got;

    if (t == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    t->fd = fd;

    got = read(fd, t->inbuf, sizeof(t->inbuf));
    if (got < 0) {
        snprintf(err, errlen, "read: input error");
        free(t);
        return NULL;
    }
    t->in_len = (size_t) got;
    t->in_eof = (got == 0);

    if (got >= 2 && t->inbuf[0] == 0x1f && t->inbuf[1] == 0x8b) {
        t->comp = TAR_COMP_GZ;
        if (inflateInit2(&t->zs, 15 + 16) != Z_OK) {   /* +16: gzip wrapper */
            snprintf(err, errlen, "gzip: inflateInit failed");
            free(t);
            return NULL;
        }
        t->z_live = 1;
    } else if (got >= 4 && zstd_magic(t->inbuf)) {
#ifdef BRIX_HAVE_ZSTD
        t->comp = TAR_COMP_ZSTD;
        t->zds  = ZSTD_createDStream();
        if (t->zds == NULL) {
            snprintf(err, errlen, "zstd: DStream alloc failed");
            free(t);
            return NULL;
        }
#else
        snprintf(err, errlen, "zstd-compressed layer: rebuild with zstd "
                 "support (libzstd-devel) to ingest it");
        free(t);
        return NULL;
#endif
    } else {
        t->comp = TAR_COMP_RAW;
    }
    return t;
}

void brix_tar_close(brix_tar_t *t) {
    if (t == NULL)
        return;
    if (t->dig_on)
        brix_oci_sha256_abort(&t->dig);         /* unfinished capture */
    if (t->z_live)
        inflateEnd(&t->zs);
#ifdef BRIX_HAVE_ZSTD
    if (t->zds != NULL)
        ZSTD_freeDStream(t->zds);
#endif
    free(t);
}

/* The last error message (valid until the next call). */
const char *brix_tar_error(const brix_tar_t *t) {
    return t->err;
}

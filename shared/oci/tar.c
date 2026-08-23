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
static int tar_discard(brix_tar_t *t, int64_t n) {
    while (n > 0) {
        size_t step = n > (int64_t) sizeof(t->body) ? sizeof(t->body)
                                                    : (size_t) n;
        int rc = brix_tar_fill(t, t->body, step);

        if (rc <= 0)
            return rc < 0 ? -1
                          : brix_tar_fail(t, "truncated archive body");
        n -= (int64_t) step;
    }
    return 0;
}

/* ---- header field parsing ------------------------------------------------ */

/*
 * WHAT: Decode a GNU base-256 signed tar number.
 * WHY:  GNU writers use this representation for values outside octal fields.
 * HOW:  Sign-extend the high byte and reject positive int64 overflow.
 */
static int tar_num_binary(const unsigned char *f, size_t n, int64_t *out) {
    uint64_t v   = f[0] & 0x7f;
    int      neg = (f[0] & 0x40) != 0;
    size_t   i;

    if (neg)
        v |= ~(uint64_t) 0x7f;
    for (i = 1; i < n; i++) {
        if (!neg && v > (uint64_t) INT64_MAX >> 8)
            return -1;
        v = (v << 8) | f[i];
    }
    if (!neg && (int64_t) v < 0)
        return -1;
    *out = (int64_t) v;
    return 0;
}

/*
 * WHAT: Decode a space/NUL-padded POSIX octal tar number.
 * WHY:  Standard tar fields permit leading spaces and two trailing paddings.
 * HOW:  Skip the prefix, accumulate checked octal digits, then validate tail.
 */
static int tar_num_octal(const unsigned char *f, size_t n, int64_t *out) {
    uint64_t v = 0;
    size_t   i = 0;

    while (i < n && f[i] == ' ')
        i++;
    for (; i < n && f[i] >= '0' && f[i] <= '7'; i++) {
        if (v > (uint64_t) INT64_MAX >> 3)
            return -1;
        v = (v << 3) | (uint64_t) (f[i] - '0');
    }
    while (i < n && (f[i] == ' ' || f[i] == '\0'))
        i++;
    if (i != n)
        return -1;
    *out = (int64_t) v;
    return 0;
}

/*
 * WHAT: Decode either standard octal or GNU base-256 header numbers.
 * WHY:  Callers need one strict numeric-field contract for both tar dialects.
 * HOW:  Detect GNU's high-bit marker and delegate to the matching decoder.
 */
static int tar_num(const unsigned char *f, size_t n, int64_t *out) {
    if (n > 0 && (f[0] & 0x80))
        return tar_num_binary(f, n, out);
    return tar_num_octal(f, n, out);
}

/* Verify the header checksum: unsigned byte sum with the chksum field read
 * as spaces; tolerate the historical signed-sum variant. 0 ok / -1. */
static int tar_cksum_ok(const unsigned char *h) {
    unsigned usum = 0;
    long     ssum = 0;
    int64_t  want;
    size_t   i;

    if (tar_num(h + 148, 8, &want) != 0)
        return -1;
    for (i = 0; i < 512; i++) {
        unsigned char c = (i >= 148 && i < 156) ? (unsigned char) ' ' : h[i];

        usum += c;
        ssum += (signed char) c;
    }
    return ((int64_t) usum == want || (int64_t) ssum == want) ? 0 : -1;
}

/* Copy a fixed header text field, stopping at NUL, always terminating. */
static void tar_str(const unsigned char *f, size_t n, char *out, size_t outsz) {
    size_t len = 0;

    while (len < n && f[len] != '\0')
        len++;
    if (len >= outsz)
        len = outsz - 1;
    memcpy(out, f, len);
    out[len] = '\0';
}

static int hdr_is_zero(const unsigned char *h) {
    size_t i;

    for (i = 0; i < 512; i++)
        if (h[i] != 0)
            return 0;
    return 1;
}

/* ---- entry assembly ------------------------------------------------------ */

/* Join ustar prefix+name, honoring pax/GNU overrides (per-file, then global,
 * then the raw header). 0 ok / -1 (too long / empty). */
static int entry_path(brix_tar_t *t, int posix_magic, brix_tar_entry_t *e) {
    if (t->next.have_path) {
        memcpy(e->path, t->next.path, sizeof(e->path));
    } else if (t->glob.have_path) {
        memcpy(e->path, t->glob.path, sizeof(e->path));
    } else {
        char name[101], prefix[156];

        tar_str(t->hdr, 100, name, sizeof(name));
        tar_str(t->hdr + 345, 155, prefix, sizeof(prefix));
        if (posix_magic && prefix[0] != '\0') {
            int n = snprintf(e->path, sizeof(e->path), "%s/%s", prefix, name);

            if (n < 0 || (size_t) n >= sizeof(e->path))
                return brix_tar_fail(t, "entry path exceeds 4095 bytes");
        } else {
            memcpy(e->path, name, sizeof(name));
        }
    }
    if (e->path[0] == '\0')
        return brix_tar_fail(t, "entry with empty path");
    return 0;
}

/*
 * WHAT: Map a supported tar typeflag onto the public entry type.
 * WHY:  Entry assembly should not mix type dispatch with field parsing.
 * HOW:  Translate every POSIX real-entry flag and reject metadata flags.
 */
static int entry_type(brix_tar_t *t, unsigned char typeflag,
                      brix_tar_entry_t *e) {
    switch (typeflag) {
    case '0': case '\0': case '7': e->type = BRIX_TAR_REG;      break;
    case '1':                      e->type = BRIX_TAR_HARDLINK; break;
    case '2':                      e->type = BRIX_TAR_SYMLINK;  break;
    case '3':                      e->type = BRIX_TAR_CHR;      break;
    case '4':                      e->type = BRIX_TAR_BLK;      break;
    case '5':                      e->type = BRIX_TAR_DIR;      break;
    case '6':                      e->type = BRIX_TAR_FIFO;     break;
    default:
        return brix_tar_fail(t, "internal: unmapped typeflag %d", typeflag);
    }
    return 0;
}

/*
 * WHAT: Resolve a link target from per-file, global, or raw-header metadata.
 * WHY:  Pax and GNU overrides have defined precedence over the ustar field.
 * HOW:  Copy the highest-precedence available representation into the entry.
 */
static void entry_link(brix_tar_t *t, brix_tar_entry_t *e) {
    if (t->next.have_link)
        memcpy(e->linkname, t->next.linkname, sizeof(e->linkname));
    else if (t->glob.have_link)
        memcpy(e->linkname, t->glob.linkname, sizeof(e->linkname));
    else
        tar_str(t->hdr + 157, 100, e->linkname, sizeof(e->linkname));
}

/*
 * WHAT: Decode mode, uid, and gid into a tar entry.
 * WHY:  Ownership fields share override precedence but require distinct errors.
 * HOW:  Apply per-file/global values first and parse raw numeric fields last.
 */
static int entry_permissions(brix_tar_t *t, brix_tar_entry_t *e) {
    int64_t v;

    if (tar_num(t->hdr + 100, 8, &v) != 0)
        return brix_tar_fail(t, "bad mode field on %s", e->path);
    e->mode = (mode_t) (v & 07777);

    if (t->next.have_uid)
        e->uid = (uid_t) t->next.uid;
    else if (t->glob.have_uid)
        e->uid = (uid_t) t->glob.uid;
    else if (tar_num(t->hdr + 108, 8, &v) == 0)
        e->uid = (uid_t) v;
    else
        return brix_tar_fail(t, "bad uid field on %s", e->path);

    if (t->next.have_gid)
        e->gid = (gid_t) t->next.gid;
    else if (t->glob.have_gid)
        e->gid = (gid_t) t->glob.gid;
    else if (tar_num(t->hdr + 116, 8, &v) == 0)
        e->gid = (gid_t) v;
    else
        return brix_tar_fail(t, "bad gid field on %s", e->path);
    return 0;
}

/*
 * WHAT: Resolve entry modification time and effective body size.
 * WHY:  Pax overrides and non-regular size semantics must be applied together.
 * HOW:  Resolve fields by precedence, reject negatives, then set body padding.
 */
static int entry_extent(brix_tar_t *t, brix_tar_entry_t *e) {
    int64_t v;

    if (t->next.have_mtime)
        e->mtime = t->next.mtime;
    else if (t->glob.have_mtime)
        e->mtime = t->glob.mtime;
    else if (tar_num(t->hdr + 136, 12, &v) == 0)
        e->mtime = v;
    else
        return brix_tar_fail(t, "bad mtime field on %s", e->path);

    if (t->next.have_size)
        v = t->next.size;
    else if (t->glob.have_size)
        v = t->glob.size;
    else if (tar_num(t->hdr + 124, 12, &v) != 0)
        return brix_tar_fail(t, "bad size field on %s", e->path);
    if (v < 0)
        return brix_tar_fail(t, "negative size on %s", e->path);

    /* POSIX ignores size metadata on non-regular entries. */
    e->size      = (e->type == BRIX_TAR_REG) ? v : 0;
    t->remaining = e->size;
    t->pad       = (size_t) ((512 - (e->size % 512)) % 512);
    return 0;
}

/*
 * WHAT: Decode device numbers for character and block entries.
 * WHY:  Other entry types must ignore device fields that writers may populate.
 * HOW:  Parse major/minor only for device types and combine them with makedev.
 */
static int entry_device(brix_tar_t *t, brix_tar_entry_t *e) {
    int64_t maj;
    int64_t min;

    if (e->type != BRIX_TAR_CHR && e->type != BRIX_TAR_BLK)
        return 0;
    if (tar_num(t->hdr + 329, 8, &maj) != 0 ||
        tar_num(t->hdr + 337, 8, &min) != 0)
        return brix_tar_fail(t, "bad device numbers on %s", e->path);
    e->rdev = makedev((unsigned) maj, (unsigned) min);
    return 0;
}

/*
 * WHAT: Pack accumulated pax extended attributes onto an entry.
 * WHY:  Consumers require one bounded stable blob rather than parser arrays.
 * HOW:  Pack only non-empty sets and expose the resulting internal buffer.
 */
static int entry_xattrs(brix_tar_t *t, brix_tar_entry_t *e) {
    int packed;

    if (t->xcount == 0)
        return 0;
    packed = cvmfs_xattr_pack(t->xkeys, t->xvals, t->xlens, t->xcount,
                              t->xblob, sizeof(t->xblob));
    if (packed < 0)
        return brix_tar_fail(t, "xattr set on %s exceeds pack bounds",
                             e->path);
    e->xattr     = (const char *) t->xblob;
    e->xattr_len = (size_t) packed;
    return 0;
}

/*
 * WHAT: Map one verified real-entry header and its overrides onto an entry.
 * WHY:  Callers need fully resolved metadata before any body bytes are exposed.
 * HOW:  Assemble type, path, link, ownership, extent, device, and xattrs.
 */
static int entry_build(brix_tar_t *t, unsigned char typeflag,
                       brix_tar_entry_t *e) {
    int posix_magic = memcmp(t->hdr + 257, "ustar\0", 6) == 0;

    memset(e, 0, sizeof(*e));
    if (entry_type(t, typeflag, e) != 0)
        return -1;

    if (entry_path(t, posix_magic, e) != 0)
        return -1;
    entry_link(t, e);
    if (entry_permissions(t, e) != 0 || entry_extent(t, e) != 0 ||
        entry_device(t, e) != 0 || entry_xattrs(t, e) != 0)
        return -1;
    return 0;
}

/* Read a metadata body ('x'/'g' pax, 'L'/'K' GNU-long) of claimed `size`
 * into t->pax (with its 512-pad), bounds-checked. 0 ok / -1. */
static int meta_body(brix_tar_t *t, int64_t size, size_t cap) {
    if (size < 0 || (uint64_t) size > cap)
        return brix_tar_fail(t, "oversized metadata entry (%lld bytes)",
                             (long long) size);
    if (size > 0 && brix_tar_fill(t, t->pax, (size_t) size) != 1)
        return -1;
    return tar_discard(t, (int64_t) ((512 - (size % 512)) % 512));
}

/* Take a GNU 'L' (longname) / 'K' (longlink) body into the per-file
 * override. The body is a NUL-padded string. */
static int gnu_long(brix_tar_t *t, int64_t size, int is_link) {
    char  *dst    = is_link ? t->next.linkname : t->next.path;
    size_t dstcap = 4096;
    size_t len;

    if (meta_body(t, size, dstcap + 512) != 0)
        return -1;
    len = (size_t) size;
    while (len > 0 && t->pax[len - 1] == '\0')
        len--;
    if (len >= dstcap)
        return brix_tar_fail(t, "GNU long %s exceeds 4095 bytes",
                             is_link ? "linkname" : "name");
    memcpy(dst, t->pax, len);
    dst[len] = '\0';
    if (is_link) t->next.have_link = 1; else t->next.have_path = 1;
    return 0;
}

/*
 * WHAT: Close the previously returned entry before reading another header.
 * WHY:  The API requires callers to consume bodies while tar padding is ours.
 * HOW:  Reject unread body bytes, discard padding, and clear entry state.
 */
static int entry_finish(brix_tar_t *t) {
    if (t->have_entry && t->remaining > 0)
        return brix_tar_fail(t, "API misuse: current body not fully consumed "
                             "(%lld bytes left)", (long long) t->remaining);
    if (!t->have_entry)
        return 0;
    if (tar_discard(t, (int64_t) t->pad) != 0)
        return -1;
    t->pad        = 0;
    t->have_entry = 0;
    return 0;
}

/*
 * WHAT: Read and validate the next non-terminal 512-byte tar header.
 * WHY:  End markers and checksums must be settled before type dispatch.
 * HOW:  Read one block, validate the optional second zero block, then checksum.
 */
static int header_next(brix_tar_t *t) {
    int rc = brix_tar_fill(t, t->hdr, 512);

    if (rc <= 0)
        return rc;
    if (!hdr_is_zero(t->hdr)) {
        if (tar_cksum_ok(t->hdr) != 0)
            return brix_tar_fail(t, "header checksum mismatch");
        return 1;
    }
    rc = brix_tar_fill(t, t->hdr, 512);
    if (rc < 0)
        return -1;
    if (rc == 0 || hdr_is_zero(t->hdr))
        return 0;
    return brix_tar_fail(t, "data after end-of-archive marker");
}

/*
 * WHAT: Consume and apply a pax per-file or global metadata entry.
 * WHY:  Pax records affect the following real header but are not entries.
 * HOW:  Parse its size, read its padded body, and apply the selected scope.
 */
static int metadata_pax(brix_tar_t *t, unsigned char typeflag) {
    int64_t size;

    if (tar_num(t->hdr + 124, 12, &size) != 0)
        return brix_tar_fail(t, "bad pax header size");
    if (meta_body(t, size, sizeof(t->pax)) != 0)
        return -1;
    return brix_tar_pax_apply(t, (size_t) size, typeflag == 'g');
}

/*
 * WHAT: Consume a GNU long-name or long-link metadata entry.
 * WHY:  GNU tar stores oversized text fields immediately before real entries.
 * HOW:  Parse the body size and install it as the matching per-file override.
 */
static int metadata_gnu_long(brix_tar_t *t, unsigned char typeflag) {
    int64_t size;

    if (tar_num(t->hdr + 124, 12, &size) != 0)
        return brix_tar_fail(t, "bad GNU long-header size");
    return gnu_long(t, size, typeflag == 'K');
}

/*
 * WHAT: Determine whether a typeflag represents a supported real entry.
 * WHY:  Metadata and extension records must never surface as filesystem data.
 * HOW:  Accept the NUL regular-file flag or a POSIX real-entry digit.
 */
static int typeflag_is_entry(unsigned char typeflag) {
    return typeflag == '\0' || strchr("01234567", typeflag) != NULL;
}

/*
 * WHAT: Consume an unsupported extension entry without surfacing it.
 * WHY:  Unknown records may be followed by valid entries and cannot end a walk.
 * HOW:  Validate size, discard body plus padding, and clear per-file overrides.
 */
static int metadata_unknown(brix_tar_t *t, unsigned char typeflag) {
    int64_t size;

    if (tar_num(t->hdr + 124, 12, &size) != 0 || size < 0)
        return brix_tar_fail(t, "bad size on unknown typeflag %d", typeflag);
    if (tar_discard(t, size + (512 - (size % 512)) % 512) != 0)
        return -1;
    brix_tar_pax_reset_next(t);
    return 0;
}

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

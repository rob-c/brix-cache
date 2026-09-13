/*
 * frm_zip.c — store-only ZIP32 writer/reader (phase-115 W3.1)
 *
 * WHAT: the container behind tape dataset archives; see frm_zip.h.
 *
 * WHY:  one MSS object per dataset instead of one per file, readable by any
 *       ZIP tool, with per-member offset reads on recall.
 *
 * HOW:  local headers carry the CRC back-patched after the copy (we stream the
 *       source once and never buffer a member), the central directory is
 *       written by finish(), and the reader locates the directory from the end
 *       record within the last 64 KiB + 22 bytes. Every multi-byte field is
 *       little-endian per APPNOTE; nothing here depends on nginx.
 */

#include "frm_zip.h"
#include "core/compat/crc32_ieee.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ZIP_LFH_SIG        0x04034b50u
#define ZIP_CDH_SIG        0x02014b50u
#define ZIP_EOCD_SIG       0x06054b50u
#define ZIP_LFH_LEN        30u
#define ZIP_CDH_LEN        46u
#define ZIP_EOCD_LEN       22u
#define ZIP_COMMENT_MAX    65535u
#define ZIP32_LIMIT        0xffffffffull
#define ZIP_VERSION_STORE  20u          /* 2.0: deflate/store, no ZIP64 */
#define ZIP_FLAG_UTF8      0x0800u
#define ZIP_EXT_ATTR_REG   0x81a40000u  /* -rw-r--r-- in the UNIX high word */
#define ZIP_CD_MAX_BYTES   (64u * 1024u * 1024u)
#define ZIP_IO_CHUNK       65536u

struct brix_zip_writer_s {
    int               fd;
    uint64_t          off;        /* next byte to write */
    uint64_t          cd_bytes;   /* central directory size so far */
    brix_zip_entry_t *ents;
    unsigned          n;
    unsigned          cap;
    uint32_t          dos_time;
    uint32_t          dos_date;
};

/* ---- byte helpers -------------------------------------------------------- */

static void
put16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v & 0xffu);
    p[1] = (uint8_t) ((v >> 8) & 0xffu);
}

static void
put32(uint8_t *p, uint32_t v)
{
    put16(p, v & 0xffffu);
    put16(p + 2, v >> 16);
}

static uint32_t
get16(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8);
}

static uint32_t
get32(const uint8_t *p)
{
    return get16(p) | (get16(p + 2) << 16);
}

static int
write_full(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += n;
        len -= (size_t) n;
    }
    return 0;
}

static int
pread_full(int fd, uint8_t *buf, size_t len, uint64_t off)
{
    while (len > 0) {
        ssize_t n = pread(fd, buf, len, (off_t) off);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            errno = (n == 0) ? EIO : errno;
            return -1;
        }
        buf += n;
        len -= (size_t) n;
        off += (uint64_t) n;
    }
    return 0;
}

/* ---- names --------------------------------------------------------------- */

static int
zip_segment_ok(const char *seg, size_t len)
{
    if (len == 0) {
        return 0;                                   /* "//" or leading/trailing '/' */
    }
    if (seg[0] == '.' && (len == 1 || (len == 2 && seg[1] == '.'))) {
        return 0;                                   /* "." or ".." */
    }
    return 1;
}

int
brix_zip_name_ok(const char *name)
{
    const char *p, *seg;

    if (name == NULL || name[0] == '\0' || strnlen(name, BRIX_ZIP_NAME_MAX) >= BRIX_ZIP_NAME_MAX) {
        return 0;
    }
    for (seg = p = name; ; p++) {
        unsigned char ch = (unsigned char) *p;
        if (ch == '\\' || (ch != '\0' && (ch < 0x20u || ch == 0x7fu))) {
            return 0;
        }
        if (ch != '/' && ch != '\0') {
            continue;
        }
        if (!zip_segment_ok(seg, (size_t) (p - seg))) {
            return 0;
        }
        if (ch == '\0') {
            return 1;
        }
        seg = p + 1;
    }
}

/* ---- writer -------------------------------------------------------------- */

static void
zip_dos_stamp(uint32_t *dtime, uint32_t *ddate)
{
    time_t    now = time(NULL);
    struct tm tm;

    if (gmtime_r(&now, &tm) == NULL || tm.tm_year + 1900 < 1980) {
        *dtime = 0;
        *ddate = (1u << 5) | 1u;                    /* 1980-01-01 00:00 */
        return;
    }
    *dtime = ((uint32_t) tm.tm_hour << 11) | ((uint32_t) tm.tm_min << 5) | ((uint32_t) tm.tm_sec >> 1);
    *ddate = ((uint32_t) (tm.tm_year + 1900 - 1980) << 9) | ((uint32_t) (tm.tm_mon + 1) << 5)
             | (uint32_t) tm.tm_mday;
}

brix_zip_writer_t *
brix_zip_writer_open(int fd)
{
    brix_zip_writer_t *w = calloc(1, sizeof(*w));

    if (w == NULL) {
        return NULL;
    }
    w->fd = fd;
    zip_dos_stamp(&w->dos_time, &w->dos_date);
    return w;
}

static int
writer_reserve(brix_zip_writer_t *w)
{
    unsigned          cap;
    brix_zip_entry_t *grown;

    if (w->n < w->cap) {
        return 0;
    }
    cap = (w->cap == 0) ? 16u : w->cap * 2u;
    grown = realloc(w->ents, (size_t) cap * sizeof(*grown));
    if (grown == NULL) {
        return -1;
    }
    w->ents = grown;
    w->cap = cap;
    return 0;
}

/* ZIP32 admission for one more member of `nlen` name bytes and `size` data
 * bytes: entry count, member size, and the final archive size (data so far +
 * this member + the whole central directory + end record) must all fit. */
static int
writer_fits(const brix_zip_writer_t *w, size_t nlen, uint64_t size)
{
    uint64_t after_data = w->off + ZIP_LFH_LEN + nlen + size;
    uint64_t cd_total = w->cd_bytes + ZIP_CDH_LEN + nlen;

    if (w->n >= BRIX_ZIP_MAX_ENTRIES || size >= ZIP32_LIMIT) {
        return 0;
    }
    return after_data + cd_total + ZIP_EOCD_LEN < ZIP32_LIMIT;
}

static int
writer_local_header(const brix_zip_writer_t *w, const char *name, size_t nlen, uint64_t size)
{
    uint8_t h[ZIP_LFH_LEN];

    put32(h, ZIP_LFH_SIG);
    put16(h + 4, ZIP_VERSION_STORE);
    put16(h + 6, ZIP_FLAG_UTF8);
    put16(h + 8, 0);                                /* method: store */
    put16(h + 10, w->dos_time);
    put16(h + 12, w->dos_date);
    put32(h + 14, 0);                               /* crc: back-patched */
    put32(h + 18, (uint32_t) size);
    put32(h + 22, (uint32_t) size);
    put16(h + 26, (uint32_t) nlen);
    put16(h + 28, 0);                               /* extra length */
    if (write_full(w->fd, h, sizeof(h)) != 0) {
        return -1;
    }
    return write_full(w->fd, (const uint8_t *) name, nlen);
}

/* Stream exactly `size` bytes from src_fd into the archive; CRC into *crc. */
static int
writer_copy(int dst_fd, int src_fd, uint64_t size, uint32_t *crc)
{
    uint8_t *buf = malloc(ZIP_IO_CHUNK);
    int      rc = 0;

    if (buf == NULL) {
        return -1;
    }
    *crc = 0;
    while (size > 0 && rc == 0) {
        size_t  want = (size > ZIP_IO_CHUNK) ? ZIP_IO_CHUNK : (size_t) size;
        ssize_t n = read(src_fd, buf, want);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            errno = (n == 0) ? EIO : errno;         /* source shrank under us */
            rc = -1;
            break;
        }
        *crc = brix_crc32_ieee_update(*crc, buf, (size_t) n);
        rc = write_full(dst_fd, buf, (size_t) n);
        size -= (uint64_t) n;
    }
    free(buf);
    return rc;
}

int
brix_zip_writer_add(brix_zip_writer_t *w, const char *name, int src_fd,
                    uint64_t size, brix_zip_entry_t *out)
{
    size_t            nlen;
    brix_zip_entry_t *e;
    uint8_t           crc_le[4];

    if (!brix_zip_name_ok(name)) {
        errno = EINVAL;
        return -1;
    }
    nlen = strlen(name);
    if (!writer_fits(w, nlen, size)) {
        errno = EFBIG;
        return -1;
    }
    if (writer_reserve(w) != 0) {
        return -1;
    }
    e = &w->ents[w->n];
    memset(e, 0, sizeof(*e));
    memcpy(e->name, name, nlen + 1);
    e->size = size;
    e->lfh_off = w->off;

    if (writer_local_header(w, name, nlen, size) != 0 || writer_copy(w->fd, src_fd, size, &e->crc) != 0) {
        return -1;
    }
    put32(crc_le, e->crc);
    if (pwrite(w->fd, crc_le, sizeof(crc_le), (off_t) (e->lfh_off + 14u)) != (ssize_t) sizeof(crc_le)) {
        return -1;
    }
    w->off += ZIP_LFH_LEN + nlen + size;
    w->cd_bytes += ZIP_CDH_LEN + nlen;
    w->n++;
    if (out != NULL) {
        *out = *e;
    }
    return 0;
}

static int
writer_central_entry(const brix_zip_writer_t *w, const brix_zip_entry_t *e)
{
    uint8_t h[ZIP_CDH_LEN];
    size_t  nlen = strlen(e->name);

    put32(h, ZIP_CDH_SIG);
    put16(h + 4, ZIP_VERSION_STORE);                /* version made by */
    put16(h + 6, ZIP_VERSION_STORE);                /* version needed */
    put16(h + 8, ZIP_FLAG_UTF8);
    put16(h + 10, 0);                               /* method: store */
    put16(h + 12, w->dos_time);
    put16(h + 14, w->dos_date);
    put32(h + 16, e->crc);
    put32(h + 20, (uint32_t) e->size);
    put32(h + 24, (uint32_t) e->size);
    put16(h + 28, (uint32_t) nlen);
    put16(h + 30, 0);                               /* extra */
    put16(h + 32, 0);                               /* comment */
    put16(h + 34, 0);                               /* disk */
    put16(h + 36, 0);                               /* internal attrs */
    put32(h + 38, ZIP_EXT_ATTR_REG);
    put32(h + 42, (uint32_t) e->lfh_off);
    if (write_full(w->fd, h, sizeof(h)) != 0) {
        return -1;
    }
    return write_full(w->fd, (const uint8_t *) e->name, nlen);
}

int
brix_zip_writer_finish(brix_zip_writer_t *w)
{
    uint8_t  eocd[ZIP_EOCD_LEN];
    uint64_t cd_off = w->off;
    unsigned i;

    for (i = 0; i < w->n; i++) {
        if (writer_central_entry(w, &w->ents[i]) != 0) {
            return -1;
        }
    }
    put32(eocd, ZIP_EOCD_SIG);
    put16(eocd + 4, 0);                             /* this disk */
    put16(eocd + 6, 0);                             /* directory disk */
    put16(eocd + 8, w->n);
    put16(eocd + 10, w->n);
    put32(eocd + 12, (uint32_t) w->cd_bytes);
    put32(eocd + 16, (uint32_t) cd_off);
    put16(eocd + 20, 0);                            /* comment length */
    if (write_full(w->fd, eocd, sizeof(eocd)) != 0) {
        return -1;
    }
    w->off = cd_off + w->cd_bytes + ZIP_EOCD_LEN;
    return 0;
}

unsigned
brix_zip_writer_count(const brix_zip_writer_t *w)
{
    return w->n;
}

const brix_zip_entry_t *
brix_zip_writer_entry(const brix_zip_writer_t *w, unsigned i)
{
    return (i < w->n) ? &w->ents[i] : NULL;
}

void
brix_zip_writer_close(brix_zip_writer_t *w)
{
    if (w == NULL) {
        return;
    }
    free(w->ents);
    free(w);
}

/* ---- reader -------------------------------------------------------------- */

typedef struct {
    uint64_t cd_off;
    uint64_t cd_size;
    unsigned count;
} zip_eocd_t;

/* Scan the tail of the file for the end-of-central-directory record; the
 * record is the LAST one whose comment length reaches exactly the file end. */
static int
zip_find_eocd(int fd, zip_eocd_t *out)
{
    struct stat sb;
    uint64_t    tail, base;
    uint8_t    *buf;
    size_t      i;
    int         found = 0;

    if (fstat(fd, &sb) != 0) {
        return -1;
    }
    if (sb.st_size < (off_t) ZIP_EOCD_LEN) {
        errno = EINVAL;
        return -1;
    }
    tail = (uint64_t) sb.st_size;
    if (tail > ZIP_EOCD_LEN + ZIP_COMMENT_MAX) {
        tail = ZIP_EOCD_LEN + ZIP_COMMENT_MAX;
    }
    base = (uint64_t) sb.st_size - tail;
    buf = calloc((size_t) tail, 1);
    if (buf == NULL) {
        return -1;
    }
    if (pread_full(fd, buf, (size_t) tail, base) != 0) {
        free(buf);
        return -1;
    }
    for (i = (size_t) tail - ZIP_EOCD_LEN + 1; i-- > 0 && !found; ) {
        if (get32(buf + i) == ZIP_EOCD_SIG && i + ZIP_EOCD_LEN + get16(buf + i + 20) == (size_t) tail) {
            out->count = get16(buf + i + 10);
            out->cd_size = get32(buf + i + 12);
            out->cd_off = get32(buf + i + 16);
            found = 1;
        }
    }
    free(buf);
    if (!found || out->cd_off + out->cd_size > (uint64_t) sb.st_size) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Decode one central-directory header at p (len bytes remain). Returns the
 * bytes consumed, 0 on a malformed record. *usable says whether the entry is
 * a safely-named stored member. */
static size_t
zip_decode_cdh(const uint8_t *p, size_t len, brix_zip_entry_t *e, int *usable)
{
    uint32_t method, csize, nlen, xlen, clen;
    size_t   total;

    if (len < ZIP_CDH_LEN || get32(p) != ZIP_CDH_SIG) {
        return 0;
    }
    method = get16(p + 10);
    csize = get32(p + 20);
    nlen = get16(p + 28);
    xlen = get16(p + 30);
    clen = get16(p + 32);
    total = ZIP_CDH_LEN + nlen + xlen + clen;
    if (total > len) {
        return 0;
    }
    memset(e, 0, sizeof(*e));
    e->crc = get32(p + 16);
    e->size = get32(p + 24);
    e->lfh_off = get32(p + 42);
    *usable = 0;
    if (nlen < BRIX_ZIP_NAME_MAX) {
        memcpy(e->name, p + ZIP_CDH_LEN, nlen);
        e->name[nlen] = '\0';
        *usable = (method == 0 && csize == e->size && brix_zip_name_ok(e->name));
    }
    return total;
}

int
brix_zip_index(int fd, brix_zip_index_cb cb, void *ud, unsigned *skipped_out)
{
    zip_eocd_t       eocd;
    uint8_t         *cd;
    size_t           pos = 0;
    unsigned         i, skipped = 0;
    brix_zip_entry_t e;

    if (zip_find_eocd(fd, &eocd) != 0) {
        return -1;
    }
    if (eocd.cd_size > ZIP_CD_MAX_BYTES) {
        errno = EFBIG;
        return -1;
    }
    cd = malloc((size_t) eocd.cd_size + 1u);
    if (cd == NULL || pread_full(fd, cd, (size_t) eocd.cd_size, eocd.cd_off) != 0) {
        free(cd);
        return -1;
    }
    for (i = 0; i < eocd.count; i++) {
        int    usable, stop = 0;
        size_t used = zip_decode_cdh(cd + pos, (size_t) eocd.cd_size - pos, &e, &usable);
        if (used == 0) {
            free(cd);
            errno = EINVAL;
            return -1;
        }
        pos += used;
        if (!usable) {
            skipped++;
        } else {
            stop = cb(ud, &e);
        }
        if (stop) {
            break;
        }
    }
    free(cd);
    if (skipped_out != NULL) {
        *skipped_out = skipped;
    }
    return 0;
}

int
brix_zip_extract(int fd, const brix_zip_entry_t *e, int dst_fd)
{
    uint8_t  h[ZIP_LFH_LEN];
    uint8_t *buf;
    uint64_t off, left = e->size;
    uint32_t crc = 0;
    int      rc = 0;

    if (pread_full(fd, h, sizeof(h), e->lfh_off) != 0) {
        return -1;
    }
    if (get32(h) != ZIP_LFH_SIG) {
        errno = EINVAL;
        return -1;
    }
    if (get16(h + 8) != 0) {
        errno = ENOTSUP;
        return -1;
    }
    off = e->lfh_off + ZIP_LFH_LEN + get16(h + 26) + get16(h + 28);
    buf = malloc(ZIP_IO_CHUNK);
    if (buf == NULL) {
        return -1;
    }
    while (left > 0 && rc == 0) {
        size_t want = (left > ZIP_IO_CHUNK) ? ZIP_IO_CHUNK : (size_t) left;
        rc = pread_full(fd, buf, want, off);
        if (rc == 0) {
            crc = brix_crc32_ieee_update(crc, buf, want);
            rc = write_full(dst_fd, buf, want);
            off += want;
            left -= want;
        }
    }
    free(buf);
    if (rc == 0 && crc != e->crc) {
        errno = EIO;
        rc = -1;
    }
    return rc;
}

/* rpmhdr.c — clean-room RPM package header reader (phase-104 D12.2).
 *
 * WHAT: implement rpmhdr.h: lead (96 B) → signature header (parsed for its
 *       length, padded to 8) → main header (retained) → payload (streamed
 *       through sha256 only). Typed accessors over the retained regions.
 * WHY:  see rpmhdr.h. The oracle for every byte read here is the Appendix-X
 *       Python walker that a stock EL9 dnf consumed first try.
 * HOW:  a header region = 16-byte preamble (magic 8e ad e8 + version 01 +
 *       reserved + il + dl) + il×16-byte index entries + dl data bytes, both
 *       malloc'd and bounds-capped before the read. Accessors re-validate
 *       offset/count against dl on every lookup, so a lying index entry is
 *       an absent tag, never an out-of-region read.
 */
#define _POSIX_C_SOURCE 200809L
#include "rpm/rpmhdr.h"

#include "oci/digest.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RPM_LEAD_LEN   96
#define RPM_LEAD_MAGIC "\xed\xab\xee\xdb"
#define RPM_HDR_MAGIC  "\x8e\xad\xe8\x01"

/* rpm.org index-entry types. */
#define RPM_T_INT16    3
#define RPM_T_INT32    4
#define RPM_T_STRING   6
#define RPM_T_STRARRAY 8
#define RPM_T_I18N     9

typedef struct {
    unsigned char *index;    /* il × 16-byte entries */
    unsigned char *data;     /* dl bytes */
    uint32_t       il, dl;
} rpm_region_t;

struct brix_rpm_pkg_s {
    rpm_region_t sig;
    rpm_region_t hdr;
    char         pkgid[BRIX_OCI_SHA256_HEXLEN + 1];
    int64_t      file_size;
    int64_t      hdr_start, hdr_end;
    /* STRING_ARRAY iteration cursors, one per tag so the file-list walk
     * (BASENAMES + DIRNAMES interleaved) stays O(1) amortized per element. */
    struct { uint32_t tag, idx, off; int live; } cur[4];
    unsigned     cur_next;
};

static int rpm_fail(char *err, size_t errlen, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    if (err != NULL && errlen > 0)
        vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
    return -1;
}

static uint32_t be32(const unsigned char *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static uint16_t be16(const unsigned char *p) {
    return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}

/* Read exactly n bytes, feeding the pkgid hash. 0 ok / -1 short-or-error. */
static int read_hashed(int fd, brix_oci_sha256_ctx_t *h, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t         got = 0;

    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;
        got += (size_t) r;
    }
    return brix_oci_sha256_update(h, buf, n);
}

/* Load one header region (signature or main) at the current file offset.
 * Every message names the file: these surface through `brixrpm createrepo`'s
 * skip warnings, where "which package?" is the whole question. */
static int region_load(int fd, brix_oci_sha256_ctx_t *h, rpm_region_t *r,
                       const char *what, const char *path, char *err,
                       size_t errlen) {
    unsigned char pre[16];

    if (read_hashed(fd, h, pre, sizeof(pre)) != 0)
        return rpm_fail(err, errlen, "%s: truncated %s header preamble",
                        path, what);
    if (memcmp(pre, RPM_HDR_MAGIC, 4) != 0)
        return rpm_fail(err, errlen, "%s: %s header magic mismatch", path,
                        what);
    r->il = be32(pre + 8);
    r->dl = be32(pre + 12);
    if (r->il > BRIX_RPM_IL_MAX)
        return rpm_fail(err, errlen, "%s: %s header il %u exceeds %d",
                        path, what, r->il, BRIX_RPM_IL_MAX);
    if (r->dl > BRIX_RPM_DL_MAX)
        return rpm_fail(err, errlen, "%s: %s header dl %u exceeds %u",
                        path, what, r->dl, BRIX_RPM_DL_MAX);

    r->index = malloc(r->il > 0 ? (size_t) r->il * 16 : 1);
    r->data  = malloc(r->dl > 0 ? r->dl : 1);
    if (r->index == NULL || r->data == NULL)
        return rpm_fail(err, errlen, "%s: out of memory loading %s header",
                        path, what);
    if (read_hashed(fd, h, r->index, (size_t) r->il * 16) != 0 ||
        read_hashed(fd, h, r->data, r->dl) != 0)
        return rpm_fail(err, errlen, "%s: truncated %s header body", path,
                        what);
    return 0;
}

/* Locate a tag's index entry; every use re-validates bounds afterwards. */
static int ent_find(const rpm_region_t *r, uint32_t tag, uint32_t *type,
                    uint32_t *off, uint32_t *cnt) {
    uint32_t i;

    for (i = 0; i < r->il; i++) {
        const unsigned char *e = r->index + (size_t) i * 16;
        if (be32(e) == tag) {
            *type = be32(e + 4);
            *off  = be32(e + 8);
            *cnt  = be32(e + 12);
            return 0;
        }
    }
    return -1;
}

/* NUL-bounded string starting at data[off]; NULL when unterminated. */
static const char *region_str(const rpm_region_t *r, uint32_t off) {
    const void *z;

    if (off >= r->dl)
        return NULL;
    z = memchr(r->data + off, '\0', r->dl - off);
    return z != NULL ? (const char *) (r->data + off) : NULL;
}

static int region_u32(const rpm_region_t *r, uint32_t tag, uint32_t idx,
                      uint32_t *out) {
    uint32_t type, off, cnt;

    if (ent_find(r, tag, &type, &off, &cnt) != 0 || idx >= cnt)
        return -1;
    if (type == RPM_T_INT32) {
        if (off > r->dl || cnt > (r->dl - off) / 4)
            return -1;
        *out = be32(r->data + off + (size_t) idx * 4);
        return 0;
    }
    if (type == RPM_T_INT16) {
        if (off > r->dl || cnt > (r->dl - off) / 2)
            return -1;
        *out = be16(r->data + off + (size_t) idx * 2);
        return 0;
    }
    return -1;
}

/*
 * WHAT: Parse the RPM lead, signature header, padding, and main header.
 * WHY:  Payload streaming starts only after both bounded metadata regions validate.
 * HOW:  Verify lead fields, load regions, consume alignment, and record offsets.
 */
static int pkg_headers(brix_rpm_pkg_t *p, int fd, brix_oci_sha256_ctx_t *hash,
                       const char *path, char *err, size_t errlen) {
    unsigned char     lead[RPM_LEAD_LEN];
    int64_t           consumed;
    uint32_t          padding;

    if (read_hashed(fd, hash, lead, sizeof(lead)) != 0)
        return rpm_fail(err, errlen, "%s: truncated lead", path);
    if (memcmp(lead, RPM_LEAD_MAGIC, 4) != 0)
        return rpm_fail(err, errlen, "%s: not an RPM (lead magic)", path);
    if (be16(lead + 78) != 5)
        return rpm_fail(err, errlen, "%s: unsupported signature type %u",
                        path, be16(lead + 78));

    if (region_load(fd, hash, &p->sig, "signature", path, err, errlen) != 0)
        return -1;
    consumed = RPM_LEAD_LEN + 16 + (int64_t) p->sig.il * 16 + p->sig.dl;
    padding = (uint32_t) ((8 - consumed % 8) % 8);
    if (padding > 0) {
        unsigned char bytes[8];

        if (read_hashed(fd, hash, bytes, padding) != 0)
            return rpm_fail(err, errlen, "%s: truncated signature padding", path);
    }
    p->hdr_start = consumed + padding;
    if (region_load(fd, hash, &p->hdr, "main", path, err, errlen) != 0)
        return -1;
    p->hdr_end = p->hdr_start + 16 + (int64_t) p->hdr.il * 16 + p->hdr.dl;
    return 0;
}

/*
 * WHAT: Stream and hash the RPM payload after its parsed header regions.
 * WHY:  Package identity covers the full file without retaining payload bytes.
 * HOW:  Read fixed chunks through SHA-256 and update the final file size.
 */
static int pkg_payload(brix_rpm_pkg_t *p, int fd, brix_oci_sha256_ctx_t *hash,
                       const char *path, char *err, size_t errlen) {
    unsigned char tail[65536];
    int64_t       consumed = p->hdr_end;

    for (;;) {
        ssize_t r = read(fd, tail, sizeof(tail));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return rpm_fail(err, errlen, "%s: read: %s", path,
                            strerror(errno));
        }
        if (r == 0)
            break;
        if (brix_oci_sha256_update(hash, tail, (size_t) r) != 0)
            return rpm_fail(err, errlen, "sha256 failure");
        consumed += r;
    }
    p->file_size = consumed;
    return 0;
}

/* Parse the whole file through an initialized hash ctx. 0 ok / -1 + err. */
static int pkg_parse(brix_rpm_pkg_t *p, int fd, brix_oci_sha256_ctx_t *h,
                     const char *path, char *err, size_t errlen) {
    static const uint32_t required[] = {
        BRIX_RPMTAG_NAME, BRIX_RPMTAG_VERSION,
        BRIX_RPMTAG_RELEASE, BRIX_RPMTAG_ARCH
    };
    brix_oci_digest_t digest;

    if (pkg_headers(p, fd, h, path, err, errlen) != 0 ||
        pkg_payload(p, fd, h, path, err, errlen) != 0)
        return -1;
    if (brix_oci_sha256_final(h, &digest) != 0)
        return rpm_fail(err, errlen, "sha256 failure");
    memcpy(p->pkgid, digest.hex, sizeof(p->pkgid));

    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        if (brix_rpm_str(p, required[i]) == NULL)
            return rpm_fail(err, errlen, "%s: required tag %u missing",
                            path, required[i]);
    }
    return 0;
}

brix_rpm_pkg_t *brix_rpm_open(const char *path, char *err, size_t errlen) {
    brix_rpm_pkg_t       *p;
    brix_oci_sha256_ctx_t h;
    int                   fd, rc;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        rpm_fail(err, errlen, "open %s: %s", path, strerror(errno));
        return NULL;
    }
    p = calloc(1, sizeof(*p));
    if (p == NULL || brix_oci_sha256_init(&h) != 0) {
        rpm_fail(err, errlen, "out of memory");
        free(p);
        close(fd);
        return NULL;
    }

    rc = pkg_parse(p, fd, &h, path, err, errlen);
    close(fd);
    if (rc != 0) {
        brix_oci_sha256_abort(&h);    /* no-op if final already consumed it */
        brix_rpm_close(p);
        return NULL;
    }
    return p;
}

void brix_rpm_close(brix_rpm_pkg_t *p) {
    if (p == NULL)
        return;
    free(p->sig.index);
    free(p->sig.data);
    free(p->hdr.index);
    free(p->hdr.data);
    free(p);
}

int brix_rpm_file_sha256(const char *path, char *hex, size_t hexlen,
                         char *err, size_t errlen) {
    brix_oci_sha256_ctx_t h;
    brix_oci_digest_t     d;
    unsigned char         buf[65536];
    int                   fd;

    if (hexlen < 65)
        return rpm_fail(err, errlen, "%s: digest buffer too small", path);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return rpm_fail(err, errlen, "open %s: %s", path, strerror(errno));
    if (brix_oci_sha256_init(&h) != 0) {
        close(fd);
        return rpm_fail(err, errlen, "sha256 failure");
    }
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            brix_oci_sha256_abort(&h);
            return rpm_fail(err, errlen, "%s: read: %s", path,
                            strerror(errno));
        }
        if (r == 0)
            break;
        if (brix_oci_sha256_update(&h, buf, (size_t) r) != 0) {
            close(fd);
            brix_oci_sha256_abort(&h);
            return rpm_fail(err, errlen, "sha256 failure");
        }
    }
    close(fd);
    if (brix_oci_sha256_final(&h, &d) != 0)
        return rpm_fail(err, errlen, "sha256 failure");
    memcpy(hex, d.hex, strlen(d.hex) + 1);   /* sha256: 64 hex + NUL */
    return 0;
}

const char *brix_rpm_pkgid(const brix_rpm_pkg_t *p) {
    return p->pkgid;
}

int64_t brix_rpm_size_bytes(const brix_rpm_pkg_t *p) {
    return p->file_size;
}

void brix_rpm_header_range(const brix_rpm_pkg_t *p, int64_t *start,
                           int64_t *end) {
    *start = p->hdr_start;
    *end   = p->hdr_end;
}

const char *brix_rpm_str(brix_rpm_pkg_t *p, uint32_t tag) {
    uint32_t type, off, cnt;

    if (ent_find(&p->hdr, tag, &type, &off, &cnt) != 0 || cnt == 0)
        return NULL;
    if (type != RPM_T_STRING && type != RPM_T_I18N)
        return NULL;
    return region_str(&p->hdr, off);    /* I18N: first string = C locale */
}

uint32_t brix_rpm_count(brix_rpm_pkg_t *p, uint32_t tag) {
    uint32_t type, off, cnt;

    if (ent_find(&p->hdr, tag, &type, &off, &cnt) != 0)
        return 0;
    return cnt;
}

int brix_rpm_u32(brix_rpm_pkg_t *p, uint32_t tag, uint32_t idx,
                 uint32_t *out) {
    return region_u32(&p->hdr, tag, idx, out);
}

int brix_rpm_sig_u32(brix_rpm_pkg_t *p, uint32_t tag, uint32_t *out) {
    return region_u32(&p->sig, tag, 0, out);
}

const char *brix_rpm_stra(brix_rpm_pkg_t *p, uint32_t tag, uint32_t idx) {
    uint32_t    type, off, cnt, i, start;
    unsigned    slot, k;
    const char *s;

    if (ent_find(&p->hdr, tag, &type, &off, &cnt) != 0 || idx >= cnt)
        return NULL;
    if (type != RPM_T_STRARRAY)
        return NULL;

    /* Resume from this tag's cursor when the caller iterates forward. */
    i     = 0;
    start = off;
    slot  = ~0u;
    for (k = 0; k < 4; k++) {
        if (p->cur[k].live && p->cur[k].tag == tag) {
            slot = k;
            if (p->cur[k].idx <= idx) {
                i     = p->cur[k].idx;
                start = p->cur[k].off;
            }
            break;
        }
    }
    for (; i < idx; i++) {
        s = region_str(&p->hdr, start);
        if (s == NULL)
            return NULL;
        start += (uint32_t) strlen(s) + 1;
    }
    s = region_str(&p->hdr, start);
    if (s == NULL)
        return NULL;

    if (slot == ~0u) {
        slot = p->cur_next;
        p->cur_next = (p->cur_next + 1) % 4;
    }
    p->cur[slot].live = 1;
    p->cur[slot].tag  = tag;
    p->cur[slot].idx  = idx;
    p->cur[slot].off  = start;
    return s;
}

uint32_t brix_rpm_nfiles(brix_rpm_pkg_t *p) {
    return brix_rpm_count(p, BRIX_RPMTAG_BASENAMES);
}

int brix_rpm_file(brix_rpm_pkg_t *p, uint32_t i, char *path, size_t pathlen,
                  uint32_t *mode, int *ghost) {
    const char *base, *dir;
    uint32_t    dix, m = 0, fl = 0;
    int         n;

    base = brix_rpm_stra(p, BRIX_RPMTAG_BASENAMES, i);
    if (base == NULL || brix_rpm_u32(p, BRIX_RPMTAG_DIRINDEXES, i, &dix) != 0)
        return -1;
    dir = brix_rpm_stra(p, BRIX_RPMTAG_DIRNAMES, dix);
    if (dir == NULL)
        return -1;
    n = snprintf(path, pathlen, "%s%s", dir, base);
    if (n < 0 || (size_t) n >= pathlen)
        return -1;

    if (mode != NULL) {
        (void) brix_rpm_u32(p, BRIX_RPMTAG_FILEMODES, i, &m);
        *mode = m;
    }
    if (ghost != NULL) {
        (void) brix_rpm_u32(p, BRIX_RPMTAG_FILEFLAGS, i, &fl);
        *ghost = (fl & BRIX_RPMFILE_GHOST) != 0;
    }
    return 0;
}

int brix_rpm_path_sane(const char *path) {
    const char *p = path;

    while (*p != '\0') {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '/' || p[2] == '\0') &&
            (p == path || p[-1] == '/'))
            return 0;
        p++;
    }
    return 1;
}

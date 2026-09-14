/* stargz_toc.c — the `stargz.index.json` document (phase-104 D15.8).
 *
 * One growable buffer, one entry-append call, and the two encodings the
 * format needs that JSON does not give for free: RFC3339 modtimes and
 * base64 xattr values. Every append is bounds-checked through sgz_toc_put,
 * which latches a failure so the caller checks once at the end instead of
 * after every field. */
#include "stargz_internal.h"

#include "cvmfs/catalog/catalog_write.h"   /* cvmfs_xattr_unpack */

#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <time.h>

#define SGZ_TOC_CAP0 (64u * 1024u)

/* Append raw bytes, growing by doubling. A failure is latched rather than
 * returned: a half-built document is never serialized either way. */
static void sgz_toc_put(sgz_toc_t *t, const char *s, size_t n) {
    if (t->failed)
        return;
    if (t->len + n + 1 > t->cap) {
        size_t want = t->cap ? t->cap : SGZ_TOC_CAP0;
        char  *grown;

        while (want < t->len + n + 1)
            want *= 2;
        grown = realloc(t->buf, want);
        if (grown == NULL) {
            t->failed = 1;
            return;
        }
        t->buf = grown;
        t->cap = want;
    }
    memcpy(t->buf + t->len, s, n);
    t->len += n;
    t->buf[t->len] = '\0';
}

static void sgz_puts(sgz_toc_t *t, const char *s) {
    sgz_toc_put(t, s, strlen(s));
}

static void sgz_putf(sgz_toc_t *t, const char *fmt, long long v) {
    char num[32];

    sgz_toc_put(t, num, (size_t) snprintf(num, sizeof(num), fmt, v));
}

/* A JSON string literal, quotes included. Control bytes go out as \u00xx —
 * a tar path may legally contain them and an unescaped one would make the
 * whole TOC unparseable for every reader. */
static void sgz_putstr(sgz_toc_t *t, const char *s, size_t n) {
    size_t i;

    sgz_toc_put(t, "\"", 1);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char) s[i];
        char          esc[8];

        if (c == '"' || c == '\\') {
            esc[0] = '\\';
            esc[1] = (char) c;
            sgz_toc_put(t, esc, 2);
        } else if (c < 0x20) {
            sgz_toc_put(t, esc, (size_t) snprintf(esc, sizeof(esc),
                                                  "\\u%04x", c));
        } else {
            sgz_toc_put(t, (const char *) &c, 1);
        }
    }
    sgz_toc_put(t, "\"", 1);
}

/* The TOC carries entry names the way path.Clean leaves them: no leading
 * "./" or "/", no trailing "/" on a directory. That is the spelling a
 * snapshotter joins its lookups from, so a name that disagrees with it is
 * a file the mount cannot find. */
static void sgz_putname(sgz_toc_t *t, const char *path) {
    size_t n;

    while (path[0] == '/' || (path[0] == '.' && path[1] == '/'))
        path += (path[0] == '/') ? 1 : 2;
    n = strlen(path);
    while (n > 0 && path[n - 1] == '/')
        n--;
    sgz_putstr(t, path, n);
}

static const char *sgz_typename(brix_tar_type_t ty) {
    switch (ty) {
    case BRIX_TAR_DIR:      return "dir";
    case BRIX_TAR_SYMLINK:  return "symlink";
    case BRIX_TAR_HARDLINK: return "hardlink";
    case BRIX_TAR_CHR:      return "char";
    case BRIX_TAR_BLK:      return "block";
    case BRIX_TAR_FIFO:     return "fifo";
    case BRIX_TAR_REG:      break;
    }
    return "reg";
}

/* "2026-08-19T12:34:56Z". An mtime gmtime_r cannot represent is written as
 * the empty string, which the format defines as "zero/unknown" — better
 * than emitting a year the reader will reject. */
static void sgz_put_modtime(sgz_toc_t *t, int64_t mtime) {
    struct tm  tm;
    time_t     tv = (time_t) mtime;
    char       buf[40];

    if (gmtime_r(&tv, &tm) == NULL
        || strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        sgz_puts(t, "\"\"");
        return;
    }
    sgz_putstr(t, buf, strlen(buf));
}

/* {"key":"<base64 value>", ...} from the reader's packed xattr blob. */
static void sgz_put_xattrs(sgz_toc_t *t, const brix_tar_entry_t *e) {
    const unsigned char *blob = (const unsigned char *) e->xattr;
    int                  n, i;

    if (blob == NULL || e->xattr_len == 0)
        return;
    n = cvmfs_xattr_count(blob, e->xattr_len);
    if (n <= 0)
        return;
    sgz_puts(t, ",\"xattrs\":{");
    for (i = 0; i < n; i++) {
        const char          *key;
        const unsigned char *val;
        size_t               klen, vlen;
        unsigned char       *b64;
        int                  enc;

        if (cvmfs_xattr_unpack(blob, e->xattr_len, (size_t) i, &key, &klen,
                               &val, &vlen) != 0)
            break;
        if (i > 0)
            sgz_puts(t, ",");
        sgz_putstr(t, key, klen);
        sgz_puts(t, ":");
        b64 = malloc(4 * ((vlen + 2) / 3) + 4);
        if (b64 == NULL) {
            t->failed = 1;
            break;
        }
        enc = EVP_EncodeBlock(b64, val, (int) vlen);
        sgz_putstr(t, (const char *) b64, enc > 0 ? (size_t) enc : 0);
        free(b64);
    }
    sgz_puts(t, "}");
}

int sgz_toc_begin(sgz_toc_t *t) {
    memset(t, 0, sizeof(*t));
    sgz_puts(t, "{\"version\":1,\"entries\":[");
    return t->failed ? -1 : 0;
}

int sgz_toc_add(sgz_toc_t *t, const brix_tar_entry_t *e, long long offset,
                const char *content) {
    if (t->n > 0)
        sgz_puts(t, ",");
    sgz_puts(t, "{\"name\":");
    sgz_putname(t, e->path);
    sgz_puts(t, ",\"type\":\"");
    sgz_puts(t, sgz_typename(e->type));
    sgz_puts(t, "\",\"modtime\":");
    sgz_put_modtime(t, e->mtime);
    sgz_putf(t, ",\"mode\":%lld", (long long) (e->mode & 07777));
    sgz_putf(t, ",\"uid\":%lld", (long long) e->uid);
    sgz_putf(t, ",\"gid\":%lld", (long long) e->gid);

    if (e->type == BRIX_TAR_SYMLINK || e->type == BRIX_TAR_HARDLINK) {
        sgz_puts(t, ",\"linkName\":");
        sgz_putname(t, e->linkname);
    }
    if (e->type == BRIX_TAR_CHR || e->type == BRIX_TAR_BLK) {
        sgz_putf(t, ",\"devMajor\":%lld", (long long) major(e->rdev));
        sgz_putf(t, ",\"devMinor\":%lld", (long long) minor(e->rdev));
    }
    if (e->type == BRIX_TAR_REG) {
        sgz_putf(t, ",\"size\":%lld", (long long) e->size);
        /* offset/digest exist only where there are payload bytes to find:
         * an empty file has no gzip member of its own to point at. */
        if (e->size > 0) {
            sgz_putf(t, ",\"offset\":%lld", offset);
            sgz_puts(t, ",\"digest\":");
            sgz_putstr(t, content, strlen(content));
            sgz_puts(t, ",\"chunkDigest\":");
            sgz_putstr(t, content, strlen(content));
        }
    }
    sgz_put_xattrs(t, e);
    sgz_puts(t, "}");
    t->n++;
    return t->failed ? -1 : 0;
}

int sgz_toc_end(sgz_toc_t *t) {
    sgz_puts(t, "]}");
    return t->failed ? -1 : 0;
}

void sgz_toc_free(sgz_toc_t *t) {
    free(t->buf);
    memset(t, 0, sizeof(*t));
}

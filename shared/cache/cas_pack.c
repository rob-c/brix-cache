/* cas_pack.c — packed (log-structured) CAS cache backend. See cas_pack.h.
 *
 * On-disk (host-endian, cache-local, never interchanged):
 *   segment record  pack/seg-<n>.dat @ off:
 *     u32 magic "BXS1" · u16 klen · u8 fmt · u8 rsvd · u32 crc32(data) ·
 *     u64 stored_len · u64 raw_len · key[klen] · data[stored_len]
 *   journal record  pack/index.log:
 *     u32 magic "BXI1" · u8 op(1 put·2 del) · u8 fmt · u16 klen · u32 seg ·
 *     u32 crc32(record with this field zeroed) · u64 off · u64 stored_len ·
 *     u64 raw_len · key[klen]
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1        /* openat/pread/renameat under strict -std=c11 */
#endif
#include "cache/cas_pack.h"
#include "cvmfs/platform/platform.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <zlib.h>
#include <zstd.h>

#define SEG_MAGIC   0x31535842u                /* "BXS1" */
#define IDX_MAGIC   0x31495842u                /* "BXI1" */
#define SEG_HDR     28u
#define IDX_HDR     40u
#define OP_PUT      1u
#define OP_DEL      2u
#define FSYNC_BATCH (8L * 1024 * 1024)
#define TIER_MIN    64u                        /* don't bother compressing under this */

/* ---- little fixed-offset codec (avoids struct padding) ------------------ */

static void put32(unsigned char *b, uint32_t v) { memcpy(b, &v, 4); }
static void put64(unsigned char *b, uint64_t v) { memcpy(b, &v, 8); }
static uint32_t get32(const unsigned char *b) { uint32_t v; memcpy(&v, b, 4); return v; }
static uint64_t get64(const unsigned char *b) { uint64_t v; memcpy(&v, b, 8); return v; }

static uint32_t crc_of(const void *buf, size_t len) {
    return (uint32_t) crc32(crc32(0L, Z_NULL, 0), buf, (uInt) len);
}

static int write_full(int fd, const void *buf, size_t len) {
    const char *b = buf; size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, b + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t) w;
    }
    return 0;
}

static int pread_full(int fd, void *buf, size_t len, uint64_t off) {
    char *b = buf; size_t got = 0;
    while (got < len) {
        ssize_t r = pread(fd, b + got, len - got, (off_t) (off + got));
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        got += (size_t) r;
    }
    return 0;
}

/* ---- in-memory index: open-addressed table + key arena ------------------ */

static uint64_t fnv1a(const char *k, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char) k[i]; h *= 1099511628211ull; }
    return h;
}

static const char *ent_key(const brix_cas_pack_t *p, const brix_pack_ent_t *e) {
    return p->keys + e->koff;
}

static brix_pack_ent_t *tab_find(brix_cas_pack_t *p, const char *key, size_t klen) {
    if (p->tab_cap == 0) return NULL;
    uint32_t mask = p->tab_cap - 1;
    uint32_t i = (uint32_t) fnv1a(key, klen) & mask;
    for (uint32_t n = 0; n < p->tab_cap; n++, i = (i + 1) & mask) {
        brix_pack_ent_t *e = &p->tab[i];
        if (e->state == 0) return NULL;
        if (e->state == 1 && e->klen == klen
            && memcmp(ent_key(p, e), key, klen) == 0) return e;
    }
    return NULL;
}

static int tab_grow(brix_cas_pack_t *p) {
    uint32_t ncap = p->tab_cap ? p->tab_cap * 2 : 1024;
    brix_pack_ent_t *nt = calloc(ncap, sizeof(*nt));
    if (nt == NULL) return -1;
    uint32_t mask = ncap - 1;
    for (uint32_t i = 0; i < p->tab_cap; i++) {
        brix_pack_ent_t *e = &p->tab[i];
        if (e->state != 1) continue;
        uint32_t j = (uint32_t) fnv1a(ent_key(p, e), e->klen) & mask;
        while (nt[j].state == 1) j = (j + 1) & mask;
        nt[j] = *e;
    }
    free(p->tab);
    p->tab = nt; p->tab_cap = ncap; p->tab_used = p->tab_live;
    return 0;
}

/* Find-or-create the slot for `key`; sets *existed for a live duplicate. */
static brix_pack_ent_t *tab_insert(brix_cas_pack_t *p, const char *key,
                                   size_t klen, int *existed) {
    *existed = 0;
    if ((p->tab_used + 1) * 10 >= p->tab_cap * 7 && tab_grow(p) != 0) return NULL;
    uint32_t mask = p->tab_cap - 1;
    uint32_t i = (uint32_t) fnv1a(key, klen) & mask;
    brix_pack_ent_t *tomb = NULL;
    for (;; i = (i + 1) & mask) {
        brix_pack_ent_t *e = &p->tab[i];
        if (e->state == 0) {
            if (tomb != NULL) e = tomb; else p->tab_used++;
            if (p->keys_len + klen + 1 > p->keys_cap) {
                uint32_t nc = p->keys_cap ? p->keys_cap * 2 : 65536;
                while (nc < p->keys_len + klen + 1) nc *= 2;
                char *nk = realloc(p->keys, nc);
                if (nk == NULL) return NULL;
                p->keys = nk; p->keys_cap = nc;
            }
            e->koff = p->keys_len;
            memcpy(p->keys + p->keys_len, key, klen);
            p->keys[p->keys_len + klen] = '\0';
            p->keys_len += (uint32_t) klen + 1;
            e->klen = (uint16_t) klen;
            e->state = 1; e->hits = 0;
            p->tab_live++;
            return e;
        }
        if (e->state == 2) { if (tomb == NULL) tomb = e; continue; }
        if (e->klen == klen && memcmp(ent_key(p, e), key, klen) == 0) {
            *existed = 1;
            return e;
        }
    }
}

/* ---- paths + fds -------------------------------------------------------- */

static void seg_path(char *buf, size_t n, uint32_t seg) {
    snprintf(buf, n, "pack/seg-%08u.dat", seg);
}

static int seg_open(brix_cas_pack_t *p, uint32_t seg, int flags) {
    char nm[64];
    seg_path(nm, sizeof(nm), seg);
    return openat(p->basefd, nm, flags, 0644);
}

/* ---- journal ------------------------------------------------------------ */

static int idx_build(unsigned char *rec, int op, uint8_t fmt, uint32_t seg,
                     uint64_t off, uint64_t stored, uint64_t raw,
                     const char *key, size_t klen) {
    put32(rec, IDX_MAGIC);
    rec[4] = (unsigned char) op;
    rec[5] = fmt;
    put32(rec + 8, seg);
    put32(rec + 12, 0);
    put64(rec + 16, off);
    put64(rec + 24, stored);
    put64(rec + 32, raw);
    rec[6] = (unsigned char) (klen & 0xff);
    rec[7] = (unsigned char) (klen >> 8);
    memcpy(rec + IDX_HDR, key, klen);
    put32(rec + 12, crc_of(rec, IDX_HDR + klen));
    return (int) (IDX_HDR + klen);
}

static int idx_append(brix_cas_pack_t *p, int op, const brix_pack_ent_t *e,
                      const char *key) {
    unsigned char rec[IDX_HDR + BRIX_PACK_KMAX];
    int n = idx_build(rec, op, e->fmt, e->seg, e->off, e->stored_len,
                      e->raw_len, key, e->klen);
    return write_full(p->idxfd, rec, (size_t) n);
}

/* Rewrite the journal as one put-record per live entry (after segment drops,
 * so replay never chases unlinked segments). Crash-safe: new file + rename. */
static int idx_compact(brix_cas_pack_t *p) {
    int fd = openat(p->basefd, "pack/index.log.new",
                    O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    for (uint32_t i = 0; i < p->tab_cap; i++) {
        brix_pack_ent_t *e = &p->tab[i];
        if (e->state != 1) continue;
        unsigned char rec[IDX_HDR + BRIX_PACK_KMAX];
        int n = idx_build(rec, OP_PUT, e->fmt, e->seg, e->off, e->stored_len,
                          e->raw_len, ent_key(p, e), e->klen);
        if (write_full(fd, rec, (size_t) n) != 0) { close(fd); return -1; }
    }
    if (brix_plat_fsync_data(fd) != 0 || close(fd) != 0) return -1;
    if (renameat(p->basefd, "pack/index.log.new",
                 p->basefd, "pack/index.log") != 0) return -1;
    close(p->idxfd);
    p->idxfd = openat(p->basefd, "pack/index.log", O_RDWR | O_CLOEXEC);
    if (p->idxfd < 0) return -1;
    return lseek(p->idxfd, 0, SEEK_END) < 0 ? -1 : 0;
}

/* ---- open: replay + orphan-tail adoption -------------------------------- */

/* Replay the journal into the table; stop at the first torn/corrupt record
 * and truncate the tail. `hwm` returns the active segment's journal-covered
 * high-water mark (max record END ever referenced, including deleted ones —
 * the adoption floor that keeps deleted records from resurrecting). */
static int replay(brix_cas_pack_t *p, const uint64_t *segsz, uint64_t *hwm) {
    struct stat st;
    *hwm = 0;
    if (fstat(p->idxfd, &st) != 0) return -1;
    size_t sz = (size_t) st.st_size, pos = 0, good = 0;
    unsigned char *buf = malloc(sz ? sz : 1);
    if (buf == NULL) return -1;
    if (sz > 0 && pread_full(p->idxfd, buf, sz, 0) != 0) { free(buf); return -1; }

    while (pos + IDX_HDR <= sz) {
        unsigned char *r = buf + pos;
        size_t klen = (size_t) r[6] | ((size_t) r[7] << 8);
        if (get32(r) != IDX_MAGIC || klen == 0 || klen > BRIX_PACK_KMAX
            || pos + IDX_HDR + klen > sz) break;
        uint32_t want = get32(r + 12);
        put32(r + 12, 0);
        uint32_t have = crc_of(r, IDX_HDR + klen);
        put32(r + 12, want);
        if (want != have) break;
        good = pos + IDX_HDR + klen;
        pos = good;

        int      op     = r[4];
        uint8_t  fmt    = r[5];
        uint32_t seg    = get32(r + 8);
        uint64_t off    = get64(r + 16);
        uint64_t stored = get64(r + 24);
        uint64_t raw    = get64(r + 32);
        const char *key = (const char *) r + IDX_HDR;
        uint64_t end    = off + SEG_HDR + klen + stored;

        if (seg < p->seg_lo || seg > p->seg_hi || end > segsz[seg - p->seg_lo])
            continue;                     /* stale ref (e.g. torn compaction) */
        if (seg == p->seg_hi && end > *hwm) *hwm = end;

        if (op == OP_PUT) {
            int existed = 0;
            brix_pack_ent_t *e = tab_insert(p, key, klen, &existed);
            if (e == NULL) { free(buf); return -1; }
            if (existed) p->live_bytes -= (long) e->stored_len;
            e->seg = seg; e->off = off; e->fmt = fmt;
            e->stored_len = stored; e->raw_len = raw;
            p->live_bytes += (long) stored;
        } else if (op == OP_DEL) {
            brix_pack_ent_t *e = tab_find(p, key, klen);
            if (e != NULL) {
                p->live_bytes -= (long) e->stored_len;
                e->state = 2; p->tab_live--;
            }
        }
    }
    free(buf);
    if (good < sz && ftruncate(p->idxfd, (off_t) good) != 0) return -1;
    return lseek(p->idxfd, (off_t) good, SEEK_SET) < 0 ? -1 : 0;
}

/* Adopt intact records the journal never saw (crash between data append and
 * journal append) from the ACTIVE segment's tail; truncate the first torn
 * one and everything after it. */
static int adopt_tail(brix_cas_pack_t *p, uint64_t hwm) {
    struct stat st;
    if (fstat(p->segfd, &st) != 0) return -1;
    uint64_t fsz = (uint64_t) st.st_size, pos = hwm;

    while (pos + SEG_HDR <= fsz) {
        unsigned char hdr[SEG_HDR + BRIX_PACK_KMAX];
        if (pread_full(p->segfd, hdr, SEG_HDR, pos) != 0) break;
        size_t   klen   = (size_t) hdr[4] | ((size_t) hdr[5] << 8);
        uint8_t  fmt    = hdr[6];
        uint32_t crc    = get32(hdr + 8);
        uint64_t stored = get64(hdr + 12);
        uint64_t raw    = get64(hdr + 20);
        if (get32(hdr) != SEG_MAGIC || klen == 0 || klen > BRIX_PACK_KMAX
            || fmt > 1 || pos + SEG_HDR + klen + stored > fsz) break;
        if (pread_full(p->segfd, hdr + SEG_HDR, klen, pos + SEG_HDR) != 0) break;

        unsigned char *data = malloc(stored ? (size_t) stored : 1);
        if (data == NULL) return -1;
        int ok = pread_full(p->segfd, data, (size_t) stored,
                            pos + SEG_HDR + klen) == 0
                 && crc_of(data, (size_t) stored) == crc;
        free(data);
        if (!ok) break;

        int existed = 0;
        brix_pack_ent_t *e = tab_insert(p, (const char *) hdr + SEG_HDR, klen,
                                        &existed);
        if (e == NULL) return -1;
        if (existed) p->live_bytes -= (long) e->stored_len;
        e->seg = p->seg_hi; e->off = pos; e->fmt = fmt;
        e->stored_len = stored; e->raw_len = raw;
        p->live_bytes += (long) stored;
        if (idx_append(p, OP_PUT, e, ent_key(p, e)) != 0) return -1;
        pos += SEG_HDR + klen + stored;
    }
    if (pos < fsz && ftruncate(p->segfd, (off_t) pos) != 0) return -1;
    p->seg_off = pos;
    return lseek(p->segfd, (off_t) pos, SEEK_SET) < 0 ? -1 : 0;
}

/* Resolve + own the base fd and ensure pack/ exists. */
static int open_base(brix_cas_pack_t *p, const char *root, int dirfd) {
    if (dirfd >= 0) {
        p->basefd = dirfd;                      /* caller-owned */
    } else {
        if (root == NULL || strlen(root) >= sizeof(p->spill)) { errno = EINVAL; return -1; }
        if (mkdirat(AT_FDCWD, root, 0755) != 0 && errno != EEXIST) return -1;
        p->basefd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (p->basefd < 0) return -1;
        p->owns_base = 1;
        strcpy(p->spill, root);
    }
    return mkdirat(p->basefd, "pack", 0755) != 0 && errno != EEXIST ? -1 : 0;
}

/* Discover existing segments → [seg_lo, seg_hi]. */
static int scan_segments(brix_cas_pack_t *p) {
    int pd = openat(p->basefd, "pack", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (pd < 0) return -1;
    DIR *d = fdopendir(pd);
    if (d == NULL) { close(pd); return -1; }
    uint32_t lo = UINT32_MAX, hi = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        unsigned n; char c;
        if (sscanf(de->d_name, "seg-%8u.da%c", &n, &c) == 2 && c == 't') {
            if (n < lo) lo = n;
            if (n > hi) hi = n;
        }
    }
    closedir(d);
    p->seg_lo = lo == UINT32_MAX ? 0 : lo;
    p->seg_hi = lo == UINT32_MAX ? 0 : hi;
    return 0;
}

/* Open journal + active segment, replay, adopt the orphan tail. */
static int open_and_recover(brix_cas_pack_t *p) {
    uint32_t  nseg  = p->seg_hi - p->seg_lo + 1;
    uint64_t *segsz = calloc(nseg, sizeof(*segsz));
    if (segsz == NULL) return -1;
    for (uint32_t s = p->seg_lo; s <= p->seg_hi; s++) {
        struct stat st;
        int fd = seg_open(p, s, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            if (fstat(fd, &st) == 0) segsz[s - p->seg_lo] = (uint64_t) st.st_size;
            close(fd);
        }
    }
    p->idxfd = openat(p->basefd, "pack/index.log",
                      O_CREAT | O_RDWR | O_CLOEXEC, 0644);
    p->segfd = seg_open(p, p->seg_hi, O_CREAT | O_RDWR | O_CLOEXEC);
    uint64_t hwm = 0;
    int rc = (p->idxfd < 0 || p->segfd < 0
              || replay(p, segsz, &hwm) != 0 || adopt_tail(p, hwm) != 0) ? -1 : 0;
    free(segsz);
    return rc;
}

int brix_cas_pack_open(brix_cas_pack_t **out, const char *root, int dirfd,
                       long quota_bytes, long seg_bytes, int tiering) {
    brix_cas_pack_t *p = calloc(1, sizeof(*p));
    if (p == NULL) return -1;
    pthread_mutex_init(&p->mu, NULL);
    p->segfd = p->idxfd = p->basefd = -1;
    p->quota_bytes = quota_bytes;
    p->seg_max = seg_bytes > 0 ? seg_bytes : BRIX_PACK_SEG_DEFAULT;
    p->tiering = tiering;

    if (open_base(p, root, dirfd) != 0 || scan_segments(p) != 0
        || open_and_recover(p) != 0) {
        int e = errno;
        brix_cas_pack_close(p);
        errno = e;
        return -1;
    }
    *out = p;
    return 0;
}

void brix_cas_pack_close(brix_cas_pack_t *p) {
    if (p == NULL) return;
    if (p->segfd >= 0) { brix_plat_fsync_data(p->segfd); close(p->segfd); }
    if (p->idxfd >= 0) close(p->idxfd);
    if (p->owns_base && p->basefd >= 0) close(p->basefd);
    pthread_mutex_destroy(&p->mu);
    free(p->tab);
    free(p->keys);
    free(p);
}

/* ---- ops ---------------------------------------------------------------- */

static int roll_active(brix_cas_pack_t *p) {
    if (brix_plat_fsync_data(p->segfd) != 0) return -1;
    close(p->segfd);
    p->seg_hi++;
    p->segfd = seg_open(p, p->seg_hi, O_CREAT | O_RDWR | O_CLOEXEC);
    if (p->segfd < 0) return -1;
    p->seg_off = 0;
    p->unsynced = 0;
    return 0;
}

static int reap_locked(brix_cas_pack_t *p, long target) {
    int dropped = 0;
    while (p->live_bytes > target) {
        if (p->seg_lo == p->seg_hi) {
            if (p->seg_off == 0 || roll_active(p) != 0) break;
            continue;
        }
        for (uint32_t i = 0; i < p->tab_cap; i++) {
            brix_pack_ent_t *e = &p->tab[i];
            if (e->state == 1 && e->seg == p->seg_lo) {
                p->live_bytes -= (long) e->stored_len;
                e->state = 2; p->tab_live--; dropped++;
            }
        }
        char nm[64];
        seg_path(nm, sizeof(nm), p->seg_lo);
        unlinkat(p->basefd, nm, 0);
        p->seg_lo++;
    }
    if (dropped > 0) idx_compact(p);
    return dropped;
}

/* Append one record to the active segment; fills e->{seg,off,fmt,lens}. */
static int append_record(brix_cas_pack_t *p, brix_pack_ent_t *e, const char *key,
                         size_t klen, uint8_t fmt, const void *payload,
                         uint64_t stored, uint64_t raw) {
    uint64_t rec = SEG_HDR + klen + stored;
    if (p->seg_off > 0 && p->seg_off + rec > (uint64_t) p->seg_max
        && roll_active(p) != 0) return -1;

    unsigned char hdr[SEG_HDR + BRIX_PACK_KMAX];
    put32(hdr, SEG_MAGIC);
    hdr[4] = (unsigned char) (klen & 0xff);
    hdr[5] = (unsigned char) (klen >> 8);
    hdr[6] = fmt;
    hdr[7] = 0;
    put32(hdr + 8, crc_of(payload, (size_t) stored));
    put64(hdr + 12, stored);
    put64(hdr + 20, raw);
    memcpy(hdr + SEG_HDR, key, klen);

    uint64_t off = p->seg_off;
    if (write_full(p->segfd, hdr, SEG_HDR + klen) != 0
        || write_full(p->segfd, payload, (size_t) stored) != 0) {
        int err = errno;
        if (ftruncate(p->segfd, (off_t) off) == 0)
            lseek(p->segfd, (off_t) off, SEEK_SET);
        errno = err;
        return -1;
    }
    p->seg_off += rec;
    p->unsynced += (long) rec;
    if (p->unsynced >= FSYNC_BATCH) {
        brix_plat_fsync_data(p->segfd);
        p->unsynced = 0;
    }
    e->seg = p->seg_hi; e->off = off; e->fmt = fmt;
    e->stored_len = stored; e->raw_len = raw;
    return 0;
}

int brix_cas_pack_has(brix_cas_pack_t *p, const char *key) {
    pthread_mutex_lock(&p->mu);
    int hit = tab_find(p, key, strlen(key)) != NULL;
    pthread_mutex_unlock(&p->mu);
    return hit;
}

int brix_cas_pack_put(brix_cas_pack_t *p, const char *key,
                      const void *data, size_t len) {
    size_t klen = strlen(key);
    if (klen == 0 || klen > BRIX_PACK_KMAX) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&p->mu);
    if (tab_find(p, key, klen) != NULL) {           /* immutable: present */
        pthread_mutex_unlock(&p->mu);
        return 0;
    }

    uint8_t        fmt = 0;
    const void    *payload = data;
    uint64_t       stored = len;
    unsigned char *cbuf = NULL;
    if (p->tiering && len >= TIER_MIN) {            /* G5: pack cold as zstd */
        size_t bound = ZSTD_compressBound(len);
        cbuf = malloc(bound);
        if (cbuf != NULL) {
            size_t csz = ZSTD_compress(cbuf, bound, data, len, 3);
            if (!ZSTD_isError(csz) && csz < len) {
                fmt = 1; payload = cbuf; stored = csz;
            }
        }
    }

    int rc = -1;
    int existed = 0;
    brix_pack_ent_t *e = tab_insert(p, key, klen, &existed);
    if (e != NULL && !existed
        && append_record(p, e, key, klen, fmt, payload, stored, len) == 0
        && idx_append(p, OP_PUT, e, key) == 0) {
        p->live_bytes += (long) stored;
        rc = 0;
        if (p->quota_bytes > 0 && p->live_bytes > p->quota_bytes)
            reap_locked(p, (p->quota_bytes * 3) / 4);
    } else if (e != NULL && !existed) {
        e->state = 2; p->tab_live--;                /* failed append: retract */
    }
    free(cbuf);
    pthread_mutex_unlock(&p->mu);
    return rc;
}

/* Header + crc + key checks against `sfd`; returns malloc'd RAW bytes. */
static unsigned char *read_verified_fd(brix_cas_pack_t *p, brix_pack_ent_t *e,
                                       int sfd) {
    unsigned char hdr[SEG_HDR + BRIX_PACK_KMAX];
    if (pread_full(sfd, hdr, SEG_HDR + e->klen, e->off) != 0
        || get32(hdr) != SEG_MAGIC
        || ((size_t) hdr[4] | ((size_t) hdr[5] << 8)) != e->klen
        || hdr[6] != e->fmt
        || get64(hdr + 12) != e->stored_len
        || memcmp(hdr + SEG_HDR, ent_key(p, e), e->klen) != 0) return NULL;

    unsigned char *data = malloc(e->stored_len ? (size_t) e->stored_len : 1);
    if (data == NULL) return NULL;
    if (pread_full(sfd, data, (size_t) e->stored_len,
                   e->off + SEG_HDR + e->klen) != 0
        || crc_of(data, (size_t) e->stored_len) != get32(hdr + 8)) {
        free(data);
        return NULL;
    }
    if (e->fmt == 0) return data;

    unsigned char *raw = malloc(e->raw_len ? (size_t) e->raw_len : 1);
    if (raw != NULL) {
        size_t dsz = ZSTD_decompress(raw, (size_t) e->raw_len,
                                     data, (size_t) e->stored_len);
        if (ZSTD_isError(dsz) || dsz != e->raw_len) { free(raw); raw = NULL; }
    }
    free(data);
    return raw;
}

/* Read + structurally verify e's record; returns malloc'd RAW bytes. */
static unsigned char *read_verified(brix_cas_pack_t *p, brix_pack_ent_t *e) {
    int sfd = e->seg == p->seg_hi ? p->segfd
                                  : seg_open(p, e->seg, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) return NULL;
    unsigned char *raw = read_verified_fd(p, e, sfd);
    if (sfd != p->segfd) close(sfd);
    return raw;
}

int brix_cas_pack_get_fd(brix_cas_pack_t *p, const char *key) {
    pthread_mutex_lock(&p->mu);
    brix_pack_ent_t *e = tab_find(p, key, strlen(key));
    unsigned char *raw = e != NULL ? read_verified(p, e) : NULL;
    if (raw == NULL) {
        pthread_mutex_unlock(&p->mu);
        errno = e == NULL ? ENOENT : EIO;
        return -1;
    }

    /* G5: promote hot zstd entries back to raw (re-append; old space is
     * reclaimed at segment drop). Best-effort — serving never depends on it. */
    e->hits++;
    if (p->tiering && e->fmt == 1 && e->hits >= BRIX_PACK_PROMOTE_HITS) {
        brix_pack_ent_t ne = *e;
        if (append_record(p, &ne, ent_key(p, e), e->klen, 0, raw,
                          e->raw_len, e->raw_len) == 0
            && idx_append(p, OP_PUT, &ne, ent_key(p, e)) == 0) {
            p->live_bytes += (long) ne.stored_len - (long) e->stored_len;
            ne.koff = e->koff; ne.klen = e->klen;
            ne.state = 1; ne.hits = e->hits;
            *e = ne;
        }
    }

    int afd = brix_plat_anon_fd(key, p->spill[0] != '\0' ? p->spill : NULL);
    uint64_t raw_len = e->raw_len;
    pthread_mutex_unlock(&p->mu);

    if (afd < 0 || write_full(afd, raw, (size_t) raw_len) != 0
        || lseek(afd, 0, SEEK_SET) != 0) {
        if (afd >= 0) close(afd);
        free(raw);
        errno = EIO;
        return -1;
    }
    free(raw);
    return afd;
}

int brix_cas_pack_del(brix_cas_pack_t *p, const char *key) {
    pthread_mutex_lock(&p->mu);
    brix_pack_ent_t *e = tab_find(p, key, strlen(key));
    if (e == NULL) {
        pthread_mutex_unlock(&p->mu);
        errno = ENOENT;
        return -1;
    }
    idx_append(p, OP_DEL, e, ent_key(p, e));
    p->live_bytes -= (long) e->stored_len;
    e->state = 2; p->tab_live--;
    pthread_mutex_unlock(&p->mu);
    return 0;
}

long brix_cas_pack_size(brix_cas_pack_t *p) {
    pthread_mutex_lock(&p->mu);
    long n = p->live_bytes;
    pthread_mutex_unlock(&p->mu);
    return n;
}

int brix_cas_pack_reap(brix_cas_pack_t *p, long target_bytes) {
    pthread_mutex_lock(&p->mu);
    int n = reap_locked(p, target_bytes);
    pthread_mutex_unlock(&p->mu);
    return n;
}

int brix_cas_pack_enforce_quota(brix_cas_pack_t *p) {
    pthread_mutex_lock(&p->mu);
    int n = 0;
    if (p->quota_bytes > 0 && p->live_bytes > p->quota_bytes)
        n = reap_locked(p, (p->quota_bytes * 3) / 4);
    pthread_mutex_unlock(&p->mu);
    return n;
}

int brix_cas_pack_fsck(brix_cas_pack_t *p) {
    pthread_mutex_lock(&p->mu);
    int dropped = 0;
    for (uint32_t i = 0; i < p->tab_cap; i++) {
        brix_pack_ent_t *e = &p->tab[i];
        if (e->state != 1) continue;
        unsigned char *raw = read_verified(p, e);
        if (raw != NULL) { free(raw); continue; }
        idx_append(p, OP_DEL, e, ent_key(p, e));
        p->live_bytes -= (long) e->stored_len;
        e->state = 2; p->tab_live--; dropped++;
    }
    pthread_mutex_unlock(&p->mu);
    return dropped;
}

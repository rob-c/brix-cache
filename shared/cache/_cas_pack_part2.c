/* _cas_pack_part2.c — fragment 2 of cas_pack.c (auto-split).
 * Do not compile directly; it is #included by cas_pack.c. */
#ifndef _CAS_PACK_PART2_C_INC
#define _CAS_PACK_PART2_C_INC
#ifndef __CAS_PACK_C_COMPILED__
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

#endif /* __CAS_PACK_C_COMPILED__ */

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
#endif /* _CAS_PACK_PART2_C_INC */

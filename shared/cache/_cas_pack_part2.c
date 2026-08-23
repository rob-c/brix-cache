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

typedef struct {
    uint8_t        format;
    const void    *bytes;
    uint64_t       stored;
    unsigned char *compressed;
} pack_payload_t;

/*
 * WHAT: Select the raw or zstd representation for a new packed-CAS object.
 * WHY:  Tiering should save space only when compression beats the source size.
 * HOW:  Attempt bounded level-three compression and otherwise retain raw input.
 */
static void pack_payload_prepare(brix_cas_pack_t *pack, const void *data,
                                 size_t len, pack_payload_t *payload) {
    size_t bound;
    size_t compressed_size;

    payload->format = 0;
    payload->bytes = data;
    payload->stored = len;
    payload->compressed = NULL;
    if (!pack->tiering || len < TIER_MIN)
        return;
    bound = ZSTD_compressBound(len);
    payload->compressed = malloc(bound);
    if (payload->compressed == NULL)
        return;
    compressed_size = ZSTD_compress(payload->compressed, bound, data, len, 3);
    if (ZSTD_isError(compressed_size) || compressed_size >= len)
        return;
    payload->format = 1;
    payload->bytes = payload->compressed;
    payload->stored = compressed_size;
}

/*
 * WHAT: Append and journal one prepared packed-CAS object while holding its lock.
 * WHY:  Failed data or journal writes must retract their provisional table slot.
 * HOW:  Insert the key, append both records, account bytes, and enforce quota.
 */
static int pack_put_commit(brix_cas_pack_t *pack, const char *key, size_t klen,
                           size_t raw_len, const pack_payload_t *payload) {
    brix_pack_ent_t *entry;
    int              existed = 0;

    entry = tab_insert(pack, key, klen, &existed);
    if (entry == NULL || existed)
        return -1;
    if (append_record(pack, entry, key, klen, payload->format, payload->bytes,
                      payload->stored, raw_len) != 0 ||
        idx_append(pack, OP_PUT, entry, key) != 0) {
        entry->state = 2;
        pack->tab_live--;
        return -1;
    }
    pack->live_bytes += (long) payload->stored;
    if (pack->quota_bytes > 0 && pack->live_bytes > pack->quota_bytes)
        reap_locked(pack, (pack->quota_bytes * 3) / 4);
    return 0;
}

int brix_cas_pack_put(brix_cas_pack_t *pack, const char *key,
                      const void *data, size_t len) {
    pack_payload_t payload;
    size_t         klen = strlen(key);
    int            rc;

    if (klen == 0 || klen > BRIX_PACK_KMAX) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&pack->mu);
    if (tab_find(pack, key, klen) != NULL) {
        pthread_mutex_unlock(&pack->mu);
        return 0;
    }
    pack_payload_prepare(pack, data, len, &payload);
    rc = pack_put_commit(pack, key, klen, len, &payload);
    free(payload.compressed);
    pthread_mutex_unlock(&pack->mu);
    return rc;
}

/*
 * WHAT: Validate a stored segment header against its in-memory index entry.
 * WHY:  Index corruption must not redirect reads to unrelated segment bytes.
 * HOW:  Compare magic, key, encoding, and lengths after a complete header read.
 */
static int stored_header_read(brix_cas_pack_t *pack, brix_pack_ent_t *entry,
                              int segment_fd, unsigned char *header) {
    if (pread_full(segment_fd, header, SEG_HDR + entry->klen, entry->off) != 0)
        return -1;
    if (get32(header) != SEG_MAGIC ||
        ((size_t) header[4] | ((size_t) header[5] << 8)) != entry->klen ||
        header[6] != entry->fmt || get64(header + 12) != entry->stored_len ||
        memcmp(header + SEG_HDR, ent_key(pack, entry), entry->klen) != 0)
        return -1;
    return 0;
}

/*
 * WHAT: Read and checksum the stored payload named by a verified header.
 * WHY:  Serving corrupt packed bytes would violate CAS content integrity.
 * HOW:  Allocate the recorded length, pread it fully, and compare its CRC32.
 */
static unsigned char *stored_payload_read(brix_pack_ent_t *entry, int segment_fd,
                                          const unsigned char *header) {
    unsigned char *data = malloc(entry->stored_len ?
                                 (size_t) entry->stored_len : 1);

    if (data == NULL)
        return NULL;
    if (pread_full(segment_fd, data, (size_t) entry->stored_len,
                   entry->off + SEG_HDR + entry->klen) != 0 ||
        crc_of(data, (size_t) entry->stored_len) != get32(header + 8)) {
        free(data);
        return NULL;
    }
    return data;
}

/*
 * WHAT: Expand a zstd packed payload to the raw length recorded in the index.
 * WHY:  Callers consume raw CAS bytes regardless of the on-disk storage tier.
 * HOW:  Allocate the exact raw length and require an exact decompression result.
 */
static unsigned char *stored_payload_expand(brix_pack_ent_t *entry,
                                            unsigned char *data) {
    unsigned char *raw = malloc(entry->raw_len ? (size_t) entry->raw_len : 1);
    size_t         size;

    if (raw == NULL) {
        free(data);
        return NULL;
    }
    size = ZSTD_decompress(raw, (size_t) entry->raw_len, data,
                           (size_t) entry->stored_len);
    free(data);
    if (ZSTD_isError(size) || size != entry->raw_len) {
        free(raw);
        return NULL;
    }
    return raw;
}

/* Header + crc + key checks against `sfd`; returns malloc'd RAW bytes. */
static unsigned char *read_verified_fd(brix_cas_pack_t *p, brix_pack_ent_t *e,
                                       int sfd) {
    unsigned char hdr[SEG_HDR + BRIX_PACK_KMAX];
    unsigned char *data;

    if (stored_header_read(p, e, sfd, hdr) != 0)
        return NULL;
    data = stored_payload_read(e, sfd, hdr);
    if (data == NULL || e->fmt == 0)
        return data;
    return stored_payload_expand(e, data);
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

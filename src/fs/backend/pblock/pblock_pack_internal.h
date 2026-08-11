/*
 * pblock_pack_internal.h — cross-TU seam for the packed-arena implementation.
 *
 * The low-level segment-file helpers live in pblock_pack_seg.c; the catalog /
 * admit / serve logic lives in pblock_pack.c. Both are compiled only under
 * BRIX_HAVE_SQLITE. These declarations were file-local statics in pblock_pack.c
 * before the file-size split; nothing outside these two TUs uses them.
 */
#ifndef BRIX_PBLOCK_PACK_INTERNAL_H
#define BRIX_PBLOCK_PACK_INTERNAL_H

#include "pblock_store.h"   /* pblock_state_t */

#include <sys/types.h>      /* off_t */
#include <stddef.h>         /* size_t */
#include <stdint.h>         /* int64_t */

/* Read/write exactly len bytes at off (EINTR-safe); 0 on success, -1/errno. */
int pack_pread_full(int fd, void *buf, size_t len, off_t off);
int pack_pwrite_full(int fd, const void *buf, size_t len, off_t off);

/* Format "<root>/pack/seg-<n>.dat" into out[cap]; 0 or -1 (truncation). */
int pack_seg_path(const pblock_state_t *st, int64_t seg, char *out, size_t cap);

/* Take the arena append/reap lock (pack/.lock, flock LOCK_EX): held fd or -1. */
int pack_lock(const pblock_state_t *st);

/* Highest existing segment number (0 when none); call under the arena lock. */
int64_t pack_active_seg(const pblock_state_t *st);

#endif /* BRIX_PBLOCK_PACK_INTERNAL_H */

/*
 * pblock_xform.h — Phase-83 F12/F13 per-block transform seam for pblock.
 *
 * WHAT: One seam, two transforms. An export configured with `xform=crypt:<keyfile>`
 *       or `xform=zstd` stores every data block through a whole-block encode on the
 *       write path and the matching decode on the read path. `crypt` keeps physical
 *       size == logical (a keyed XOR keystream — deliberately NOT a reviewed
 *       security boundary, per the phase non-goals); `zstd` makes physical bytes ≠
 *       logical size, which is the point of F13 (every place that conflated
 *       block-file size with the logical extent now has to ask the block header).
 *
 * WHY:  F12 exercises the "backend cannot offer a block-0 fd" lane (a transformed
 *       open drops CAP_SENDFILE/CAP_IOURING at instance build); F13 exercises the
 *       logical≠physical size split. Both are semantics exercises for the VFS, not
 *       production storage features.
 *
 * HOW:  A transformed block file is `[u32 logical_len][u32 phys_len][phys bytes]`
 *       (little-endian header). Because the block engine still issues arbitrary
 *       sub-block writes, the write path is read-modify-write: load the whole
 *       logical block, overlay the new bytes, re-encode. Scratch buffers are
 *       heap-owned (block_size can be megabytes). ngx-free (libc + optional
 *       libzstd), gated by BRIX_HAVE_SQLITE like the rest of the backend; `zstd`
 *       additionally needs BRIX_HAVE_ZSTD or it is a config error (ENOTSUP).
 *
 * Requires: <stdint.h>, <sys/types.h> before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_XFORM_H
#define BRIX_FS_BACKEND_PBLOCK_XFORM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    PBLOCK_XFORM_NONE  = 0,   /* production path: raw block files, no header    */
    PBLOCK_XFORM_CRYPT = 1,   /* keyed XOR keystream (NOT a security boundary)  */
    PBLOCK_XFORM_ZSTD  = 2    /* zstd compression (physical ≠ logical size)     */
} pblock_xform_kind;

/* Resolved per-export transform. `key` is derived from the crypt keyfile at
 * config time (unused for zstd/none). Copied by value into pblock_state_t. */
typedef struct {
    pblock_xform_kind kind;
    unsigned char     key[32];
} pblock_xform_t;

/* On-disk transformed-block header (little-endian). logical_len ≤ block_size. */
#define PBLOCK_XFORM_HDR 8

/* Parse an `xform=<spec>` value ("crypt:<keyfile>" or "zstd") into *xf (zeroed
 * first). Returns 0, or -1 with errno: EINVAL (malformed spec), ENOENT (crypt
 * keyfile unreadable), ENOTSUP (`zstd` without BRIX_HAVE_ZSTD). An empty/NULL
 * spec yields kind NONE and returns 0. */
int pblock_xform_config(pblock_xform_t *xf, const char *spec, size_t len);

/* 1 when a real transform is configured (kind != NONE), else 0. */
int pblock_xform_active(const pblock_xform_t *xf);

/* Canonical lowercase name of a kind ("crypt"/"zstd"/""), for the objects.xform
 * catalog column; and the reverse map (unknown ⇒ NONE). */
const char       *pblock_xform_name(pblock_xform_kind kind);
pblock_xform_kind pblock_xform_kind_from_name(const char *name);

/* Load block `idx`'s whole logical content from transformed block file `path`
 * into out[0..bs) (zero-filled past the stored logical length). *llen_out gets
 * the logical byte count. A missing file is a hole: out all-zero, *llen_out 0.
 * Returns 0, or -1/errno (EIO on a corrupt header or a failed decode). */
int pblock_xform_block_load(const pblock_xform_t *xf, int64_t idx,
    const char *path, unsigned char *out, int64_t bs, uint32_t *llen_out);

/* Encode logical[0..llen) (llen ≤ bs) as block `idx` and rewrite block file
 * `path` (truncated to exactly header+phys). Returns 0 or -1/errno. */
int pblock_xform_block_store(const pblock_xform_t *xf, int64_t idx,
    const char *path, const unsigned char *logical, uint32_t llen, int64_t bs);

#endif /* BRIX_FS_BACKEND_PBLOCK_XFORM_H */

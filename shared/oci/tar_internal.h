/* tar_internal.h — reader state shared by tar.c and tar_pax.c (phase-104 D6).
 *
 * WHAT: the brix_tar_s definition plus the cross-TU seams: the decompressing
 *       byte source, the pax-override store, and the pax record parser.
 * WHY:  pax parsing is split into its own TU by design (§0.5 budget); both
 *       TUs need the struct, nobody else does.
 * HOW:  all buffers are fixed-size members of one malloc'd struct, so reader
 *       memory is flat in archive size (the D6 contract).
 */
#ifndef BRIX_OCI_TAR_INTERNAL_H
#define BRIX_OCI_TAR_INTERNAL_H

#include "oci/tar.h"
#include "oci/digest.h"

#include <zlib.h>

#ifdef BRIX_HAVE_ZSTD
#include <zstd.h>
#endif

#define TAR_INBUF_CAP    (64u * 1024u)   /* compressed-input window */
#define TAR_BODY_CAP     (64u * 1024u)   /* skip/pax body window */
#define TAR_PAX_CAP      (160u * 1024u)  /* whole-pax-body cap: 64 KiB xattr
                                            budget + 2 x 4 KiB paths + slack;
                                            a pax header past this exceeds the
                                            bounds the publish plane accepts
                                            anyway (changeset xattr cap) */
#define TAR_XATTR_ARENA  (96u * 1024u)   /* staged key+value bytes */
#define TAR_XATTR_MAX    255             /* cvmfs_xattr_pack count bound */
#define TAR_PAX_REC_MAX  65536           /* records per entry (CPU-bomb cap) */

typedef enum { TAR_COMP_RAW = 0, TAR_COMP_GZ, TAR_COMP_ZSTD } tar_comp_e;

/* pax/GNU-long overrides staged for the NEXT entry ('x'/'L'/'K') or for all
 * subsequent entries ('g'). Per-file wins over global, global over ustar. */
typedef struct {
    int      have_path, have_link, have_size, have_mtime, have_uid, have_gid;
    char     path[4096];
    char     linkname[4096];
    int64_t  size;
    int64_t  mtime;
    int64_t  uid, gid;
} tar_override_t;

struct brix_tar_s {
    int           fd;
    tar_comp_e    comp;

    /* -- decompressors (one live per stream) -- */
    z_stream      zs;
    int           z_live;
    int           z_done;            /* Z_STREAM_END seen: the source is spent */
#ifdef BRIX_HAVE_ZSTD
    ZSTD_DStream *zds;
#endif

    /* -- compressed/raw input window -- */
    unsigned char inbuf[TAR_INBUF_CAP];
    size_t        in_len, in_off;
    int           in_eof;

    /* -- frame state -- */
    unsigned char hdr[512];
    unsigned char body[TAR_BODY_CAP];
    int           have_entry;
    int64_t       remaining;         /* unread body bytes of current entry */
    size_t        pad;               /* 512-padding after current body */

    /* -- pax state (tar_pax.c) -- */
    unsigned char pax[TAR_PAX_CAP];
    tar_override_t next;             /* per-file ('x'/'L'/'K') overrides */
    tar_override_t glob;             /* 'g' global overrides */

    /* per-file xattr staging (SCHILY.xattr.*), packed at entry emission */
    char          xarena[TAR_XATTR_ARENA];
    size_t        xarena_len;
    const char   *xkeys[TAR_XATTR_MAX];
    const unsigned char *xvals[TAR_XATTR_MAX];
    size_t        xlens[TAR_XATTR_MAX];
    size_t        xcount;
    unsigned char xblob[TAR_XATTR_ARENA];   /* cvmfs_xattr_pack output */

    /* -- diff-id capture (tar_digest.c): sha256 of the decompressed stream */
    brix_oci_sha256_ctx_t dig;
    int                   dig_on;

    /* Decompressed bytes produced so far. The source hands out exactly what
     * a caller asked for and never reads ahead into a decompressed window,
     * so this counter is an exact stream position — which is what an
     * eStargz writer needs to cut gzip members at (D15.8). */
    int64_t               stream_off;

    char          err[256];
};

/* Produce up to cap decompressed bytes into dst, hashing them into the
 * diff-id when capture is on. >0 produced, 0 stream end, -1 corrupt input. */
int brix_tar_src(brix_tar_t *t, unsigned char *dst, size_t cap);

/* Read exactly n decompressed bytes into dst. 1 = filled, 0 = clean EOF with
 * zero bytes produced, -1 = error or short read (t->err set). */
int brix_tar_fill(brix_tar_t *t, unsigned char *dst, size_t n);

/* Format into t->err (printf-style) and return -1, so error paths read
 * `return tar_fail(t, ...)`. */
int brix_tar_fail(brix_tar_t *t, const char *fmt, ...);

/* Parse one pax body ('x' per-file / 'g' global) of `len` bytes already in
 * t->pax. Applies keys onto t->next or t->glob (and the xattr staging for
 * per-file records). 0 ok / -1 malformed (t->err set). */
int brix_tar_pax_apply(brix_tar_t *t, size_t len, int global);

/* Reset the per-file override + xattr staging (after an entry is emitted). */
void brix_tar_pax_reset_next(brix_tar_t *t);

#endif /* BRIX_OCI_TAR_INTERNAL_H */

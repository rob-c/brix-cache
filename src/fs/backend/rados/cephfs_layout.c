/*
 * cephfs_layout.c — typed decoders for CephFS on-RADOS metadata (see header).
 *
 * Field orders and version guards mirror Ceph v18.2.4 verbatim:
 *   - inode_t::decode            src/include/cephfs/types.h
 *   - InodeStoreBase::decode_bare src/mds/CInode.cc
 *   - CDir::_load_dentry          src/mds/CDir.cc (the dentry value wrapper)
 *   - file_layout_t               framed v2 (long stable since Jewel)
 * The byte layout is cross-checked against captured reef fixtures
 * (tests/ceph/fixtures/reef-18.2.4). Every decode is bounds-safe via cephfs_denc:
 * we test the cursor's sticky error once at the end rather than per field.
 */
#include "cephfs_layout.h"

/* a Ceph utime_t is two u32: seconds, then nanoseconds. */
static void
decode_utime(cephfs_denc_t *d, int64_t *sec, uint32_t *nsec)
{
    uint32_t s = cephfs_denc_u32(d);
    uint32_t n = cephfs_denc_u32(d);
    if (sec  != NULL) { *sec  = (int64_t) s; }
    if (nsec != NULL) { *nsec = n; }
}

int
cephfs_decode_file_layout(cephfs_denc_t *d, cephfs_layout_t *out)
{
    cephfs_denc_frame_t f;

    cephfs_denc_start(d, &f);
    out->stripe_unit  = cephfs_denc_u32(d);
    out->stripe_count = cephfs_denc_u32(d);
    out->object_size  = cephfs_denc_u32(d);
    out->pool_id      = cephfs_denc_s64(d);
    /* pool_ns string follows; not needed to locate data objects — frame-skip */
    cephfs_denc_finish(d, &f);
    return cephfs_denc_ok(d) ? 0 : -1;
}

/* Decode inode_t up to mtime (everything the driver needs), honouring the
 * version guards from inode_t::decode, then frame-skip the remaining fields.
 *   v>=4 : dir_layout (8 bytes) present
 *   v>=5 : truncate_pending (u32) present
 * Fields after mtime (atime, dirstat/rstat, client_ranges, quota, btime, fscrypt,
 * ...) are not needed here and are skipped by jumping to the frame end. */
int
cephfs_decode_inode(cephfs_denc_t *d, cephfs_inode_t *out)
{
    cephfs_denc_frame_t f;
    uint8_t             v;

    v = cephfs_denc_start(d, &f);
    out->struct_v = v;

    out->ino = cephfs_denc_u64(d);
    (void) cephfs_denc_u32(d);                         /* rdev  */
    decode_utime(d, &out->ctime_sec, &out->ctime_nsec);/* ctime */
    out->mode  = cephfs_denc_u32(d);
    out->uid   = cephfs_denc_u32(d);
    out->gid   = cephfs_denc_u32(d);
    out->nlink = cephfs_denc_u32(d);
    (void) cephfs_denc_u8(d);                           /* anchored (bool) */

    if (v >= 4) {
        cephfs_denc_skip(d, 8);                         /* dir_layout */
    }

    if (cephfs_decode_file_layout(d, &out->layout) != 0) {
        return -1;
    }

    out->size = cephfs_denc_u64(d);
    (void) cephfs_denc_u32(d);                          /* truncate_seq  */
    (void) cephfs_denc_u64(d);                          /* truncate_size */
    (void) cephfs_denc_u64(d);                          /* truncate_from */
    if (v >= 5) {
        (void) cephfs_denc_u32(d);                      /* truncate_pending */
    }
    decode_utime(d, &out->mtime_sec, &out->mtime_nsec); /* mtime */

    cephfs_denc_finish(d, &f);                          /* skip the rest */
    return cephfs_denc_ok(d) ? 0 : -1;
}

/* frag_t is encoded as a single u32 `_enc` = (bits << 24) | value. */
static uint32_t frag_bits (uint32_t enc) { return enc >> 24; }
static uint32_t frag_value(uint32_t enc) { return enc & 0x00ffffffu; }
static uint32_t
frag_make_child(uint32_t enc, uint32_t nbits, uint32_t i)
{
    uint32_t cb = frag_bits(enc) + nbits;
    uint32_t cv = ((frag_value(enc) << nbits) | i) & 0x00ffffffu;
    return (cb << 24) | cv;
}

int
cephfs_decode_fragtree(cephfs_denc_t *d, uint32_t *leaves, uint32_t max,
                       uint32_t *count, int *truncated)
{
    /* the split map: each entry says a frag node splits into 2^nway children */
    struct { uint32_t enc; int32_t nway; } splits[CEPHFS_MAX_FRAGS];
    uint32_t stack[CEPHFS_MAX_FRAGS];
    uint32_t nsplit, i, sp = 0, nleaf = 0;
    int      trunc = 0;

    if (truncated != NULL) { *truncated = 0; }

    nsplit = cephfs_denc_u32(d);
    if (!cephfs_denc_ok(d)) { return -1; }
    if (nsplit > CEPHFS_MAX_FRAGS) { d->err = 1; return -1; }  /* implausible */
    for (i = 0; i < nsplit; i++) {
        splits[i].enc  = cephfs_denc_u32(d);
        splits[i].nway = (int32_t) cephfs_denc_u32(d);
    }
    if (!cephfs_denc_ok(d)) { return -1; }

    /* walk the tree from the root frag (enc 0); a node not in the split map is a
     * leaf. Explicit stack — no recursion. */
    stack[sp++] = 0;
    while (sp > 0) {
        uint32_t f  = stack[--sp];
        int32_t  nb = -1;

        for (i = 0; i < nsplit; i++) {
            if (splits[i].enc == f) { nb = splits[i].nway; break; }
        }
        if (nb <= 0) {                              /* leaf */
            if (nleaf < max) { leaves[nleaf] = f; } else { trunc = 1; }
            nleaf++;
        } else {
            uint32_t children, c;
            if (nb > 8) { nb = 8; }                 /* cap fan-out (256) */
            children = 1u << nb;
            for (c = 0; c < children; c++) {
                if (sp < CEPHFS_MAX_FRAGS) {
                    stack[sp++] = frag_make_child(f, (uint32_t) nb, c);
                } else {
                    trunc = 1;
                }
            }
        }
    }

    *count = (nleaf <= max) ? nleaf : max;
    if (truncated != NULL) { *truncated = trunc; }
    return cephfs_denc_ok(d) ? 0 : -1;
}

int
cephfs_decode_xattrs(cephfs_denc_t *d, cephfs_xattr_t *out, uint32_t max,
                     uint32_t *count, int *truncated)
{
    uint32_t n, i, w = 0;
    int      trunc = 0;

    if (truncated != NULL) { *truncated = 0; }

    n = cephfs_denc_u32(d);
    if (!cephfs_denc_ok(d)) { return -1; }
    for (i = 0; i < n; i++) {
        const char *nm, *vl;
        uint32_t    nl = 0, vlen = 0;

        cephfs_denc_str(d, &nm, &nl);     /* xattr name (string)            */
        cephfs_denc_str(d, &vl, &vlen);   /* xattr value (bufferptr == str) */
        if (!cephfs_denc_ok(d)) { return -1; }

        if (w < max) {
            out[w].name = nm; out[w].name_len = nl;
            out[w].val  = vl; out[w].val_len  = vlen;
            w++;
        } else {
            trunc = 1;
        }
    }
    *count = w;
    if (truncated != NULL) { *truncated = trunc; }
    return 0;
}

/* Decode a primary inode body (InodeStore decode_bare prefix): the framed inode;
 * the symlink target if it is a symlink; the directory fragment tree; and the
 * xattr map. Fields after the xattrs (snap_blob, old_inodes, oldest_snap,
 * damage_flags) are not needed and are frame-skipped by the caller (for 'i', via
 * the InodeStore frame). */
static int
decode_primary_body(cephfs_denc_t *d, cephfs_dentry_t *out)
{
    out->kind            = CEPHFS_DENTRY_PRIMARY;
    out->symlink         = NULL;
    out->symlink_len     = 0;
    out->nfrags          = 0;
    out->frags_truncated = 0;
    out->nxattrs         = 0;
    out->xattrs_truncated = 0;

    if (cephfs_decode_inode(d, &out->inode) != 0) {
        return -1;
    }
    if (cephfs_mode_is_link(out->inode.mode)) {
        cephfs_denc_str(d, &out->symlink, &out->symlink_len);
    }
    cephfs_decode_fragtree(d, out->frag_enc, CEPHFS_MAX_FRAGS,
                           &out->nfrags, &out->frags_truncated);
    cephfs_decode_xattrs(d, out->xattrs, CEPHFS_MAX_XATTRS,
                         &out->nxattrs, &out->xattrs_truncated);
    return cephfs_denc_ok(d) ? 0 : -1;
}

int
cephfs_decode_dentry(const void *buf, size_t len, cephfs_dentry_t *out)
{
    cephfs_denc_t d;
    uint8_t       type;

    cephfs_denc_init(&d, buf, len);

    (void) cephfs_denc_u64(&d);          /* snapid_t first */
    type = cephfs_denc_u8(&d);
    if (!cephfs_denc_ok(&d)) {
        return -1;
    }

    /* remote dentry (hardlink): inodeno_t ino, then d_type; 'L' also carries an
     * alternate_name we don't need. Only ino + d_type are stored here — resolving
     * the inode itself is the caller's job. */
    if (type == 'L' || type == 'l') {
        out->kind          = CEPHFS_DENTRY_REMOTE;
        out->remote_ino    = cephfs_denc_u64(&d);
        out->remote_d_type = cephfs_denc_u8(&d);
        return cephfs_denc_ok(&d) ? 0 : -1;
    }

    /* primary dentry. 'i' (old) wraps the InodeStore in a small frame that also
     * carries an alternate_name; 'I' (new) stores the InodeStore bare. */
    if (type == 'i') {
        cephfs_denc_frame_t wrap, store;
        int                 rc;

        cephfs_denc_start(&d, &wrap);                /* dentry wrapper (v>=2) */
        if (wrap.struct_v >= 2) {
            cephfs_denc_str(&d, NULL, NULL);         /* alternate_name (discard) */
        }
        cephfs_denc_start(&d, &store);               /* InodeStore frame */
        rc = decode_primary_body(&d, out);
        cephfs_denc_finish(&d, &store);              /* skip fragtree/xattrs/... */
        cephfs_denc_finish(&d, &wrap);
        if (rc != 0 || !cephfs_denc_ok(&d)) {
            return -1;
        }
        return 0;
    }

    if (type == 'I') {
        /* InodeStore stored bare (no surrounding frame) */
        return decode_primary_body(&d, out);
    }

    /* unknown dentry marker */
    return -1;
}

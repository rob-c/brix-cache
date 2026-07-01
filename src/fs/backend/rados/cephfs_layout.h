/*
 * cephfs_layout.h — typed decoders for CephFS on-RADOS metadata structures.
 *
 * WHAT: Decodes the Ceph MDS's on-disk encodings — the directory-entry value
 *       (primary vs remote dentry), the embedded inode (inode_t), and the file
 *       layout (file_layout_t) — into plain C structs the read-only driver and
 *       recovery tools consume. Built entirely on cephfs_denc primitives.
 *
 * WHY:  Serving a CephFS by reading RADOS directly means parsing exactly what the
 *       MDS wrote into the metadata-pool omaps. These encodings are versioned
 *       (struct_v grows as Ceph adds fields); decoding here is driven by the same
 *       version guards the Ceph source uses, so one decoder spans many releases
 *       and refuses cleanly on an encoding it does not understand.
 *
 * HOW:  Every Ceph struct is wrapped in an ENCODE_START frame (struct_v / compat /
 *       byte-length). We decode the leading fields we need, honour each
 *       `if (struct_v >= N)` guard exactly as Ceph does, then jump to the frame's
 *       end (forward-compat) — so newer trailing fields are skipped, not
 *       mis-read. The inode is itself framed, so we only decode up to the fields
 *       the driver needs (ino/mode/size/mtime/layout) and frame-skip the rest.
 *
 * VERSION COVERAGE: inode_t decode honours every guard from struct_v 2 through 19
 *       (reef). file_layout_t is the long-stable framed v2 form. The byte layout
 *       is verified against captured reef-18.2.4 fixtures (tests/ceph/fixtures/)
 *       and the field order/guards are taken verbatim from the Ceph v18.2.4
 *       source (src/include/cephfs/types.h, src/mds/CInode.cc, src/mds/CDir.cc).
 *
 * SCOPE (this layer): primary inodes (files, dirs, symlinks) + file layout +
 *       remote-dentry ino/d_type, plus the directory fragment tree and inode
 *       xattr map that sit after the inode inside the InodeStore.
 *
 * Pure C; no RADOS, no nginx.
 */
#ifndef XROOTD_CEPHFS_LAYOUT_H
#define XROOTD_CEPHFS_LAYOUT_H

#include "cephfs_denc.h"

/* Bounds on the per-inode collections we materialize. A directory with more leaf
 * fragments, or an inode with more xattrs, than these is decoded up to the cap
 * and flagged truncated (see cephfs_dentry_t.frags_truncated / xattrs_truncated)
 * rather than overrunning. */
#define CEPHFS_MAX_FRAGS   256
#define CEPHFS_MAX_XATTRS  64

/* Ceph st_mode type bits (independent of host <sys/stat.h>, which the decoder
 * must not depend on for a portable, testable parse). */
#define CEPHFS_S_IFMT   0170000u
#define CEPHFS_S_IFDIR  0040000u
#define CEPHFS_S_IFREG  0100000u
#define CEPHFS_S_IFLNK  0120000u

static inline int cephfs_mode_is_dir (uint32_t m) { return (m & CEPHFS_S_IFMT) == CEPHFS_S_IFDIR; }
static inline int cephfs_mode_is_reg (uint32_t m) { return (m & CEPHFS_S_IFMT) == CEPHFS_S_IFREG; }
static inline int cephfs_mode_is_link(uint32_t m) { return (m & CEPHFS_S_IFMT) == CEPHFS_S_IFLNK; }

/* Decoded file/dir striping layout (file_layout_t). pool_ns is decoded but
 * discarded (rarely set; not needed to locate data objects). */
typedef struct {
    uint32_t stripe_unit;
    uint32_t stripe_count;
    uint32_t object_size;
    int64_t  pool_id;
} cephfs_layout_t;

/* The inode fields the driver/tools need (a subset of inode_t). */
typedef struct {
    uint64_t        ino;
    uint32_t        mode;        /* full st_mode incl. CEPHFS_S_IFMT bits */
    uint32_t        uid;
    uint32_t        gid;
    uint32_t        nlink;
    uint64_t        size;
    int64_t         mtime_sec;
    uint32_t        mtime_nsec;
    int64_t         ctime_sec;
    uint32_t        ctime_nsec;
    cephfs_layout_t layout;
    uint8_t         struct_v;    /* inode_t encode version actually seen */
} cephfs_inode_t;

/* One inode xattr. name/val point into the decoded buffer (NOT null-terminated);
 * names include the full "user."/"ceph."/... prefix as stored. */
typedef struct {
    const char *name;
    uint32_t    name_len;
    const char *val;
    uint32_t    val_len;
} cephfs_xattr_t;

/* What a directory-entry value resolved to. */
typedef enum {
    CEPHFS_DENTRY_PRIMARY = 1,   /* embeds a full inode (the common case) */
    CEPHFS_DENTRY_REMOTE  = 2,   /* a hardlink: only ino + d_type are stored */
} cephfs_dentry_kind_t;

typedef struct {
    cephfs_dentry_kind_t kind;

    /* REMOTE only: */
    uint64_t  remote_ino;
    uint8_t   remote_d_type;

    /* PRIMARY only: */
    cephfs_inode_t inode;
    const char    *symlink;      /* symlink target (into the input buffer, NOT
                                  * null-terminated); NULL unless a symlink     */
    uint32_t       symlink_len;

    /* directory leaf fragments — the object-name suffixes ("%08x" of each leaf
     * frag) whose omaps hold this dir's entries; for an unsplit dir this is the
     * single value 0 ("00000000"). Meaningful for directories. */
    uint32_t       frag_enc[CEPHFS_MAX_FRAGS];
    uint32_t       nfrags;
    int            frags_truncated;

    /* inode xattrs (read-only). */
    cephfs_xattr_t xattrs[CEPHFS_MAX_XATTRS];
    uint32_t       nxattrs;
    int            xattrs_truncated;
} cephfs_dentry_t;

/* Decode a file_layout_t (framed) at the cursor into *out. 0 on success; -1 (and
 * the cursor's sticky error set) on a malformed/unsupported encoding. */
int cephfs_decode_file_layout(cephfs_denc_t *d, cephfs_layout_t *out);

/* Decode an inode_t (framed) at the cursor into *out, honouring all version
 * guards and frame-skipping fields past what we need. 0 / -1. */
int cephfs_decode_inode(cephfs_denc_t *d, cephfs_inode_t *out);

/* Decode a fragtree_t (an UNframed compact_map<frag_t,int32_t> as written inside
 * the InodeStore) at the cursor and resolve it to its LEAF fragments, writing up
 * to `max` leaf `_enc` values to `leaves` and the count to `*count`. An empty
 * split map yields the single leaf 0. Sets *truncated when there are more leaves
 * than `max`. 0 / -1 (cursor error). */
int cephfs_decode_fragtree(cephfs_denc_t *d, uint32_t *leaves, uint32_t max,
                           uint32_t *count, int *truncated);

/* Decode an xattr map (u32 count + (string name, bufferptr value) pairs, as
 * written by InodeStore) at the cursor, writing up to `max` entries to `out`
 * (pointers into the cursor's buffer). Sets *truncated when there are more than
 * `max`. 0 / -1. */
int cephfs_decode_xattrs(cephfs_denc_t *d, cephfs_xattr_t *out, uint32_t max,
                         uint32_t *count, int *truncated);

/* Decode a whole directory-entry omap value (`<name>_head`) into *out. Handles
 * primary ('I'/'i') and remote ('L'/'l') dentries. 0 on success; -1 on a
 * malformed value or an encoding this decoder does not understand. */
int cephfs_decode_dentry(const void *buf, size_t len, cephfs_dentry_t *out);

#endif /* XROOTD_CEPHFS_LAYOUT_H */

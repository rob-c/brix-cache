/* changeset.h — publish changeset from a union-overlay upper tree (phase-96 S4).
 *
 * WHAT: walk an upper directory (the overlay grammar of client/lib/fs/overlay.h:
 *       real entries = adds/modifies, ".brix.wh.<name>" = whiteout/delete,
 *       ".brix.opq" = opaque dir) into an ordered add/modify/delete set.
 * WHY:  the overlay IS the transaction's changeset representation; publish
 *       consumes this set, never the raw upper tree.
 * HOW:  per-component O_NOFOLLOW descent rooted at the upper dir — symlinks in
 *       the (user-writable) upper tree are recorded as entries, NEVER followed,
 *       so a planted link cannot lead the ingestion walk outside the upper dir.
 */
#ifndef BRIX_CVMFS_CHANGESET_H
#define BRIX_CVMFS_CHANGESET_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    CVMFS_CH_DELETE = 0,        /* whiteout: remove path (file or subtree) */
    CVMFS_CH_ADD_DIR,           /* mkdir / attr refresh (upsert, keeps children) */
    CVMFS_CH_ADD_FILE,          /* new or replaced regular file (src = upper file) */
    CVMFS_CH_ADD_LINK           /* new or replaced symlink */
} cvmfs_change_op_e;

typedef struct {
    char     *path;             /* repo-root-relative, leading '/' */
    char     *src;              /* absolute upper-tree path (ADD_FILE ingestion) */
    char     *link;             /* symlink target (ADD_LINK) */
    int       op;               /* cvmfs_change_op_e */
    uint32_t  mode;             /* full st_mode */
    uint32_t  uid, gid;
    int64_t   mtime;
    uint64_t  size;
    int       opaque;           /* ADD_DIR: replace the lower dir wholesale */
    int       no_clobber;       /* ADD_DIR: refuse if published entry is a
                                   non-dir; ADD_LINK: refuse if it is a dir.
                                   Set by reprefix-synthesized ancestors and
                                   the ingest CLI's structural entries so a
                                   publish never silently retypes foreign
                                   content (phase-104 D8/D9). */
    uint32_t  linkcount;        /* ADD_FILE: hardlink-group member count, 0 = 1 */
    uint32_t  hardlink_group;   /* ADD_FILE: 0 = not hardlinked within the upper */
    unsigned char *xattr;       /* packed user.* xattr BLOB (cvmfs_xattr_pack) */
    size_t    xattr_len;        /* 0 = no xattrs */
    uint64_t  dev, ino;         /* scan-internal: hardlink identity (ADD_FILE) */
    uint32_t  nlink;            /* scan-internal: st_nlink at scan time */
} cvmfs_change_t;

typedef struct {
    cvmfs_change_t *v;
    size_t          n, cap;
} cvmfs_changeset_t;

/* Scan `upper_dir` into *cs (caller must cvmfs_changeset_free). The result is
 * ordered for direct application: all DELETEs first, then ADDs sorted by path
 * (parents strictly before children). Regular files sharing an inode within
 * the upper tree are assigned a common hardlink_group with linkcount = member
 * count; user.* xattrs of files and dirs are captured as packed BLOBs (an
 * xattr set exceeding the catalog BLOB bounds fails the scan). 0 on success;
 * on error -1 with a message in err. */
int cvmfs_changeset_scan(const char *upper_dir, cvmfs_changeset_t *cs,
                         char *err, size_t errlen);

void cvmfs_changeset_free(cvmfs_changeset_t *cs);

/* Re-root a scanned changeset under `prefix` (absolute, validated: no empty,
 * "." or ".." components, no reserved ".brix.*" grammar): every path becomes
 * <prefix><path>, and one ADD_DIR upsert per prefix ancestor (0755, caller's
 * uid/gid, no_clobber set) is appended and the set re-sorted, so publishing
 * into a repo where the chain does not exist yet just works while a published
 * NON-dir at any ancestor fails the publish instead of being retyped.
 * "/" is the identity. The ingest conductors (phase-104 D8/D9) are the
 * callers. 0 on success; -1 with a message in err (the set may be partially
 * rewritten — callers free it on failure anyway). */
int cvmfs_changeset_reprefix(cvmfs_changeset_t *cs, const char *prefix,
                             char *err, size_t errlen);

#endif /* BRIX_CVMFS_CHANGESET_H */

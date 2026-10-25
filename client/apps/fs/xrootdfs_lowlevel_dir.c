/* Bounded, seekable per-open directory snapshots. Native BSD readdir needs
 * nonzero directory inode values and real continuation offsets, not a repeatedly
 * emitted unbounded list. No directory entry grants a lookup reference.
 */
#include "xrootdfs_lowlevel.h"

#define XFS_DIRECTORY_LIMIT (64U * 1024U * 1024U)
typedef struct {
    fuse_req_t req;
    xfs_session *session;
    fuse_ino_t ino;
    char *data;
    size_t length, capacity;
    int error;
} xfs_directory;

/* WHAT: Choose an advisory directory inode. WHY: Listing/stat identities should
 * agree, without creating lookup owners. HOW: 1. Resolve dots explicitly.
 * 2. Form a checked child key. 3. Ask the shared collision-aware registry. */
static ino_t
xfs_dir_ino(xfs_directory *directory, const char *name, const struct stat *attr)
{
    if (strcmp(name, ".") == 0) {
        return (ino_t) directory->ino;
    }
    char path[XRDC_PATH_MAX];
    if (strcmp(name, "..") == 0) {
        if (xfs_req_path(directory->session, directory->ino, path) != 0) {
            return (ino_t) -1;
        }
        char *slash = strrchr(path, '/');
        if (slash == path) { slash[1] = '\0'; }
        else { *slash = '\0'; }
        xfs_alias *alias = xfs_nodes_alias(&directory->session->nodes, path);
        return alias ? (ino_t) alias->node->ino : (ino_t) -1;
    }
    if (xfs_req_child(directory->session, directory->ino, name, path) != 0) {
        return (ino_t) -1;
    }
    uint64_t candidate = xfs_nodes_ino_hint(&directory->session->nodes, path,
                                           attr ? (uint64_t) attr->st_ino : 0);
    return candidate ? (ino_t) candidate : (ino_t) -1;
}

/* WHAT: Append one encoded directory entry. WHY: FUSE owns wire encoding.
 * HOW: 1. Compute public-API encoded size. 2. Enforce a snapshot budget.
 *      3. Grow geometrically and emit its byte-exact continuation offset. */
static int
xfs_dir_fill(void *userdata, const char *name, const struct stat *attr,
               off_t offset, enum fuse_fill_dir_flags flags)
{
    xfs_directory *directory = userdata;
    (void) offset; (void) flags;
    if (directory->error) {
        return 1;
    }
    struct stat entry = {0};
    if (attr) {
        entry = *attr;
    }
    /* A collision is explicitly unknown (-1), never inode zero (an unused
     * entry on native BSD). No advisory id authorizes a kernel lookup. */
    entry.st_ino = xfs_dir_ino(directory, name, attr);
    size_t bytes = fuse_add_direntry(directory->req, NULL, 0, name, &entry, 0);
    if (bytes > XFS_DIRECTORY_LIMIT - directory->length) {
        directory->error = -EOVERFLOW;
        return 1;
    }
    size_t end = directory->length + bytes;
    if (end > directory->capacity) {
        size_t capacity = directory->capacity ? directory->capacity * 2 : 4096;
        if (capacity < end) { capacity = end; }
        char *replacement = realloc(directory->data, capacity);
        if (!replacement) {
            directory->error = -ENOMEM;
            return 1;
        }
        directory->data = replacement;
        directory->capacity = capacity;
    }
    fuse_add_direntry(directory->req, directory->data + directory->length, bytes,
                       name, &entry, (off_t) end);
    directory->length = end;
    return 0;
}

/* WHAT: Free a directory snapshot. WHY: Both failed replies and release own it.
 * HOW: 1. Free payload. 2. Free its owner. */
static void
xfs_dir_free(xfs_directory *directory)
{
    free(directory->data);
    free(directory);
}

/* WHAT: Open an authorized directory snapshot. WHY: Offset pagination must be stable.
 * HOW: 1. Resolve caller path. 2. Build bounded entries. 3. Retain open owner.
 *      4. Reply with handle or release all resources on failure. */
void
xfs_ll_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    int rc = xfs_req_path(session, ino, path);
    xfs_directory *directory = calloc(1, sizeof(*directory));
    if (!directory) {
        xfs_req_finish(req, session, -ENOMEM);
        return;
    }
    directory->req = req;
    directory->session = session;
    directory->ino = ino;
    if (rc == 0) {
        rc = xfs_readdir(xfs_req_uid(req), path, directory, xfs_dir_fill, 0, NULL, 0);
    }
    if (rc == 0) { rc = directory->error; }
    if (rc != 0) {
        xfs_dir_free(directory);
        xfs_req_finish(req, session, rc);
        return;
    }
    xfs_node *node = xfs_nodes_find(&session->nodes, ino);
    node->opens++;
    fi->fh = (uint64_t) (uintptr_t) directory;
    if (fuse_reply_open(req, fi) != 0) {
        xfs_dir_free(directory);
        xfs_nodes_close(&session->nodes, node);
    }
    pthread_mutex_unlock(&session->mutex);
}

/* WHAT: Return a requested snapshot segment. WHY: Honor kernel pagination.
 * HOW: 1. Validate handle and cursor. 2. Clamp count to remaining bytes.
 *      3. Reply without re-querying or acquiring lookup references. */
void
xfs_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                struct fuse_file_info *fi)
{
    (void) ino;
    xfs_directory *directory = (xfs_directory *) (uintptr_t) fi->fh;
    if (!directory || offset < 0 || (uint64_t) offset > directory->length) {
        fuse_reply_err(req, EINVAL);
        return;
    }
    size_t remaining = directory->length - (size_t) offset;
    size_t count = size < remaining ? size : remaining;
    fuse_reply_buf(req, count ? directory->data + offset : NULL, count);
}

/* WHAT: Release a directory snapshot. WHY: Open owners survive kernel forgets.
 * HOW: 1. Free the exact handle. 2. Drop its inode open owner. 3. Reply. */
void
xfs_ll_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    xfs_directory *directory = (xfs_directory *) (uintptr_t) fi->fh;
    if (directory) {
        xfs_dir_free(directory);
        fi->fh = 0;
    }
    xfs_session *session = xfs_req_lock(req);
    xfs_node *node = xfs_nodes_find(&session->nodes, ino);
    if (node) {
        xfs_nodes_close(&session->nodes, node);
    }
    xfs_req_finish(req, session, 0);
}

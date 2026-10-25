/* FUSE low-level lifecycle and request ownership, shared by root and WebDAV.
 * The async driver already daemonizes before creating threads. This layer
 * mounts without another fork and gives every alias the same kernel identity.
 */
#include "xrootdfs_lowlevel.h"
#include "../../../shared/observability/log_stdio.h"

/* WHAT: Obtain the kernel-authenticated caller uid. WHY: No owner fallback.
 * HOW: 1. Read the public low-level request context. */
uid_t
xfs_req_uid(fuse_req_t req)
{
    return fuse_req_ctx(req)->uid;
}

/* WHAT: Lock this request's namespace. WHY: Rename and aliases move together.
 * HOW: 1. Read mount userdata. 2. Lock its mutex. */
xfs_session *
xfs_req_lock(fuse_req_t req)
{
    xfs_session *session = fuse_req_userdata(req);
    pthread_mutex_lock(&session->mutex);
    return session;
}

/* WHAT: Complete a status-only request. WHY: Unlock on every error path.
 * HOW: 1. Release namespace ownership. 2. Reply with positive errno. */
void
xfs_req_finish(fuse_req_t req, xfs_session *session, int rc)
{
    pthread_mutex_unlock(&session->mutex);
    fuse_reply_err(req, rc < 0 ? -rc : rc);
}

/* WHAT: Copy a live inode name, returning negative errno if absent.
 * WHY: Never substitute root or another file for a forgotten/unlinked inode.
 * HOW: 1. Resolve its exact id. 2. Require a surviving alias. 3. Copy bounded key. */
int
xfs_req_path(xfs_session *session, fuse_ino_t ino, char *out)
{
    const char *path = xfs_node_path(xfs_nodes_find(&session->nodes, ino));
    if (!path) {
        return -ESTALE;
    }
    memcpy(out, path, strlen(path) + 1);
    return 0;
}

/* WHAT: Construct one child key, returning negative errno on malformed input.
 * WHY: FUSE node names cannot escape their parent or alias another namespace.
 * HOW: 1. Reject traversal/separators. 2. Resolve parent. 3. Append with bounds. */
int
xfs_req_child(xfs_session *session, fuse_ino_t parent, const char *name, char *out)
{
    if (!name[0] || strchr(name, '/') || strcmp(name, ".") == 0
        || strcmp(name, "..") == 0) {
        return -EINVAL;
    }
    int rc = xfs_req_path(session, parent, out);
    if (rc != 0) {
        return rc;
    }
    size_t length = strlen(out), extra = strlen(name);
    size_t slash = length > 1 ? 1 : 0;
    if (length + slash + extra >= XRDC_PATH_MAX
        || strlen(g_base) + length + slash + extra >= XRDC_PATH_MAX) {
        return -ENAMETOOLONG;
    }
    if (slash) {
        out[length++] = '/';
    }
    memcpy(out + length, name, extra + 1);
    return 0;
}

/* WHAT: Reply with one stable identity and balanced lookup/open owners.
 * WHY: LINK must return its source node id, not a fresh path-based id.
 * HOW: 1. Authorize/stat as the caller. 2. Bind reserved alias. 3. Reply and
 *      compensate references if the kernel rejects an interrupted reply. */
int
xfs_ll_entry(fuse_req_t req, xfs_session *session, const char *path,
              struct fuse_file_info *fi, xfs_node_ticket *ticket, xfs_node *preferred)
{
    struct fuse_entry_param entry;
    memset(&entry, 0, sizeof(entry));
    int rc;
    if (fi && fi->fh && !g_web) {
        afh *handle = (afh *) (uintptr_t) fi->fh;
        brix_statinfo info;
        brix_status status;
        brix_status_clear(&status);
        rc = brix_mfile_stat(handle->mf, &info, &status);
        if (rc == 0) {
            xfs_fill_stat(&info, &entry.attr);
        } else {
            rc = xfs_err(&status);
        }
    } else {
        rc = xfs_getattr(xfs_req_uid(req), path, &entry.attr, fi);
    }
    if (rc != 0) {
        return rc;
    }
    xfs_node *node = xfs_nodes_bind(&session->nodes, ticket,
                                   (uint64_t) entry.attr.st_ino, preferred);
    entry.ino = node->ino;
    entry.generation = node->generation;
    entry.attr.st_ino = (ino_t) node->ino;
    entry.attr_timeout = g_sss_ident ? 0 : g_attr_timeout;
    entry.entry_timeout = g_sss_ident ? 0 : g_entry_timeout;
    node->lookups++;
    if (fi) {
        ((afh *) (uintptr_t) fi->fh)->attr = entry.attr;
        xfs_ll_handle_attach(node, fi, xfs_req_uid(req));
        rc = fuse_reply_create(req, &entry, fi);
    } else {
        rc = fuse_reply_entry(req, &entry);
    }
    if (rc != 0) {
        if (fi) {
            node->open_handles = ((afh *) (uintptr_t) fi->fh)->node_next;
            xfs_release(path, fi);
            node->opens--;
        }
        xfs_nodes_forget(&session->nodes, node, 1);
    }
    return 0; /* a reply, including an interrupted one, was already sent */
}

/* WHAT: Complete negotiated startup. WHY: Launchers must not race initialization.
 * HOW: 1. Disable implicit writeback identity sharing. 2. Signal readiness. */
static void
xfs_ll_init(void *userdata, struct fuse_conn_info *conn)
{
    (void) userdata;
    conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;
    xfs_daemon_ready(0);
}

const struct fuse_lowlevel_ops xfs_lowlevel_ops = {
    .init = xfs_ll_init, .lookup = xfs_ll_lookup, .forget = xfs_ll_forget,
    .getattr = xfs_ll_getattr, .setattr = xfs_ll_setattr,
    .readlink = xfs_ll_readlink, .mknod = xfs_ll_mknod, .mkdir = xfs_ll_mkdir,
    .unlink = xfs_ll_unlink, .rmdir = xfs_ll_rmdir, .symlink = xfs_ll_symlink,
    .rename = xfs_ll_rename, .link = xfs_ll_link,
    .open = xfs_ll_open, .create = xfs_ll_create,
    .read = xfs_ll_read, .write = xfs_ll_write, .flush = xfs_ll_flush,
    .release = xfs_ll_release, .fsync = xfs_ll_fsync,
    .opendir = xfs_ll_opendir, .readdir = xfs_ll_readdir,
    .releasedir = xfs_ll_releasedir, .statfs = xfs_ll_statfs,
    .access = xfs_ll_access, .getxattr = xfs_ll_getxattr,
    .listxattr = xfs_ll_listxattr, .setxattr = xfs_ll_setxattr,
    .removexattr = xfs_ll_removexattr,
};

/* WHAT: Mount/run one prepared session. WHY: Balance signals and unmount on exit.
 * HOW: 1. Mount. 2. Install signal hooks. 3. Run requested threading. 4. Unwind. */
static int
xfs_session_run(struct fuse_session *session, struct fuse_cmdline_opts *opts)
{
    if (fuse_session_mount(session, opts->mountpoint) != 0) {
        return 1;
    }
    if (fuse_set_signal_handlers(session) != 0) {
        fuse_session_unmount(session);
        return 1;
    }
    int rc = opts->singlethread ? fuse_session_loop(session)
                                : fuse_session_loop_mt(session, opts->clone_fd);
    fuse_remove_signal_handlers(session);
    fuse_session_unmount(session);
    return rc < 0 ? 1 : 0;
}

/* WHAT: Run the low-level driver, returning shell status.
 * WHY: A single inode-aware path serves every supported host and transport.
 * HOW: 1. Initialize mount-owned state. 2. Parse public libfuse arguments.
 *      3. Create/run/destroy the session. 4. Free all mount resources. */
int
xfs_session_main(int argc, char **argv)
{
    xfs_session *state = calloc(1, sizeof(*state));
    if (!state) {
        return 1;
    }
    int rc = xfs_nodes_init(&state->nodes);
    if (rc != 0) {
        free(state);
        return 1;
    }
    pthread_mutex_init(&state->mutex, NULL);
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    memset(&opts, 0, sizeof(opts));
    rc = 1;
    if (fuse_parse_cmdline(&args, &opts) == 0 && opts.mountpoint) {
        struct fuse_session *session = fuse_session_new(&args, &xfs_lowlevel_ops,
                                                       sizeof(xfs_lowlevel_ops), state);
        if (session) {
            rc = xfs_session_run(session, &opts);
            fuse_session_destroy(session);
        }
    }
    free(opts.mountpoint);
    fuse_opt_free_args(&args);
    xfs_nodes_destroy(&state->nodes);
    pthread_mutex_destroy(&state->mutex);
    free(state);
    return rc;
}

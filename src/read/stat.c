#include "../ngx_xrootd_module.h"
#include "stat.h"
#include "../path/op_path.h"
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../cms/cms_internal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/statvfs.h>

/*
 * xrootd_make_vfs_body — kXR_stat(kXR_vfs) / `xrdfs statvfs` response body.
 *
 * The reference format (XrdCl StatInfoVFS::ParseServerResponse) is SIX
 * space-separated integers, each a bare number:
 *   "<nodesRW> <freeRW_MB> <utilRW%> <nodesStaging> <freeStaging_MB> <utilStaging%>"
 * (We previously emitted the 4-field "id size flags mtime" stat line here, which
 * the stock client rejects as "Invalid response".) Free space comes from
 * statvfs(2) on the export root; staging is reported as 0 (no tape staging tier).
 */
static void
xrootd_make_vfs_body(ngx_stream_xrootd_srv_conf_t *conf, char *out, size_t outsz)
{
    struct statvfs vfs;
    const char    *root = conf->common.root_canon[0]
                          ? conf->common.root_canon : "/";
    long long      free_mb = 0, total_mb = 0;
    int            util = 0;
    int            nrw = conf->common.allow_write ? 1 : 0;

    if (statvfs(root, &vfs) == 0) {
        unsigned long bs = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
        free_mb  = (long long) ((double) vfs.f_bavail * (double) bs / 1048576.0);
        total_mb = (long long) ((double) vfs.f_blocks * (double) bs / 1048576.0);
        if (total_mb > 0) {
            util = (int) (100.0 * (double) (total_mb - free_mb)
                          / (double) total_mb);
        }
    }

    snprintf(out, outsz, "%d %lld %d 0 0 0", nrw, free_mb, util);
}

extern char **environ;

/* ---- xrootd_stat_origin_forward — GSI-origin stat for the cache ----
 *
 * WHAT: When the cache has an X.509 proxy (xrootd_cache_origin_proxy) and the
 *       path is not present locally, resolve a kXR_stat by fork/exec'ing the
 *       native `xrdfs <origin> stat <path>` (GSI) and parsing its output into a
 *       host `struct stat`. Same PSS-via-native-client pattern as the cache fill
 *       and the dirlist forward.
 * WHY:  The cache disk holds only fetched FILES; a metadata stat on a namespace
 *       entry that has not yet been cached (a directory, or an un-fetched file)
 *       must be answered from the origin, which requires GSI auth that only the
 *       native client provides.
 * HOW:  Combined stdout+stderr captured over a pipe. exit 0 → parse the "Size:"
 *       and "Flags:" lines (Flags containing "IsDir" → directory) into `st`;
 *       returns 0. exit != 0 (or parse failure) → returns -1, caller falls back
 *       to the local errno error.
 * NOTE: Runs synchronously in the event loop (like the local stat), so a slow
 *       origin briefly stalls the worker — acceptable first cut, mirrors the
 *       dirlist forward; a threaded variant is future work. */
static int
xrootd_stat_origin_forward(ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *reqpath, struct stat *st)
{
    char        endpoint[320];
    char        proxy_env[XROOTD_MAX_PATH + 32];
    char        cadir_env[XROOTD_MAX_PATH + 32];
    char        xrdfs_path[XROOTD_MAX_PATH + 1];
    char       *argv[5];
    char      **envp;
    posix_spawn_file_actions_t fa;
    int         pipefd[2];
    pid_t       pid;
    int         n, rc, wstatus, ai;
    size_t      envn, ei;
    char        out[4096];
    size_t      out_len = 0;
    char       *line, *save;
    const char *client;
    long long   sz = -1;
    int         is_dir = 0, have_size = 0, have_flags = 0;

    /* derive the xrdfs path from the configured xrdcp path (…/xrdcp → …/xrdfs) */
    client = conf->cache_origin_client.len
             ? (char *) conf->cache_origin_client.data : "xrdcp";
    n = snprintf(xrdfs_path, sizeof(xrdfs_path), "%s", client);
    if (n >= 5 && strcmp(xrdfs_path + n - 5, "xrdcp") == 0) {
        ngx_memcpy(xrdfs_path + n - 5, "xrdfs", 5);
    } else {
        snprintf(xrdfs_path, sizeof(xrdfs_path), "xrdfs");
    }

    n = snprintf(endpoint, sizeof(endpoint), "%s://%s:%u",
                 conf->cache_origin_tls ? "roots" : "root",
                 (char *) conf->cache_origin_host.data,
                 (unsigned) conf->cache_origin_port);
    if (n < 0 || (size_t) n >= sizeof(endpoint)) {
        return -1;
    }
    snprintf(proxy_env, sizeof(proxy_env), "X509_USER_PROXY=%s",
             (char *) conf->cache_origin_proxy.data);
    snprintf(cadir_env, sizeof(cadir_env), "X509_CERT_DIR=%s",
             (char *) conf->cache_origin_cadir.data);

    for (envn = 0; environ[envn] != NULL; envn++) { /* count */ }
    envp = ngx_palloc(c->pool, (envn + 3) * sizeof(char *));
    if (envp == NULL) { return -1; }
    ei = 0;
    for (n = 0; (size_t) n < envn; n++) {
        if (ngx_strncmp(environ[n], "X509_USER_PROXY=", 16) == 0
            || ngx_strncmp(environ[n], "X509_CERT_DIR=", 14) == 0) {
            continue;
        }
        envp[ei++] = environ[n];
    }
    envp[ei++] = proxy_env;
    envp[ei++] = cadir_env;
    envp[ei]   = NULL;

    ai = 0;
    argv[ai++] = xrdfs_path;
    argv[ai++] = endpoint;
    argv[ai++] = (char *) "stat";
    argv[ai++] = (char *) reqpath;
    argv[ai]   = NULL;

    if (pipe(pipefd) != 0) { return -1; }
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], 1);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], 2);
    posix_spawn_file_actions_addclose(&fa, pipefd[0]);
    posix_spawn_file_actions_addclose(&fa, pipefd[1]);

    rc = posix_spawnp(&pid, xrdfs_path, &fa, NULL, argv, envp);
    posix_spawn_file_actions_destroy(&fa);
    close(pipefd[1]);
    if (rc != 0) { close(pipefd[0]); return -1; }

    for (;;) {
        ssize_t r = read(pipefd[0], out + out_len, sizeof(out) - 1 - out_len);
        if (r < 0 && errno == EINTR) { continue; }
        if (r <= 0) { break; }
        out_len += (size_t) r;
        if (out_len >= sizeof(out) - 1) { break; }
    }
    close(pipefd[0]);
    out[out_len] = '\0';
    while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) { /* retry */ }

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        return -1;
    }

    /* Parse the "Size:" and "Flags:" lines of the xrdfs stat report. */
    for (line = strtok_r(out, "\n", &save);
         line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        while (*line == ' ' || *line == '\t') { line++; }
        if (ngx_strncmp(line, "Size:", 5) == 0) {
            if (sscanf(line + 5, " %lld", &sz) == 1) { have_size = 1; }
        } else if (ngx_strncmp(line, "Flags:", 6) == 0) {
            have_flags = 1;
            if (strstr(line, "IsDir") != NULL) { is_dir = 1; }
        }
    }

    if (!have_flags) { return -1; }

    ngx_memzero(st, sizeof(*st));
    st->st_mode  = is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
    st->st_size  = have_size && sz >= 0 ? (off_t) sz : 0;
    st->st_nlink = 1;
    st->st_mtime = ngx_time();
    return 0;
}

/* Return kXR_cachersp if reqpath (client's clean path) exists in cache_root. */
int
xrootd_cache_path_flag(const ngx_stream_xrootd_srv_conf_t *conf, const char *reqpath)
{
    char        cache_path[PATH_MAX];
    struct stat cst;
    int         n;

    if (!conf->cache || conf->cache_root.len == 0 || reqpath == NULL) {
        return 0;
    }

    n = snprintf(cache_path, sizeof(cache_path), "%s%s",
                 (char *) conf->cache_root.data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(cache_path)) {
        return 0;
    }

    return (stat(cache_path, &cst) == 0 && S_ISREG(cst.st_mode))
           ? kXR_cachersp : 0;
}

ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientStatRequest *req = (ClientStatRequest *) ctx->hdr_buf;
    struct stat        st;
    char               full_path[PATH_MAX];
    char               reqpath_buf[XROOTD_MAX_PATH + 1];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath = NULL;
    ngx_int_t          validate_rc;
    int                extra_flags = 0;

    is_vfs = (req->options & kXR_vfs) ? 1 : 0;

    /*
     * kXR_stat is dual-mode like upstream XRootD:
     *   - dlen > 0 means the payload names a path to resolve and stat(2)
     *   - dlen == 0 means the opaque handle identifies an already-open fd
     *
     * The logging path and the syscall target are deliberately separated in the
     * handle case: logs use the cached canonical path, while fstat() uses the fd.
     */

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                 reqpath_buf, sizeof(reqpath_buf), 1)) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", "-", "-",
                              kXR_ArgInvalid, "invalid path payload");
        }
        reqpath = reqpath_buf;
        /* Reject any ".." component outright (the reference does not normalize
         * "..").  This op resolves through the kernel RESOLVE_BENEATH, which
         * would silently collapse an in-tree "..", so the guard is explicit. */
        if (xrootd_reject_dotdot_path(ctx, c, XROOTD_OP_STAT, "STAT", reqpath)) {
            return ctx->write_rc;
        }
        /* Static manager_map: an explicit prefix→backend redirect (mirrors the
         * open/locate paths) so a static-map redirector also serves stat — stock
         * and go-hep clients stat a path before they open it, and without this a
         * map-only redirector answered stat locally (IOError, no root). */
        if (conf->manager_map != NULL) {
            const xrootd_manager_map_t *m =
                xrootd_find_manager_map(reqpath, conf->manager_map);
            if (m != NULL) {
                XROOTD_RETURN_REDIR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath,
                                    "manager_map",
                                    (const char *) m->host.data, m->port);
            }
        }
        /* Manager mode: redirect to a registered data server. */
        if (conf->manager_mode) {
            char     redir_host[256];
            uint16_t redir_port;

            /* tried/triedrc: if the client has already visited every server
             * that holds this path and they returned enoent, stop redirecting
             * and answer not-found — otherwise the client redirect-loops. */
            if (xrootd_manager_tried_exhausted(ctx->payload, ctx->cur_dlen,
                                               reqpath)) {
                XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                                  kXR_NotFound,
                                  "file not found on any data server");
            }

            /* Like open: tolerate a server whose CMS heartbeat just dropped (it
             * is almost certainly still serving) rather than a false NotFound. */
            if (xrootd_srv_select_or_blacklisted(reqpath, 0, redir_host,
                                  sizeof(redir_host), &redir_port)) {
                XROOTD_RETURN_REDIR(ctx, c, XROOTD_OP_STAT, "STAT",
                                    reqpath, "registry",
                                    redir_host, redir_port);
            }

            /* Registry miss — ask CMS parent if configured. */
            if (conf->cms_ctx != NULL) {
                uint32_t streamid;

                streamid = ngx_xrootd_cms_next_streamid(conf->cms_ctx);
                if (xrootd_pending_insert(streamid, ngx_pid, c->fd,
                                          c->number,
                                          ctx->cur_streamid,
                                          conf->cms_locate_timeout) == NGX_OK)
                {
                    ctx->cms_wait_streamid = streamid;
                    ctx->state = XRD_ST_WAITING_CMS;
                    ngx_add_timer(c->read, conf->cms_locate_timeout);
                    if (ngx_xrootd_cms_send_locate(conf->cms_ctx, streamid,
                                                   reqpath) == NGX_OK)
                    {
                        return NGX_AGAIN;
                    }
                    ngx_del_timer(c->read);
                    ctx->state = XRD_ST_REQ_HEADER;
                    xrootd_pending_remove(streamid, ngx_pid);
                }
            }
        }

        xrootd_beneath_full_path(conf->common.root_canon, reqpath,
                                  full_path, sizeof(full_path));

        if (xrootd_auth_gate(ctx, c, XROOTD_OP_STAT, "STAT",
                              reqpath, full_path, conf,
                              XROOTD_AUTH_LOOKUP, 0) != NGX_OK) {
            return ctx->write_rc;
        }

        {
            /* kXR_statNoFollow (vendor): lstat the final component so a symlink
             * reports as itself (kXR_other + target-length size) for FUSE getattr;
             * default follows symlinks exactly as before. */
            int src = (req->options & kXR_statNoFollow)
                      ? xrootd_lstat_beneath(conf->rootfd, reqpath, &st)
                      : xrootd_stat_beneath(conf->rootfd, reqpath, &st);

            /* Follow fallback for an in-export symlink with a host-ABSOLUTE
             * target: RESOLVE_IN_ROOT chroots the absolute target and lands on
             * ENOENT, where stock follows it on the real fs.  Match stock, but
             * CONFINE via realpath — accept only when the canonical target is
             * within the export root (an escaping link is rejected).  Read-only,
             * so the realpath/stat TOCTOU window is benign. */
            if (src != 0 && errno == ENOENT
                && !(req->options & kXR_statNoFollow)
                && conf->common.root_canon[0] != '\0')
            {
                char        real[PATH_MAX];
                size_t      rl = ngx_strlen(conf->common.root_canon);
                if (realpath(full_path, real) != NULL
                    && ngx_strncmp(real, conf->common.root_canon, rl) == 0
                    && (real[rl] == '/' || real[rl] == '\0')
                    && stat(real, &st) == 0)
                {
                    src = 0;
                }
            }
            if (src != 0) {
                int saved_errno = errno;
                /* Local miss: a GSI-proxy cache forwards the metadata stat to
                 * the origin namespace (file not yet fetched, or a directory). */
                if (conf->cache && conf->cache_origin_proxy.len > 0
                    && conf->cache_origin_host.len > 0
                    && xrootd_stat_origin_forward(c, conf, reqpath, &st) == 0)
                {
                    /* fall through to the response build with the origin stat */
                } else {
                    errno = saved_errno;
                    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath,
                                      "-", xrootd_kxr_from_errno(errno),
                                      strerror(errno));
                }
            }
        }

        extra_flags = xrootd_cache_path_flag(conf, reqpath);

        /* Phase 35: a nearline file (on the backend, not on disk) is reported
         * offline so the client knows to issue a prepare/stage before reading. */
        if (conf->frm.enable) {
            frm_residency_t _res;
            if (frm_residency_probe(c->log, full_path, &_res) == NGX_OK
                && (_res.state == FRM_RES_NEARLINE
                    || _res.state == FRM_RES_OFFLINE))
            {
                extra_flags |= kXR_offline | kXR_bkpexist;
            }
        }

    } else {
        /* Handle-based stat: fhandle[0] is our slot index. */
        /* The cached path is only for logging; the real metadata comes from fstat(). */
        int idx = (int)(unsigned char) req->fhandle[0];

        if (!xrootd_validate_file_handle(ctx, c, idx, "STAT",
                                         XROOTD_OP_STAT, &validate_rc)) {
            return validate_rc;
        }

        full_path[0] = '\0';
        ngx_cpystrn((u_char *) full_path,
                    (u_char *) (ctx->files[idx].path != NULL
                                ? ctx->files[idx].path : "-"),
                    sizeof(full_path));

        if (ctx->files[idx].slice_mode) {
            /*
             * Slice-mode handles park their fd on /dev/null (Phase 26), so
             * fstat() would report size 0.  The real file size was learned
             * from the origin at open time and stored in cached_size; synthesize
             * a regular-file stat from it so the client sees the true length.
             */
            ngx_memzero(&st, sizeof(st));
            st.st_mode = S_IFREG | 0644;
            st.st_size = (off_t) ctx->files[idx].cached_size;
            st.st_nlink = 1;
            st.st_mtime = ngx_time();
        } else if (fstat(ctx->files[idx].fd, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", full_path, "-",
                              kXR_IOError, strerror(errno));
        }

        extra_flags = (ctx->files[idx].from_cache || ctx->files[idx].slice_mode)
                          ? kXR_cachersp : 0;
    }

    /* Convert into the exact ASCII body the client expects. statvfs has its own
     * 6-field RW/staging-space format (xrdfs statvfs); a plain stat is the
     * 4-field "id size flags mtime" line. */
    if (is_vfs) {
        xrootd_make_vfs_body(conf, body, sizeof(body));
    } else {
        xrootd_make_stat_body(&st, 0, extra_flags, body, sizeof(body));
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_stat ok: %s", body);

    xrootd_log_access(ctx, c, "STAT",
                      (reqpath && reqpath[0]) ? reqpath : full_path,
                      is_vfs ? "vfs" : "-",
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_STAT);

    return xrootd_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}

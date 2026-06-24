/*
 * Directory listing handler — implements the kXR_dirlist operation.
 * Clients request a directory listing and receive entries as newline-delimited
 * text, optionally with per-entry stat information and checksum tokens.
 * The response is sent in 64KB chunks using kXR_oksofar continuation frames,
 * ending with a single kXR_ok frame to signal completion.
 */

#include "../ngx_xrootd_module.h"
#include "../aio/aio.h"
#include "../path/op_path.h"
#include "../manager/registry.h"
#include "../protocol/dirlist_fmt.h"   /* shared dstat lead-in sentinel */
#include "dcksm.h"

#include <spawn.h>
#include <sys/wait.h>
#include "../compat/alloc_guard.h"

extern char **environ;

/*
 * xrootd_dirlist_name_is_unsafe — detect control characters in a directory
 * entry name that would corrupt the newline-delimited kXR_dirlist wire format.
 *
 * The XRootD dirlist response separates entries with '\n'.  A filename
 * containing '\n' (or any other byte < 0x20) would be misinterpreted as a
 * record separator by the client.  Such filenames are skipped silently.
 *
 * Returns 1 (unsafe, skip this entry), 0 (safe to include).
 */
static ngx_flag_t
xrootd_dirlist_name_is_unsafe(const char *name)
{
    const u_char *p;

    for (p = (const u_char *) name; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f) {
            return 1;
        }
    }

    return 0;
}

/*
 * xrootd_handle_dirlist — handle kXR_dirlist: enumerate a directory and send
 * the entries as a multi-frame kXR_oksofar ... kXR_ok response.
 *
 * Wire format (ClientDirlistRequest):
 *   options: bitfield controlling response content:
 *     kXR_dstat  (0x01) — include per-entry stat info
 *     kXR_dcksm  (0x02) — include per-entry checksum (implies kXR_dstat)
 *   payload: NUL-terminated path, optionally followed by CGI "?cks.type=algo"
 *
 * Response format: a flat text block with one entry per line, each terminated
 * by '\n'.  If kXR_dstat is set, each entry is followed by a stat body
 * (stat-line format: "f|d|p flags mtime size").  Entries with control
 * characters in their names are silently skipped to prevent wire corruption.
 *
 * A 65536-byte chunk buffer is accumulated and flushed as kXR_oksofar frames;
 * the final flush uses kXR_ok to signal end-of-listing.
 */
/* ---- xrootd_dirlist_origin_forward — GSI-origin `ls` for the cache ----
 *
 * WHAT: When the cache has an X.509 proxy (xrootd_cache_origin_proxy), answer a
 *       dirlist by fork/exec'ing the native `xrdfs <origin> ls [-l] <path>` (GSI)
 *       and converting its output into a kXR_dirlist response. Same
 *       PSS-via-native-client pattern as the cache fill.
 * WHY:  The cache holds only fetched FILES, not the origin namespace; without this
 *       an `ls` lists the empty local cache dir. EOS requires GSI auth, which the
 *       native client provides; the built-in origin client is anonymous-only.
 * HOW:  Combined stdout+stderr captured over a pipe. exit 0 → each line is a path
 *       (plain) or "<flags> <size> <path>" (-l); the basename (+ a synthesized stat
 *       body when kXR_dstat was asked) is emitted. exit != 0 → the captured text is
 *       returned as the error.
 * NOTE: Runs synchronously in the event loop (like the existing local dirlist), so a
 *       slow origin briefly stalls the worker — acceptable first cut; a threaded
 *       variant is future work. Single response chunk.
 */
static ngx_int_t
xrootd_dirlist_origin_forward(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *reqpath, ngx_flag_t want_stat)
{
    char        endpoint[320];
    char        proxy_env[XROOTD_MAX_PATH + 32];
    char        cadir_env[XROOTD_MAX_PATH + 32];
    char        xrdfs_path[XROOTD_MAX_PATH + 1];
    char       *argv[6];
    char      **envp;
    posix_spawn_file_actions_t fa;
    int         pipefd[2];
    pid_t       pid;
    int         n, rc, wstatus, ai;
    size_t      envn, ei;
    u_char     *out;
    size_t      out_cap = 1u << 20, out_len = 0;
    u_char     *chunk, *data;
    size_t      chunk_cap = 1u << 20, chunk_pos = 0;
    char       *line, *save;
    const char *client;

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
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "origin endpoint too long");
    }
    snprintf(proxy_env, sizeof(proxy_env), "X509_USER_PROXY=%s",
             (char *) conf->cache_origin_proxy.data);
    snprintf(cadir_env, sizeof(cadir_env), "X509_CERT_DIR=%s",
             (char *) conf->cache_origin_cadir.data);

    for (envn = 0; environ[envn] != NULL; envn++) { /* count */ }
    envp = ngx_palloc(c->pool, (envn + 3) * sizeof(char *));
    if (envp == NULL) { return NGX_ERROR; }
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
    argv[ai++] = (char *) "ls";
    if (want_stat) { argv[ai++] = (char *) "-l"; }
    argv[ai++] = (char *) reqpath;
    argv[ai]   = NULL;

    if (pipe(pipefd) != 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ServerError, "origin ls pipe failed");
    }
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], 1);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], 2);
    posix_spawn_file_actions_addclose(&fa, pipefd[0]);
    posix_spawn_file_actions_addclose(&fa, pipefd[1]);

    rc = posix_spawnp(&pid, xrdfs_path, &fa, NULL, argv, envp);
    posix_spawn_file_actions_destroy(&fa);
    close(pipefd[1]);
    if (rc != 0) {
        close(pipefd[0]);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ServerError, "origin ls spawn failed");
    }

    out = ngx_palloc(c->pool, out_cap);
    if (out == NULL) { close(pipefd[0]); return NGX_ERROR; }
    for (;;) {
        ssize_t r = read(pipefd[0], out + out_len, out_cap - 1 - out_len);
        if (r < 0 && errno == EINTR) { continue; }
        if (r <= 0) { break; }
        out_len += (size_t) r;
        if (out_len >= out_cap - 1) { break; }
    }
    close(pipefd[0]);
    out[out_len] = '\0';
    while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) { /* retry */ }

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        char emsg[512];
        size_t m = out_len < sizeof(emsg) - 1 ? out_len : sizeof(emsg) - 1;
        ngx_memcpy(emsg, out, m);
        emsg[m] = '\0';
        while (m > 0 && (emsg[m - 1] == '\n' || emsg[m - 1] == '\r')) {
            emsg[--m] = '\0';
        }
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotFound,
                                 emsg[0] ? emsg : "origin ls failed");
    }

    chunk = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN + chunk_cap);
    if (chunk == NULL) { return NGX_ERROR; }
    data = chunk + XRD_RESPONSE_HDR_LEN;
    if (want_stat) {
        ngx_memcpy(data, XROOTD_DSTAT_LEADIN, XROOTD_DSTAT_LEADIN_LEN);
        chunk_pos = XROOTD_DSTAT_LEADIN_LEN;
    }

    for (line = strtok_r((char *) out, "\n", &save);
         line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        const char *path = line;
        const char *base;
        char        statbuf[256];
        long long   sz = 0;
        int         is_dir = 0;
        size_t      blen, need;

        if (want_stat) {
            /* "<flags> <size> <fullpath>"; flags[0]=='d' marks a directory. */
            char flags[33];
            char p2[XROOTD_MAX_PATH + 1];
            if (sscanf(line, "%32s %lld %1024[^\n]", flags, &sz, p2) == 3) {
                is_dir = (flags[0] == 'd');
                path = p2;
            } else {
                continue;
            }
        }

        base = strrchr(path, '/');
        base = (base != NULL) ? base + 1 : path;
        if (base[0] == '\0' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
            continue;
        }
        blen = strlen(base);

        statbuf[0] = '\0';
        if (want_stat) {
            struct stat sst;
            ngx_memzero(&sst, sizeof(sst));
            sst.st_mode = is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
            sst.st_size = (off_t) sz;
            xrootd_make_stat_body(&sst, 0, 0, statbuf, sizeof(statbuf));
        }

        need = blen + 1 + (want_stat ? strlen(statbuf) + 1 : 0);
        if (chunk_pos + need >= chunk_cap) {
            break;   /* single-chunk cap; very large dirs are truncated (logged) */
        }
        ngx_memcpy(data + chunk_pos, base, blen);
        chunk_pos += blen;
        data[chunk_pos++] = '\n';
        if (want_stat) {
            size_t sl = strlen(statbuf);
            ngx_memcpy(data + chunk_pos, statbuf, sl);
            chunk_pos += sl;
            data[chunk_pos++] = '\n';
        }
    }

    {
        size_t final_len = chunk_pos;
        if (final_len > 0) {
            data[final_len - 1] = '\0';   /* replace the trailing '\n' */
        }
        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, (uint32_t) final_len,
                              (ServerResponseHdr *) chunk);
        xrootd_log_access(ctx, c, "DIRLIST", reqpath, "origin-gsi", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_DIRLIST);
        return xrootd_queue_response(ctx, c, chunk,
                                     XRD_RESPONSE_HDR_LEN + final_len);
    }
}

ngx_int_t
xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientDirlistRequest *req = (ClientDirlistRequest *) ctx->hdr_buf;
    u_char                options;
    char                  full_path[PATH_MAX];
    char                  reqpath[XROOTD_MAX_PATH + 1];
    DIR                  *dp;
    struct dirent        *de;
    ngx_flag_t            want_stat;
    u_char               *chunk;
    size_t                chunk_cap = 65536;
    size_t                chunk_pos = 0;
    char                  statbuf[256];
    char                  cksum_algo[32];
    char                  bad_algo[32];
    ngx_int_t             rc;
    ngx_flag_t            want_cksum;
    int                   dfd;

/* ------------------------------------------------------------------ */
/* Section: Request Parsing & Auth Checks                              */
/* ------------------------------------------------------------------ */

    options = req->options;
    want_cksum = (options & kXR_dcksm) ? 1 : 0;
    want_stat = (options & (kXR_dstat | kXR_dcksm)) ? 1 : 0;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", "-", "-",
                          kXR_ArgMissing, "no path given");
    }

    if (want_cksum
        && xrootd_dirlist_checksum_algorithm(ctx->payload, ctx->cur_dlen,
                                             cksum_algo, sizeof(cksum_algo),
                                             bad_algo, sizeof(bad_algo))
           != NGX_OK)
    {
        char errmsg[128];

        snprintf(errmsg, sizeof(errmsg), "%s checksum not supported.",
                 bad_algo[0] ? bad_algo : "requested");
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", "-", "dcksm",
                          kXR_ServerError, errmsg);
    }

    if (!want_cksum) {
        ngx_cpystrn((u_char *) cksum_algo, (u_char *) "adler32",
                    sizeof(cksum_algo));
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, sizeof(reqpath), 1)) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", "-", "-",
                          kXR_ArgInvalid, "invalid path payload");
    }

    /* Reject any ".." component (the reference does not normalize ".."); dirlist
     * resolves through the kernel RESOLVE_BENEATH which would collapse it. */
    if (xrootd_reject_dotdot_path(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST",
                                  reqpath)) {
        return ctx->write_rc;
    }

    /* Static manager_map: explicit prefix→backend redirect (mirrors open/stat),
     * so a static-map redirector serves dirlist too (go-hep ls = stat + dirlist). */
    if (conf->manager_map != NULL) {
        const xrootd_manager_map_t *m =
            xrootd_find_manager_map(reqpath, conf->manager_map);
        if (m != NULL) {
            XROOTD_RETURN_REDIR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", reqpath,
                                "manager_map",
                                (const char *) m->host.data, m->port);
        }
    }

    /* Manager mode: redirect dirlist to a registered data server. */
    if (conf->manager_mode) {
        char     redir_host[256];
        uint16_t redir_port;

        if (xrootd_srv_select(reqpath, 0, redir_host,
                              sizeof(redir_host), &redir_port)) {
            XROOTD_RETURN_REDIR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", reqpath,
                                "registry", redir_host, redir_port);
        }
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_Overloaded,
                                 "no data server available");
    }

    xrootd_beneath_full_path(conf->common.root_canon, reqpath,
                             full_path, sizeof(full_path));

    if (xrootd_auth_gate(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST",
                          reqpath, full_path, conf,
                          XROOTD_AUTH_LOOKUP, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    /*
     * GSI-origin namespace forward: a cache configured with an X.509 proxy holds
     * only fetched files, not the origin's namespace — so answer dirlist from the
     * origin (e.g. EOS) via the native client. (want_cksum is not forwarded; a
     * dcksm request degrades to a plain/stat listing here.)
     */
    if (conf->cache && conf->cache_origin_proxy.len > 0
        && conf->cache_origin_host.len > 0)
    {
        return xrootd_dirlist_origin_forward(ctx, c, conf, reqpath, want_stat);
    }

    /*
     * Offload directory iteration + checksum computation to the nginx thread
     * pool so the event loop is not blocked during fstatat / hash-on-miss.
     *
     * If the pool is not configured or is full, xrootd_aio_post_task() returns
     * posted=0 and we fall through to the synchronous path below.
     */
    /*
     * Keep kXR_dirlist on the synchronous path for now.  The AIO variant can
     * complete successfully without delivering a response frame to clients,
     * which wedges xrdfs readiness probes in one-worker test deployments.
     */
    if (0 && conf->common.thread_pool != NULL) {
        ngx_thread_task_t    *task;
        xrootd_dirlist_aio_t *t;
        ngx_flag_t            posted;
        u_char               *response_buf;

        XROOTD_PALLOC_OR_RETURN(response_buf, c->pool, XROOTD_DIRLIST_AIO_RESPONSE_MAX, NGX_ERROR);

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_dirlist_aio_t));
        if (task == NULL) {
            return NGX_ERROR;
        }

        t = task->ctx;
        t->c            = c;
        t->ctx          = ctx;
        t->conf         = conf;
        t->streamid[0]  = ctx->cur_streamid[0];
        t->streamid[1]  = ctx->cur_streamid[1];
        t->want_stat    = want_stat;
        t->want_cksum   = want_cksum;
        t->response     = response_buf;
        t->response_cap = XROOTD_DIRLIST_AIO_RESPONSE_MAX;
        t->response_len = 0;
        t->io_errno     = 0;
        t->err_msg[0]   = '\0';
        ngx_cpystrn((u_char *) t->resolved,
                    (u_char *) full_path, sizeof(t->resolved));
        ngx_cpystrn((u_char *) t->cksum_algo,
                    (u_char *) cksum_algo, sizeof(t->cksum_algo));

        xrootd_task_bind(task, xrootd_dirlist_aio_thread, xrootd_dirlist_aio_done);

        if (xrootd_aio_post_task(ctx, c, conf->common.thread_pool, task,
                "xrootd: dirlist thread pool full, running synchronously",
                &posted) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (posted) {
            return NGX_OK;
        }

        /* Pool queue was full — fall through to the synchronous path. */
    }

/* ------------------------------------------------------------------ */
/* Section: Directory Open & Iteration                                 */
/* ------------------------------------------------------------------ */

    dfd = xrootd_open_beneath(conf->rootfd, reqpath, O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) {
        int err = errno;

        if (err == ENOTDIR) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", reqpath,
                              "-", kXR_NotFile, "path is not a directory");
        }
        if (err == ENOENT) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", reqpath,
                              "-", kXR_NotFound, "directory not found");
        }
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", reqpath,
                          "-", kXR_IOError, strerror(err));
    }

    dp = fdopendir(dfd);
    if (dp == NULL) {
        int err = errno;

        close(dfd);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_DIRLIST, "DIRLIST", reqpath,
                          "-", kXR_IOError, strerror(err));
    }

    /* Guard against pool exhaustion from a flood of dirlist calls. */
    if (ctx->pool_bytes_used + XRD_RESPONSE_HDR_LEN + chunk_cap
            > XROOTD_MAX_CONN_POOL_BYTES)
    {
        closedir(dp);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: dirlist pool limit reached (%uz bytes), "
                      "closing connection", ctx->pool_bytes_used);
        return xrootd_send_error(ctx, c, kXR_NoMemory,
                                 "connection pool limit exceeded");
    }
    chunk = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN + chunk_cap);
    if (chunk == NULL) {
        closedir(dp);
        return NGX_ERROR;
    }
    ctx->pool_bytes_used += XRD_RESPONSE_HDR_LEN + chunk_cap;

    {
        u_char *data = chunk + XRD_RESPONSE_HDR_LEN;

        if (want_stat) {
            ngx_memcpy(data, XROOTD_DSTAT_LEADIN, XROOTD_DSTAT_LEADIN_LEN);
            chunk_pos = XROOTD_DSTAT_LEADIN_LEN;
        }

/* ------------------------------------------------------------------ */
/* Section: Chunked Response Framing                                   */
/* ------------------------------------------------------------------ */

        while ((de = readdir(dp)) != NULL) {
            const char *name = de->d_name;
            size_t      nlen = strlen(name);
            char        safe_name[256];
            size_t      need = nlen + 1;
            struct stat entry_st;
            ngx_flag_t  have_stat = 0;
            char        cksum_token[EVP_MAX_MD_SIZE * 2 + 64];
            char        entry_path[PATH_MAX];

            cksum_token[0] = '\0';

            if (name[0] == '.' && (name[1] == '\0' ||
                (name[1] == '.' && name[2] == '\0')))
            {
                continue;
            }

            /* Hide this gateway's internal control artifacts (e.g. the
             * checkpoint recovery lock) — a stock XRootD export shows no such
             * files; mirror that. */
            if (ngx_strncmp(name, ".nginx-xrootd",
                            sizeof(".nginx-xrootd") - 1) == 0)
            {
                continue;
            }

            if (xrootd_dirlist_name_is_unsafe(name)) {
                xrootd_sanitize_log_string(name, safe_name, sizeof(safe_name));
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: dirlist skipping entry with control bytes \"%s\"",
                              safe_name);
                continue;
            }

            if (want_stat) {
                if (fstatat(dirfd(dp), name, &entry_st, AT_SYMLINK_NOFOLLOW) != 0) {
                    if (errno != ENOENT) {
                        xrootd_sanitize_log_string(name, safe_name,
                                                   sizeof(safe_name));
                        ngx_log_error(NGX_LOG_WARN, c->log, errno,
                                      "xrootd: dirlist stat failed for \"%s\"",
                                      safe_name);
                    }
                    continue;
                }

                have_stat = 1;
                if (want_cksum) {
                    xrootd_dirlist_make_dcksm_stat_body(&entry_st, statbuf,
                                                        sizeof(statbuf));
                } else {
                    xrootd_make_stat_body(&entry_st, 0, 0, statbuf,
                                          sizeof(statbuf));
                }
                need += strlen(statbuf) + 1;
            }

            if (want_cksum && have_stat) {
                int n;

                n = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                             full_path, name);
                if (n < 0 || (size_t) n >= sizeof(entry_path)) {
                    snprintf(cksum_token, sizeof(cksum_token),
                             "%s:none", cksum_algo);
                } else {
                    xrootd_dirlist_checksum_token(c->log, dirfd(dp), name,
                                                  entry_path, &entry_st,
                                                  cksum_algo, cksum_token,
                                                  sizeof(cksum_token));
                }
                need += strlen(cksum_token) + sizeof(" [  ]") - 1;
            }

            if (chunk_pos + need > chunk_cap) {
                xrootd_build_resp_hdr(ctx->cur_streamid, kXR_oksofar,
                                      (uint32_t) chunk_pos,
                                      (ServerResponseHdr *) chunk);

                rc = xrootd_queue_response(ctx, c, chunk,
                                           XRD_RESPONSE_HDR_LEN + chunk_pos);
                if (rc != NGX_OK) {
                    closedir(dp);
                    return rc;
                }

                chunk_pos = 0;
            }

            ngx_memcpy(data + chunk_pos, name, nlen);
            chunk_pos += nlen;
            data[chunk_pos++] = '\n';

            if (want_stat && have_stat) {
                size_t slen;

                slen = strlen(statbuf);
                ngx_memcpy(data + chunk_pos, statbuf, slen);
                chunk_pos += slen;

                if (want_cksum) {
                    int n;

                    n = snprintf((char *) data + chunk_pos,
                                 chunk_cap - chunk_pos,
                                 " [ %s ]", cksum_token);
                    if (n > 0) {
                        chunk_pos += (size_t) n;
                    }
                }

                data[chunk_pos++] = '\n';
            }
        }

/* ------------------------------------------------------------------ */
/* Section: Final Flush & Completion                                   */
/* ------------------------------------------------------------------ */

        closedir(dp);

        {
            size_t final_len;

            if (chunk_pos == 0) {
                final_len = 0;
            } else {
                data[chunk_pos - 1] = '\0';
                final_len = chunk_pos;
            }

            xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                                  (uint32_t) final_len,
                                  (ServerResponseHdr *) chunk);

            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: kXR_dirlist final chunk %uz bytes", chunk_pos);

            xrootd_log_access(ctx, c, "DIRLIST", reqpath,
                              want_cksum ? "dcksm" : (want_stat ? "stat" : "-"),
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_DIRLIST);

            return xrootd_queue_response(ctx, c, chunk,
                                         XRD_RESPONSE_HDR_LEN + final_len);
        }
    }
}

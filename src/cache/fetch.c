#include "cache_internal.h"
#include "meta.h"


#include <fcntl.h>
#include <regex.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* ---- xrootd_cache_commit_part — publish the downloaded part file ----
 * Atomically rename part_path → cache_path and write the .meta sidecar; also
 * records the cached size on the task. Shared by the anonymous-protocol fill and
 * the exec-GSI fill. Returns 0 / -1 (t error set). */
static int
xrootd_cache_commit_part(xrootd_cache_fill_t *t)
{
    struct stat          st;
    xrootd_cache_meta_t  meta;
    ngx_log_t           *log;

    if (rename(t->part_path, t->cache_path) != 0) {
        unlink(t->part_path);
        xrootd_cache_set_syserror(t, kXR_IOError, "cache part file rename failed");
        return -1;
    }

    log = (t->c != NULL) ? t->c->log : NULL;
    if (stat(t->cache_path, &st) == 0
        && xrootd_cache_meta_from_stat(&st, NULL, &meta) == NGX_OK)
    {
        t->file_size = (uint64_t) st.st_size;
        if (xrootd_cache_meta_write(log, t->cache_path, &meta) != NGX_OK
            && log != NULL)
        {
            ngx_log_error(NGX_LOG_WARN, log, errno,
                          "xrootd: cache metadata write failed \"%s\"",
                          t->cache_path);
        }
    }
    return 0;
}

/* ---- xrootd_cache_fetch_origin_exec — GSI/X.509-proxy origin fetch ----
 *
 * WHAT: Fork/exec the native client (cache_origin_client, default "xrdcp") to
 *       download the requested file from the origin into part_path, authenticating
 *       with X509_USER_PROXY=cache_origin_proxy + X509_CERT_DIR=cache_origin_cadir,
 *       then publish it via xrootd_cache_commit_part().
 * WHY:  The built-in origin client only does an anonymous kXR_login, which a GSI
 *       origin (e.g. EOS) rejects for file access. The native client speaks full
 *       GSI (proxy) + EOS open-redirect capability — so we reuse it as the PSS for
 *       authenticated origins. Runs in the fill thread-pool worker (blocking), so
 *       posix_spawn + waitpid does not stall the event loop.
 * HOW:  Build root[s]://host:port//<clean_path>; spawn with an env that overrides
 *       the two X509_* variables; on a clean exit(0) commit the part file. */
static int
xrootd_cache_fetch_origin_exec(xrootd_cache_fill_t *t)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    char        url[XROOTD_MAX_PATH + 320];
    char        proxy_env[XROOTD_MAX_PATH + 32];
    char        cadir_env[XROOTD_MAX_PATH + 32];
    const char *client;
    char      **envp;
    char       *argv[6];
    int         n, rc, wstatus, ai;
    size_t      envn, ei;
    pid_t       pid;

    if (conf->cache_origin_host.len == 0) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
            "xrootd_cache_origin_proxy set but no xrootd_cache_origin");
        return -1;
    }

    /* root[s]://host:port//<clean_path>  (clean_path carries its leading '/') */
    n = snprintf(url, sizeof(url), "%s://%s:%u/%s",
                 conf->cache_origin_tls ? "roots" : "root",
                 (char *) conf->cache_origin_host.data,
                 (unsigned) conf->cache_origin_port, t->clean_path);
    if (n < 0 || (size_t) n >= sizeof(url)) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "cache origin URL too long");
        return -1;
    }

    n = snprintf(proxy_env, sizeof(proxy_env), "X509_USER_PROXY=%s",
                 (char *) conf->cache_origin_proxy.data);
    if (n < 0 || (size_t) n >= sizeof(proxy_env)) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "cache origin proxy path too long");
        return -1;
    }
    n = snprintf(cadir_env, sizeof(cadir_env), "X509_CERT_DIR=%s",
                 (char *) conf->cache_origin_cadir.data);
    if (n < 0 || (size_t) n >= sizeof(cadir_env)) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "cache origin CA dir too long");
        return -1;
    }

    client = conf->cache_origin_client.len
             ? (char *) conf->cache_origin_client.data : "xrdcp";

    /* envp = environ minus any inherited X509_USER_PROXY / X509_CERT_DIR, plus ours. */
    for (envn = 0; environ[envn] != NULL; envn++) { /* count */ }
    envp = malloc((envn + 3) * sizeof(char *));
    if (envp == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0, "cache origin envp alloc failed");
        return -1;
    }
    ei = 0;
    for (n = 0; (size_t) n < envn; n++) {
        if (strncmp(environ[n], "X509_USER_PROXY=", 16) == 0
            || strncmp(environ[n], "X509_CERT_DIR=", 14) == 0) {
            continue;
        }
        envp[ei++] = environ[n];
    }
    envp[ei++] = proxy_env;
    envp[ei++] = cadir_env;
    envp[ei]   = NULL;

    ai = 0;
    argv[ai++] = (char *) client;
    argv[ai++] = (char *) "-f";       /* overwrite the part file */
    argv[ai++] = url;
    argv[ai++] = t->part_path;
    argv[ai]   = NULL;

    rc = posix_spawnp(&pid, client, NULL, NULL, argv, envp);
    free(envp);
    if (rc != 0) {
        char emsg[256];
        snprintf(emsg, sizeof(emsg),
                 "cache origin client '%s' spawn failed", client);
        xrootd_cache_set_error(t, kXR_ServerError, rc, emsg);
        return -1;
    }

    while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) { /* retry */ }

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        char emsg[XROOTD_MAX_PATH + 384];
        unlink(t->part_path);
        snprintf(emsg, sizeof(emsg),
                 "origin GSI fetch via %s failed (exit %d) for %s",
                 client, WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1, url);
        xrootd_cache_set_error(t, kXR_AuthFailed, 0, emsg);
        return -1;
    }

    return xrootd_cache_commit_part(t);
}

/* ---- xrootd_cache_fetch_origin — origin file fetch and cache fill ----
 *
 * WHAT: Thread-pool worker function that fetches a complete file from the configured XRootD origin into a local `.part` file,
 *       then atomically renames it to the cache path. Handles admission filtering (size + regex) before caching begins. */

/* ---- Fetch protocol sequence ----
 *
 * HOW: Connect → bootstrap (handshake+login) → open source file → read loop → fsync local part → rename atomic.
 *      Each phase is isolated with error cleanup (origin close on failure). Returns 1 for policy rejection, -1 for errors, 0 for success. */

/* ---- Admission filter invariant ----
 *
 * WHY: Large files (> cache_max_file_size) are not cached unless basename matches include regex.
 *      Rejection returns NGX_DECLINED (not error) so done callback redirects client to origin directly instead of failing. */

int
xrootd_cache_fetch_origin(xrootd_cache_fill_t *t)
{
    xrootd_cache_origin_conn_t oc;
    u_char                    fhandle[XRD_FHANDLE_LEN];
    int                       outfd;
    uint64_t                  offset;

    outfd = -1;
    offset = 0;

    /* GSI/X.509 origin (e.g. EOS): the built-in client only does an anonymous
     * login, which such an origin rejects. Delegate the fetch to the native
     * client with the configured proxy. */
    if (t->conf->cache_origin_proxy.len > 0) {
        return xrootd_cache_fetch_origin_exec(t);
    }

    if (xrootd_cache_origin_connect(t, &oc) != 0) {
        xrootd_cache_origin_close(&oc);
        return -1;
    }

    if (xrootd_cache_origin_bootstrap(t, &oc) != 0) {
        xrootd_cache_origin_close(&oc);
        return -1;
    }

    if (xrootd_cache_origin_open(t, &oc, fhandle) != 0) {
        xrootd_cache_origin_close(&oc);
        return -1;
    }

    /*
     * Admission filter: skip caching when the file is larger than the
     * configured limit AND its basename doesn't match the include regex.
     * Returning 1 (not -1) tells the caller this is a policy decision, not
     * an error — the done callback will redirect the client to the origin.
     */
    if (t->conf->cache_max_file_size > 0
        && t->file_size > t->conf->cache_max_file_size)
    {
        const char *basename = strrchr(t->clean_path, '/');
        basename = (basename != NULL) ? basename + 1 : t->clean_path;

        if (!t->conf->cache_include_regex_set
            || regexec(&t->conf->cache_include_regex, basename,
                       0, NULL, 0) != 0)
        {
            xrootd_cache_origin_close_file(&oc, fhandle);
            xrootd_cache_origin_close(&oc);
            t->result = NGX_DECLINED;
            return 1;
        }
    }

    /*
     * Open the part file in a single atomic call — O_CREAT|O_TRUNC creates or
     * truncates, O_NOFOLLOW rejects any symlink placed at part_path between
     * calls (prevents TOCTOU / symlink-swap attacks).  The prior unlink() was
     * removed: it created a race window and is made redundant by O_TRUNC.
     */
    outfd = open(t->part_path,
                 O_CREAT | O_TRUNC | O_WRONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
                 0644);
    if (outfd < 0) {
        xrootd_cache_origin_close_file(&oc, fhandle);
        xrootd_cache_origin_close(&oc);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache part file open failed");
        return -1;
    }

    for (;;) {
        size_t got;

        got = 0;
        if (xrootd_cache_origin_read_chunk(t, &oc, fhandle, outfd, offset,
                                           XROOTD_CACHE_FETCH_CHUNK,
                                           &got) != 0) {
            close(outfd);
            unlink(t->part_path);
            xrootd_cache_origin_close_file(&oc, fhandle);
            xrootd_cache_origin_close(&oc);
            return -1;
        }

        offset += (uint64_t) got;
        if (got < XROOTD_CACHE_FETCH_CHUNK) {
            break;
        }
    }

    if (fsync(outfd) != 0) {
        close(outfd);
        unlink(t->part_path);
        xrootd_cache_origin_close_file(&oc, fhandle);
        xrootd_cache_origin_close(&oc);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache part file fsync failed");
        return -1;
    }

    if (close(outfd) != 0) {
        unlink(t->part_path);
        xrootd_cache_origin_close_file(&oc, fhandle);
        xrootd_cache_origin_close(&oc);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache part file close failed");
        return -1;
    }
    outfd = -1;

    xrootd_cache_origin_close_file(&oc, fhandle);
    xrootd_cache_origin_close(&oc);

    return xrootd_cache_commit_part(t);
}

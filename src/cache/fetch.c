#include "cache_internal.h"
#include "meta.h"
#include "verify.h"
#include "origin/http_transport.h"
#include "origin/pelican.h"


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

/* xrootd_cache_commit_part — publish the downloaded part file: atomically rename
 * part_path → cache_path, write the .meta sidecar, and record the cached size on
 * the task. Shared by the anonymous-protocol and exec-GSI fills. Returns 0 / -1
 * (t error set). */
static int
xrootd_cache_commit_part(xrootd_cache_fill_t *t)
{
    struct stat                   st;
    xrootd_cache_meta_t           meta;
    ngx_log_t                    *log;
    xrootd_cache_digest_t         origin;
    xrootd_cache_verify_result_e  vr;
    char                          vy_alg[16];
    char                          vy_hex[129];

    log = (t->c != NULL) ? t->c->log : NULL;

    /*
     * Checksum-on-fill: verify the staged part against the origin's advertised
     * digest BEFORE the atomic rename, so a corrupted/truncated transfer never
     * becomes a served cache entry. Fail-closed best-effort by default
     * (xrootd_cache_verify). t->origin_cks_* is empty when the origin offered no
     * checksum (e.g. the GSI-exec fetch path) — the verify policy then governs.
     */
    ngx_memzero(&origin, sizeof(origin));
    if (t->origin_cks_alg[0] != '\0') {
        size_t an = ngx_min(ngx_strlen(t->origin_cks_alg), sizeof(origin.alg) - 1);
        size_t hn = ngx_min(ngx_strlen(t->origin_cks_hex), sizeof(origin.hex) - 1);
        ngx_memcpy(origin.alg, t->origin_cks_alg, an);
        ngx_memcpy(origin.hex, t->origin_cks_hex, hn);
    }

    vy_alg[0] = '\0';
    vy_hex[0] = '\0';
    vr = xrootd_cache_verify_part(t, t->part_path, &origin,
            (xrootd_cache_verify_mode_e) t->conf->cache_verify, vy_alg, vy_hex);
    if (vr == XROOTD_CACHE_VERIFY_MISMATCH || vr == XROOTD_CACHE_VERIFY_ERROR) {
        unlink(t->part_path);          /* t error already set by verify */
        return -1;
    }

    if (rename(t->part_path, t->cache_path) != 0) {
        unlink(t->part_path);
        xrootd_cache_set_syserror(t, kXR_IOError, "cache part file rename failed");
        return -1;
    }

    if (stat(t->cache_path, &st) == 0
        && xrootd_cache_meta_from_stat(&st, NULL, &meta) == NGX_OK)
    {
        t->file_size = (uint64_t) st.st_size;

        /* Record a verified digest into the sidecar for durable provenance. */
        if (vr == XROOTD_CACHE_VERIFY_VERIFIED && vy_alg[0] != '\0') {
            size_t an = ngx_min(ngx_strlen(vy_alg), sizeof(meta.cks_alg) - 1);
            size_t hn = ngx_min(ngx_strlen(vy_hex), sizeof(meta.cks_hex) - 1);
            meta.version     = XROOTD_CACHE_META_VERSION;
            meta.cks_alg_len = (uint8_t) an;
            ngx_memcpy(meta.cks_alg, vy_alg, an);
            meta.cks_alg[an] = '\0';
            meta.cks_len     = (uint8_t) hn;
            ngx_memcpy(meta.cks_hex, vy_hex, hn);
            meta.cks_hex[hn] = '\0';
        }

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

/* xrootd_cache_fetch_origin_exec — GSI/X.509-proxy origin fetch: fork/exec the
 * native client (cache_origin_client, default "xrdcp") to download into part_path
 * with X509_USER_PROXY + X509_CERT_DIR overridden, then xrootd_cache_commit_part().
 * The built-in client only does an anonymous kXR_login, which a GSI origin (e.g.
 * EOS) rejects; the native client speaks full GSI + open-redirect, so we reuse it
 * as the PSS. Runs in the fill worker (blocking), so posix_spawn + waitpid is fine. */
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

/* xrootd_cache_fetch_origin — the fill worker's anonymous-protocol fetch: connect →
 * bootstrap (handshake+login) → open source → read loop → fsync the .part → atomic
 * rename, each phase isolated with origin-close cleanup. Admission filtering runs
 * first: a file over cache_max_file_size that doesn't match the include regex is
 * rejected with NGX_DECLINED (1) — not an error — so the done callback redirects the
 * client to origin. Returns 1 (policy reject), -1 (error), 0 (success). */
int
xrootd_cache_fetch_origin(xrootd_cache_fill_t *t)
{
    xrootd_cache_origin_conn_t oc;
    u_char                    fhandle[XRD_FHANDLE_LEN];
    int                       outfd;
    uint64_t                  offset;

    outfd = -1;
    offset = 0;

    /* HTTP(S)/WebDAV origin: fetch over libcurl (http_transport.c) instead of the
     * XRootD wire client, then run the shared commit+verify path. */
    if (t->conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_HTTP
        || t->conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_HTTPS)
    {
        if (xrootd_cache_http_download(t) != 0) {
            return -1;
        }
        return xrootd_cache_commit_part(t);
    }

    /* Pelican federation: discover the Director, then fetch through it (libcurl
     * follows the 307 to the chosen cache/origin). Same commit+verify path. */
    if (t->conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_PELICAN) {
        if (xrootd_cache_pelican_download(t) != 0) {
            return -1;
        }
        return xrootd_cache_commit_part(t);
    }

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
        /* whole-file fetch: write base == read offset (absolute). */
        if (xrootd_cache_origin_read_chunk(t, &oc, fhandle, outfd, offset, offset,
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

    /*
     * Checksum-on-fill: while the origin connection is still open, ask it for the
     * file's content checksum (kXR_Qcksum) so commit can verify the bytes we just
     * downloaded before publishing them. Best-effort — an origin with no checksum
     * leaves t->origin_cks_* empty and the verify policy decides what that means.
     */
    if (t->conf->cache_verify != XROOTD_CACHE_VERIFY_OFF) {
        xrootd_cache_origin_query_checksum(t, &oc,
            t->origin_cks_alg, sizeof(t->origin_cks_alg),
            t->origin_cks_hex, sizeof(t->origin_cks_hex));
    }

    xrootd_cache_origin_close_file(&oc, fhandle);
    xrootd_cache_origin_close(&oc);

    return xrootd_cache_commit_part(t);
}

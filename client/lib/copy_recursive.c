/*
 * copy_recursive.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"


/* Create LPATH and every missing parent directory (local `mkdir -p`).
 *
 * WHY: the recursive download nests the copied tree under the destination
 * (recursive_dest_root → e.g. <dst>/<basename>), so the very first directory
 * created can be two levels below an existing parent (<dst> itself may not yet
 * exist).  A single mkdir() would fail with ENOENT on that missing parent; the
 * remote upload side already creates parents (brix_mkdir parents=1), so the
 * local side must match.  Idempotent: an existing component is not an error
 * (deeper failures such as a non-directory in the path still surface ENOTDIR).
 * Returns 0 on success, -1 with errno set on the first uncreatable component. */
static int
local_mkdirs(const char *lpath, mode_t mode)
{
    char   buf[XRDC_PATH_MAX];
    size_t n = strlen(lpath);
    size_t i;

    if (n == 0 || n >= sizeof(buf)) {
        errno = (n == 0) ? EINVAL : ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, lpath, n + 1);
    for (i = 1; i < n; i++) {                    /* each intermediate component */
        if (buf[i] != '/') {
            continue;
        }
        buf[i] = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST) {
            return -1;
        }
        buf[i] = '/';
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST) {  /* the leaf */
        return -1;
    }
    return 0;
}


/* Recurse a remote tree (rpath) under conn c into local lpath. */
int
copy_tree_download(brix_conn *c, const char *rpath, const char *lpath,
                   const brix_copy_opts *o, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;

    if (local_mkdirs(lpath, 0755) != 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "mkdir %s: %s", lpath, strerror(errno));
        return -1;
    }
    if (brix_dirlist(c, rpath, 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        char rc[XRDC_PATH_MAX], lc[XRDC_PATH_MAX];
        if (ents[i].name[0] == '.'
            && (ents[i].name[1] == '\0'
                || (ents[i].name[1] == '.' && ents[i].name[2] == '\0'))) {
            continue;
        }
        if ((size_t) snprintf(rc, sizeof(rc), "%s/%s", rpath, ents[i].name)
                >= sizeof(rc)
            || (size_t) snprintf(lc, sizeof(lc), "%s/%s", lpath, ents[i].name)
                >= sizeof(lc)) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: path too long under %s", rpath);
            free(ents);
            return -1;
        }
        if (ents[i].have_stat && (ents[i].st.flags & kXR_isDir)) {
            if (copy_tree_download(c, rc, lc, o, st) != 0) { free(ents); return -1; }
        } else {
            /* For a symlink (kXR_other) the dirlist size is the lstat size — the
             * LENGTH OF THE LINK TARGET PATH, not the bytes the server serves
             * when it follows the link on open.  Trusting it truncates the copy
             * (a link to a 10-byte file named "two.txt" would copy 7 bytes), so
             * read to EOF (expected = -1) for those; regular files keep their
             * real size, whose short-read guard still catches truncation. */
            int64_t expected = (ents[i].have_stat
                                && !(ents[i].st.flags & kXR_other))
                               ? ents[i].st.size : -1;
            if (copy_one_r2l(c, rc, lc, expected, st) != 0) {
                free(ents);
                return -1;
            }
        }
    }
    free(ents);
    return 0;
}


/* Recurse a local tree (lpath) into a remote tree (rpath) under conn c. */
int
copy_tree_upload(brix_conn *c, const char *lpath, const char *rpath,
                 const brix_copy_opts *o, brix_status *st)
{
    DIR           *d;
    struct dirent *de;
    brix_status    mst;

    brix_status_clear(&mst);
    (void) brix_mkdir(c, rpath, 0755, 1 /*parents*/, &mst);  /* may already exist */
    d = opendir(lpath);
    if (d == NULL) {
        brix_status_set(st, XRDC_ESOCK, errno, "opendir %s: %s", lpath, strerror(errno));
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        char        lc[XRDC_PATH_MAX], rc[XRDC_PATH_MAX];
        struct stat sb;
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
            continue;
        }
        if ((size_t) snprintf(lc, sizeof(lc), "%s/%s", lpath, de->d_name)
                >= sizeof(lc)
            || (size_t) snprintf(rc, sizeof(rc), "%s/%s", rpath, de->d_name)
                >= sizeof(rc)) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: path too long under %s", lpath);
            closedir(d);
            return -1;
        }
        /* lstat (not stat) so symlinks are detected, not followed — a link to a
         * parent directory would otherwise drive unbounded recursion. */
        if (lstat(lc, &sb) != 0) {
            continue;   /* vanished between readdir and stat — skip */
        }
        if (S_ISLNK(sb.st_mode)) {
            continue;   /* skip symlinks (loop-safe; mirrors official -r default) */
        }
        if (S_ISDIR(sb.st_mode)) {
            if (copy_tree_upload(c, lc, rc, o, st) != 0) { closedir(d); return -1; }
        } else if (S_ISREG(sb.st_mode)) {
            if (copy_one_l2r(c, lc, rc, o, st) != 0) { closedir(d); return -1; }
        }
    }
    closedir(d);
    return 0;
}


/* Build the recursive copy's destination root from the source path, using
 * rsync-style trailing-slash semantics:
 *
 *   src WITHOUT a trailing slash ("dir")  -> NEST the tree under the source's
 *       last path component: <dst>/<basename(dir)>/...  This matches stock
 *       `xrdcp -r <dir> <dst>` and avoids silently merging two differently-named
 *       source trees into one flattened destination.
 *   src WITH a trailing slash ("dir/")    -> FLAT mirror: copy the CONTENTS of
 *       the source straight into <dst>/... (no extra basename level), exactly as
 *       `rsync dir/ dst/` does.
 *
 * A degenerate basename ('.', '/', or empty — e.g. the whole-export `//.`/`//`
 * forms) has no meaningful name to nest under, so the destination is likewise
 * used verbatim.  Returns 0 on success, -1 if the composed path would overflow. */
int
recursive_dest_root(const char *dstdir, const char *srcpath,
                    char *out, size_t outsz)
{
    size_t      len = strlen(srcpath);
    const char *base;
    size_t      blen, dl, i;
    const char *sep;

    /* Trailing slash on the source => flat mirror (copy contents into <dst>). */
    if (len > 0 && srcpath[len - 1] == '/') {
        return ((size_t) snprintf(out, outsz, "%s", dstdir) >= outsz) ? -1 : 0;
    }

    base = srcpath;
    for (i = len; i > 0; i--) {
        if (srcpath[i - 1] == '/') { base = srcpath + i; break; }
    }
    blen = (size_t) (srcpath + len - base);

    if (blen == 0 || (blen == 1 && base[0] == '.')) {       /* nothing to nest */
        return ((size_t) snprintf(out, outsz, "%s", dstdir) >= outsz) ? -1 : 0;
    }
    dl  = strlen(dstdir);
    sep = (dl > 0 && dstdir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, outsz, "%s%s%.*s", dstdir, sep,
                              (int) blen, base) >= outsz) ? -1 : 0;
}


/* Recursive copy entry: connect once, walk the source tree. Direction-aware. */
int
copy_recursive(const brix_url *su, const brix_url *du, int download,
               const brix_copy_opts *o, const brix_opts *co, brix_status *st)
{
    brix_conn c;
    int       rc;
    char      destroot[XRDC_PATH_MAX];

    /* Nest under the source basename (stock parity); see recursive_dest_root. */
    if (recursive_dest_root(du->path, su->path, destroot, sizeof(destroot)) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy: destination path too long");
        return -1;
    }

    if (download) {
        if (brix_connect(&c, su, co, st) != 0) { return -1; }
        rc = copy_tree_download(&c, su->path, destroot, o, st);
    } else {
        if (brix_connect(&c, du, co, st) != 0) { return -1; }
        rc = copy_tree_upload(&c, su->path, destroot, o, st);
    }
    brix_close(&c);
    return rc;
}


/* web transfer (davs:// / http(s):// / s3://) — production GET/PUT over  */
/* the streaming HTTP client. Auth: WebDAV bearer token or S3 SigV4.      */


/* Build the auth header block for a web request into hdrs[] (may be empty for an
 * anonymous endpoint). S3 → SigV4 (host signed as "host:port" to match the Host
 * header we send); WebDAV/HTTP → Authorization: Bearer if a token is available.
 *
 * co carries the credential store (co->cred); when set the store is tried first
 * for both the bearer token and S3 keys, falling back to opts/env on failure so
 * env-sourced credentials behave identically to today. */
int
web_auth_headers(const brix_weburl *u, const char *method,
                 const brix_copy_opts *o, const brix_opts *co,
                 char *hdrs, size_t hdrsz, brix_status *st)
{
    hdrs[0] = '\0';
    if (u->is_s3) {
        const char *ak = (o && o->s3_access) ? o->s3_access : NULL;
        const char *sk = (o && o->s3_secret) ? o->s3_secret : NULL;
        const char *rg = (o && o->s3_region) ? o->s3_region : getenv("AWS_DEFAULT_REGION");
        brix_cred_view sv;
        char host[300], payhash[65];

        /* Prefer the cred store for S3 keys when no explicit opts override. */
        if ((ak == NULL || sk == NULL) && co != NULL && co->cred != NULL) {
            if (brix_cred_acquire(co->cred, XRDC_CRED_S3KEYS, 0, &sv, st) == 0) {
                if (ak == NULL) { ak = sv.s3_access; }
                if (sk == NULL) { sk = sv.s3_secret; }
            } else {
                brix_status_clear(st);
            }
        }
        /* Fall through to env when store not set or acquire failed. */
        if (ak == NULL) { ak = getenv("AWS_ACCESS_KEY_ID"); }
        if (sk == NULL) { sk = getenv("AWS_SECRET_ACCESS_KEY"); }

        if (ak == NULL || sk == NULL) {
            return 0;   /* anonymous — server may permit unsigned access */
        }
        if (rg == NULL) { rg = "us-east-1"; }
        /* A '?' would split path vs query in the server's canonical request but
         * we sign the whole path as CanonicalURI — reject rather than mis-sign. */
        if (strchr(u->path, '?') != NULL) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "s3: query strings in the URL are not supported");
            return -1;
        }
        /* The SigV4 signed host MUST match the wire Host header byte-for-byte; that
         * header brackets IPv6 literals ([::1]:9000), so sign the same form. */
        brix_format_host_port(u->host, (uint16_t) u->port, host, sizeof(host));
        /* UNSIGNED-PAYLOAD for every method: the body isn't folded into the
         * signature (it streams), which both nginx-xrootd's S3 and real AWS accept. */
        snprintf(payhash, sizeof(payhash), "UNSIGNED-PAYLOAD");
        if (brix_s3_sign_v4(method, host, u->path, ak, sk, rg, payhash,
                            hdrs, hdrsz) != 0) {
            brix_status_set(st, XRDC_EAUTH, 0, "s3: failed to build SigV4 signature");
            return -1;
        }
        return 0;
    }
    {
        const char *tok = (o && o->bearer) ? o->bearer : NULL;
        brix_cred_view bv;

        /* Prefer the cred store for the bearer token when no explicit opt override. */
        if (tok == NULL && co != NULL && co->cred != NULL) {
            if (brix_cred_acquire(co->cred, XRDC_CRED_BEARER, 0, &bv, st) == 0
                && bv.token != NULL) {
                tok = bv.token;
            } else {
                brix_status_clear(st);
            }
        }
        /* Fall through to env when store not set or acquire failed. */
        if (tok == NULL) { tok = getenv("BEARER_TOKEN"); }

        if (tok != NULL && tok[0] != '\0') {
            int n = snprintf(hdrs, hdrsz, "Authorization: Bearer %s\r\n", tok);
            if (n < 0 || (size_t) n >= hdrsz) {
                brix_status_set(st, XRDC_EUSAGE, 0, "bearer token too long");
                return -1;
            }
        }
    }
    return 0;
}


int
copy_web_download(const brix_weburl *su, const brix_url *du, int to_stdout,
                  const brix_copy_opts *o, const brix_opts *co, brix_status *st)
{
    char      hdrs[8192];
    char      tmp[XRDC_PATH_MAX];
    int       outfd, status = 0, rc;
    long long blen = 0;

    if (web_auth_headers(su, "GET", o, co, hdrs, sizeof(hdrs), st) != 0) {
        return -1;
    }
    if (to_stdout) {
        rc = brix_http_download(su->host, su->port, su->tls, su->path,
                                hdrs[0] ? hdrs : NULL, co ? co->verify_host : 1,
                                co ? co->ca_dir : NULL, STDOUT_FILENO,
                                XRDC_WEB_TIMEOUT_MS, &status, &blen, st);
        return rc;
    }
    /* Refuse to overwrite an existing destination unless -f. */
    if (!(o && o->force) && access(du->path, F_OK) == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s", du->path);
        return -1;
    }
    /* Download to a temp sibling and atomically rename on success: a failed
     * transfer must never truncate or delete a pre-existing destination. */
    outfd = open_download_temp(du->path, tmp, sizeof(tmp), st);
    if (outfd < 0) {
        return -1;
    }
    rc = brix_http_download(su->host, su->port, su->tls, su->path,
                            hdrs[0] ? hdrs : NULL, co ? co->verify_host : 1,
                            co ? co->ca_dir : NULL, outfd, XRDC_WEB_TIMEOUT_MS,
                            &status, &blen, st);
    close(outfd);
    rc = atomic_dest_finish(tmp, du->path, rc, st);
    if (rc != 0) {
        return rc;
    }
    if (o && !o->silent) {
        fprintf(stderr, "xrdcp: downloaded %lld bytes (HTTP %d)\n", blen, status);
    }
    return 0;
}

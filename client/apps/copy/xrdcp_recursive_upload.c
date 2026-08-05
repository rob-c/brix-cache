/*
 * xrdcp_recursive_upload.c - recursive local->remote (WebDAV) directory upload.
 * Phase-38 split of xrdcp_recursive.c; behavior-identical. The download/place
 * half stays in xrdcp_recursive.c; both share apps/copy/xrdcp_internal.h.
 */
#include "xrdcp_internal.h"

/* Shared state for one recursive web-upload walk (local tree → web collection).
 * `base` is the dst URL's path with trailing slashes trimmed ("" for the root);
 * the bucket/collection root, into which the source directory's CONTENTS go
 * (symmetric with recursive download). */

/* Build "<base>/<rel>" (or "/<rel>" when base is the root "") into out.
 * 0 on success, -1 if it would not fit. */
int
web_join(const char *base, const char *rel, char *out, size_t outsz)
{
    int w = snprintf(out, outsz, "%s/%s", base, rel);
    return (w < 0 || (size_t) w >= outsz) ? -1 : 0;
}


/* WHAT: one directory entry's local path + upload-root-relative path.
 * WHY: every walk step derives this pair once and threads it through the
 * dir/file handlers; a struct keeps those helpers under the parameter cap.
 * HOW: filled by walk_child_paths on the walk frame's stack (same footprint
 * as the two buffers the walk loop previously held). */
typedef struct {
    char local[XRDC_PATH_MAX];   /* localdir/<name> */
    char rel[XRDC_PATH_MAX];     /* path relative to the upload root */
} walk_child_t;


/* WHAT: build a directory entry's local and root-relative paths.
 * WHY: isolates the overflow-guarded path joins (with the "" top-of-tree rel
 * special case) from the walk's classify/dispatch loop.
 * HOW: snprintf both joins with truncation checks. 0 on success, -1 if either
 * would not fit (caller reports and skips the entry). */
static int
walk_child_paths(const char *localdir, const char *rel, const char *name,
                 walk_child_t *out)
{
    if ((size_t) snprintf(out->local, sizeof(out->local), "%s/%s",
                          localdir, name) >= sizeof(out->local)) {
        return -1;
    }
    if (rel[0] == '\0') {
        if ((size_t) snprintf(out->rel, sizeof(out->rel), "%s", name)
                >= sizeof(out->rel)) {
            return -1;
        }
        return 0;
    }
    if ((size_t) snprintf(out->rel, sizeof(out->rel), "%s/%s", rel, name)
            >= sizeof(out->rel)) {
        return -1;
    }
    return 0;
}


/* WHAT: handle one subdirectory during the upload walk: MKCOL it, then recurse.
 * WHY: creating the remote collection top-down before descending keeps the
 * child PUTs/MKCOLs from hitting 409 Conflict; S3 has no real dirs.
 * HOW: MKCOL <base>/<rel> (davs/http only; skipped under --dry-run, which
 * still recurses so files get printed); on MKCOL failure the subtree is
 * skipped — its files would 409 — and `fail` is bumped. */
static void
walk_handle_dir(web_upload_ctx *c, const walk_child_t *ch)
{
    if (!c->u->is_s3 && (c->fo == NULL || !c->fo->dry_run)) {
        char        rpath[XRDC_PATH_MAX * 2];
        brix_status mst;
        char        proxybuf[512];
        const char *pcert = brix_web_proxy_pem(proxybuf, sizeof(proxybuf));

        brix_status_clear(&mst);
        if (web_join(c->base, ch->rel, rpath, sizeof(rpath)) != 0
            || brix_webdav_mkcol(c->u, rpath, c->bearer,
                                 c->co ? c->co->verify_host : 1,
                                 c->co ? c->co->ca_dir : NULL, pcert, &mst) != 0) {
            fprintf(stderr, "xrdcp: mkcol %s: %s\n", ch->rel, mst.msg);
            c->fail++;
            return;   /* skip this subtree — its files would 409 */
        }
    }
    web_upload_walk(c, ch->local, ch->rel);
}


/* WHAT: handle one regular file during the upload walk: filter, then PUT.
 * WHY: keeps the per-file filter/dry-run/URL-build/transfer/accounting chain
 * out of the walk's directory-scan loop.
 * HOW: apply --exclude/--include and --dry-run before any I/O; build the
 * remote URL (overflow-guarded); PUT via copy_one_with_retry; bump `ok`
 * (progress line unless silent) or `fail` (error line). */
static void
walk_handle_file(web_upload_ctx *c, const walk_child_t *ch)
{
    char        rurl[XRDC_PATH_MAX * 2 + 320];
    char        rpath[XRDC_PATH_MAX * 2];
    brix_status cst;

    if (c->fo != NULL && !brix_copy_filter_match(c->fo, ch->rel)) {
        return;   /* filtered — skip, not a failure */
    }
    if (web_join(c->base, ch->rel, rpath, sizeof(rpath)) != 0
        || (size_t) snprintf(rurl, sizeof(rurl), "%s://%s:%d%s",
                             c->scheme, c->u->host, c->u->port, rpath)
               >= sizeof(rurl)) {
        fprintf(stderr, "xrdcp: remote path too long for %s\n", ch->rel);
        c->fail++;
        return;
    }
    if (c->fo != NULL && c->fo->dry_run) {
        printf("[dry-run] copy %s -> %s\n", ch->local, rurl);
        c->ok++;
        return;
    }
    brix_status_clear(&cst);
    if (copy_one_with_retry(ch->local, rurl, c->fo, c->co, c->retries,
                            &cst) == 0) {
        c->ok++;
        if (c->fo == NULL || !c->fo->silent) {
            fprintf(stderr, "[%zu] %s -> %s\n", c->ok + c->fail,
                    ch->local, rurl);
        }
    } else {
        c->fail++;
        fprintf(stderr, "xrdcp: %s: %s\n", rurl, cst.msg);
    }
}


/* Recursively walk a local directory, MKCOL'ing each WebDAV collection (davs/http
 * only — S3 keys are flat) and PUT'ing each regular file. `rel` is the path of the
 * current directory relative to the upload root ("" at the top). Symlinks and
 * special files are skipped (only real dirs + regular files are uploaded). */
void
web_upload_walk(web_upload_ctx *c, const char *localdir, const char *rel)
{
    DIR           *d = opendir(localdir);
    struct dirent *de;

    if (d == NULL) {
        fprintf(stderr, "xrdcp: cannot open %s: %s\n", localdir, strerror(errno));
        c->fail++;
        return;
    }
    while ((de = readdir(d)) != NULL) {
        walk_child_t ch;
        struct stat  sb;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        if (walk_child_paths(localdir, rel, de->d_name, &ch) != 0) {
            fprintf(stderr, "xrdcp: path too long under %s\n", localdir);
            c->fail++;
            continue;
        }
        if (lstat(ch.local, &sb) != 0) {
            fprintf(stderr, "xrdcp: stat %s: %s\n", ch.local, strerror(errno));
            c->fail++;
            continue;
        }
        if (S_ISDIR(sb.st_mode)) {
            walk_handle_dir(c, &ch);
        } else if (S_ISREG(sb.st_mode)) {
            walk_handle_file(c, &ch);
        }
        /* else: symlink / fifo / device — skip (not uploaded) */
    }
    closedir(d);
}


/* Recursively upload a local directory's CONTENTS into a web (davs/http/s3)
 * collection: `xrdcp -r ./dir davs://h/coll/` → coll/<files-under-dir>. The wire
 * has no recursive transfer op, so walk locally + MKCOL + per-file PUT. Returns
 * 0 if every file uploaded, 1 otherwise. */
int
recursive_web_upload(const char *localdir, const char *dst, const brix_copy_opts *o,
                     const brix_opts *co, int retries)
{
    brix_weburl     u;
    brix_copy_opts  fo;
    char            base[XRDC_PATH_MAX];
    web_upload_ctx  c;
    size_t          blen;

    if (brix_weburl_parse(dst, &u) != 0) {
        fprintf(stderr, "xrdcp: bad web URL %s\n", dst);
        return 1;
    }
    /* Each file is a plain (non-recursive) copy so brix_copy's "no recursive web"
     * guard doesn't trip. */
    fo = *o;
    fo.recursive = 0;

    snprintf(base, sizeof(base), "%s", u.path);
    blen = strlen(base);
    while (blen > 0 && base[blen - 1] == '/') { base[--blen] = '\0'; }

    c.u       = &u;
    c.base    = base;
    c.scheme  = web_scheme_str(u.proto);
    c.bearer  = (o != NULL && o->bearer != NULL) ? o->bearer : getenv("BEARER_TOKEN");
    c.fo      = &fo;
    c.co      = co;
    c.retries = retries;
    c.ok      = 0;
    c.fail    = 0;

    /* Ensure the destination collection itself exists (idempotent). Root ("")
     * and S3 buckets need no MKCOL. Under --dry-run, skip to avoid creating
     * the base collection on the remote. */
    if (!u.is_s3 && base[0] != '\0' && !fo.dry_run) {
        brix_status mst;
        char        proxybuf[512];
        const char *pcert = brix_web_proxy_pem(proxybuf, sizeof(proxybuf));
        brix_status_clear(&mst);
        if (brix_webdav_mkcol(&u, base, c.bearer, co ? co->verify_host : 1,
                              co ? co->ca_dir : NULL, pcert, &mst) != 0) {
            fprintf(stderr, "xrdcp: mkcol %s: %s\n", base, mst.msg);
            /* proceed anyway — PUTs will surface any real problem */
        }
    }

    web_upload_walk(&c, localdir, "");
    if (o == NULL || !o->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu failed (recursive web upload)\n",
                c.ok, c.fail);
    }
    return (c.fail == 0) ? 0 : 1;
}



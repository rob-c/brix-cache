/*
 * xrdcp_recursive.c - extracted concern
 * Phase-38 split of xrdcp.c; behavior-identical.
 */
#include "xrdcp_internal.h"


/* Expand one source into `out`: a root:// glob via brix_glob, a local glob via
 * glob(3), otherwise the literal. Returns 0; -1 only on a hard (alloc) failure.
 * A glob that matches nothing appends nothing and warns. */
/* Like brix_has_glob, but a '?' that introduces an opaque section
 * (root://...?key=val, e.g. ?xrdcl.unzip=member) is the opaque separator, not a
 * wildcard — so only the path before it is considered for globbing. */
int
source_has_glob(const char *s)
{
    const char *q = strchr(s, '?');

    if (q != NULL && strchr(q, '=') != NULL) {
        size_t plen = (size_t) (q - s), i;
        for (i = 0; i < plen; i++) {
            if (s[i] == '*' || s[i] == '[' || s[i] == '?') {
                return 1;
            }
        }
        return 0;
    }
    return brix_has_glob(s);
}


int
expand_source(const char *s_in, const brix_opts *co, char ***out, size_t *n, size_t *cap)
{
    char        rs[XRDC_PATH_MAX];
    const char *s;
    brix_alias_resolve(s_in, rs, sizeof(rs));   /* ~/.xrdrc: name:suffix -> URL */
    s = rs;
    if (!source_has_glob(s)) {
        return str_append(out, n, cap, s);
    }
    if (brix_is_web_url(s)) {
        return str_append(out, n, cap, s);   /* web globbing not supported; literal */
    }
    if (is_root_url(s)) {
        char      **m = NULL;
        size_t      nm = 0, i;
        brix_status st;
        brix_status_clear(&st);
        if (brix_glob(s, co, &m, &nm, &st) < 0) {
            if (st.kxr == XRDC_EUSAGE) {
                return str_append(out, n, cap, s);   /* genuinely not a glob → literal */
            }
            /* Hard failure (connect/dirlist/auth): surface it; don't silently fall
             * back to copying the literal '*' pattern as a filename. */
            fprintf(stderr, "xrdcp: glob %s: %s\n", s, st.msg);
            return 0;
        }
        if (nm == 0) {
            fprintf(stderr, "xrdcp: no matches for %s\n", s);
        }
        for (i = 0; i < nm; i++) {
            if (str_append(out, n, cap, m[i]) != 0) { brix_glob_free(m, nm); return -1; }
        }
        brix_glob_free(m, nm);
        return 0;
    }
    {
        glob_t g;
        int    rc = glob(s, 0, NULL, &g);
        if (rc == 0) {
            size_t i;
            for (i = 0; i < g.gl_pathc; i++) {
                if (str_append(out, n, cap, g.gl_pathv[i]) != 0) { globfree(&g); return -1; }
            }
            globfree(&g);
            return 0;
        }
        globfree(&g);
        fprintf(stderr, "xrdcp: no matches for %s\n", s);
        return 0;
    }
}


/* mkdir -p of the directory component of `filepath` (errors other than EEXIST are
 * left for the subsequent open to report). */
void
mkdirs_for(const char *filepath)
{
    char  tmp[XRDC_PATH_MAX];
    char *slash, *p;
    snprintf(tmp, sizeof(tmp), "%s", filepath);
    slash = strrchr(tmp, '/');
    if (slash == NULL || slash == tmp) {
        return;
    }
    *slash = '\0';
    for (p = tmp + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            (void) mkdir(tmp, 0755);
            *p = '/';
        }
    }
    (void) mkdir(tmp, 0755);
}


/* MKCOL each ancestor collection of `rel` under `base` on web endpoint `du`
 * (davs/http only; S3 keys are flat → no-op). Idempotent, created top-down so a
 * deeper PUT never hits 409. 0 / -1 (st set). */
int
mkcol_parents(const brix_weburl *du, const char *base, const char *rel,
              const char *bearer, const brix_opts *co, brix_status *st)
{
    char        acc[XRDC_PATH_MAX * 2];
    const char *slash;
    size_t      blen;

    if (du->is_s3) { return 0; }
    blen = (size_t) snprintf(acc, sizeof(acc), "%s", base);
    if (blen >= sizeof(acc)) { return -1; }
    for (slash = strchr(rel, '/'); slash != NULL; slash = strchr(slash + 1, '/')) {
        int w = snprintf(acc + blen, sizeof(acc) - blen, "/%.*s",
                         (int) (slash - rel), rel);
        if (w < 0 || blen + (size_t) w >= sizeof(acc)) { return -1; }
        if (brix_webdav_mkcol(du, acc, bearer, co ? co->verify_host : 1,
                              co ? co->ca_dir : NULL, st) != 0) {
            return -1;
        }
    }
    return 0;
}


/* Place one recursively-listed source file `srcurl` at `rel` under `dstroot`,
 * which may be a LOCAL directory (mkdir -p + copy) or a WEB collection (MKCOL the
 * parent collections + a web->web relay via copy_one_with_retry). Centralising the
 * destination side lets both the WebDAV and S3 recursive sources copy to a local
 * tree OR another web endpoint (web->web). 0 / -1 (st set).
 *
 * Filter and dry-run are applied here — before any I/O — so they cover all
 * recursive sources (WebDAV, S3). A filtered or dry-run item returns 0 (handled,
 * not a failure) so the caller counts it in `ok`, not `fail`. */
int
recursive_place(const char *dstroot, const char *rel, const char *srcurl,
                const brix_copy_opts *fo, const brix_opts *co, int retries,
                brix_status *st)
{
    if (fo != NULL && !brix_copy_filter_match(fo, rel)) {
        return 0;   /* filtered — not an error, skip silently */
    }
    if (fo != NULL && fo->dry_run) {
        printf("[dry-run] copy %s -> %s/%s\n", srcurl, dstroot, rel);
        return 0;
    }
    if (brix_is_web_url(dstroot)) {
        brix_weburl du;
        char        dbase[XRDC_PATH_MAX], dsturl[XRDC_PATH_MAX * 2 + 320];
        const char *dbearer;
        size_t      blen;
        if (brix_weburl_parse(dstroot, &du) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "bad web dst URL %s", dstroot);
            return -1;
        }
        snprintf(dbase, sizeof(dbase), "%s", du.path);
        blen = strlen(dbase);
        while (blen > 0 && dbase[blen - 1] == '/') { dbase[--blen] = '\0'; }
        dbearer = (fo != NULL && fo->bearer != NULL) ? fo->bearer
                                                     : getenv("BEARER_TOKEN");
        if (mkcol_parents(&du, dbase, rel, dbearer, co, st) != 0) {
            return -1;
        }
        if ((size_t) snprintf(dsturl, sizeof(dsturl), "%s://%s:%d%s/%s",
                              web_scheme_str(du.proto), du.host, du.port, dbase, rel)
                >= sizeof(dsturl)) {
            brix_status_set(st, XRDC_EUSAGE, 0, "web->web dst path too long");
            return -1;
        }
        return copy_one_with_retry(srcurl, dsturl, fo, co, retries, st);
    } else {
        char dstfile[XRDC_PATH_MAX];
        if ((size_t) snprintf(dstfile, sizeof(dstfile), "%s/%s", dstroot, rel)
                >= sizeof(dstfile)) {
            brix_status_set(st, XRDC_EUSAGE, 0, "dst path too long");
            return -1;
        }
        mkdirs_for(dstfile);
        return copy_one_with_retry(srcurl, dstfile, fo, co, retries, st);
    }
}


/* For a recursive copy whose destination is a web COLLECTION, MKCOL the base
 * collection once (idempotent) so the first per-file PUT doesn't 409. No-op for a
 * local destination or an S3 bucket (flat keys need no collections). */
void
ensure_web_dst_base(const char *dstroot, const brix_copy_opts *fo,
                    const brix_opts *co)
{
    brix_weburl  du;
    char         dbase[XRDC_PATH_MAX];
    const char  *dbearer;
    size_t       blen;
    brix_status  st;

    if (!brix_is_web_url(dstroot) || brix_weburl_parse(dstroot, &du) != 0
        || du.is_s3) {
        return;
    }
    snprintf(dbase, sizeof(dbase), "%s", du.path);
    blen = strlen(dbase);
    while (blen > 0 && dbase[blen - 1] == '/') { dbase[--blen] = '\0'; }
    if (dbase[0] == '\0') { return; }   /* root collection needs no MKCOL */
    dbearer = (fo != NULL && fo->bearer != NULL) ? fo->bearer
                                                 : getenv("BEARER_TOKEN");
    brix_status_clear(&st);
    (void) brix_webdav_mkcol(&du, dbase, dbearer, co ? co->verify_host : 1,
                             co ? co->ca_dir : NULL, &st);   /* best-effort */
}


/* Recursively download an s3:// prefix into dstdir: ListObjectsV2 (paginated,
 * SigV4-signed) then copy each key to dstdir/<key-minus-prefix>, preserving the
 * tree. `fo` is a non-recursive opts copy carrying the S3 creds. Returns 0/1. */
int
recursive_s3_download(const brix_weburl *u, const char *dstdir,
                      const brix_copy_opts *fo, const brix_opts *co, int retries)
{
    brix_status st;
    char      **keys = NULL;
    char        bucket[256], prefix[XRDC_PATH_MAX];
    const char *ak, *sk, *region, *scheme, *bsl;
    size_t      n = 0, i, plen, ok = 0, fail = 0;

    brix_status_clear(&st);
    ak     = fo->s3_access ? fo->s3_access : getenv("AWS_ACCESS_KEY_ID");
    sk     = fo->s3_secret ? fo->s3_secret : getenv("AWS_SECRET_ACCESS_KEY");
    region = fo->s3_region ? fo->s3_region : getenv("AWS_DEFAULT_REGION");
    if (brix_s3_list(u, ak, sk, region, co ? co->verify_host : 1,
                     co ? co->ca_dir : NULL, &keys, &n, &st) != 0) {
        fprintf(stderr, "xrdcp: s3 list: %s\n", st.msg);
        return 1;
    }
    /* split u->path "/bucket[/prefix]" into bucket + prefix (no trailing slash).
     * One guarded memcpy for the bucket covers both the no-slash and prefix cases
     * (brix_s3_list already validated the same split, but stay defensive). */
    bsl = strchr(u->path + 1, '/');
    {
        size_t bl = bsl ? (size_t) (bsl - (u->path + 1)) : strlen(u->path + 1);
        if (bl >= sizeof(bucket)) {
            fprintf(stderr, "xrdcp: s3 bucket name too long\n");
            brix_strv_free(keys, n);
            return 1;
        }
        memcpy(bucket, u->path + 1, bl);
        bucket[bl] = '\0';
        if (bsl != NULL) {
            snprintf(prefix, sizeof(prefix), "%s", bsl + 1);
        } else {
            prefix[0] = '\0';
        }
    }
    plen = strlen(prefix);
    while (plen > 0 && prefix[plen - 1] == '/') { prefix[--plen] = '\0'; }
    scheme = web_scheme_str(u->proto);
    ensure_web_dst_base(dstdir, fo, co);   /* s3->web: create the dst collection */

    for (i = 0; i < n; i++) {
        const char *key = keys[i];
        const char *rel;
        char        relbuf[XRDC_NAME_MAX];
        char        srcurl[XRDC_PATH_MAX + 320];
        brix_status cst;

        if (plen == 0) {
            rel = key;
        } else if (strncmp(key, prefix, plen) == 0 && (key[plen] == '/' || key[plen] == '\0')) {
            rel = key + plen + (key[plen] == '/' ? 1 : 0);
        } else {
            path_basename(key, relbuf, sizeof(relbuf));   /* fallback: flatten */
            rel = relbuf;
        }
        if (*rel == '\0') {
            continue;
        }
        if (rel_is_unsafe(rel)) {
            fprintf(stderr, "xrdcp: refusing unsafe key from server: %s\n", key);
            fail++;
            continue;
        }
        if ((size_t) snprintf(srcurl, sizeof(srcurl), "%s://%s:%d/%s/%s",
                              scheme, u->host, u->port, bucket, key) >= sizeof(srcurl)) {
            fail++;
            continue;
        }
        /* dstdir may be a local dir OR a web collection (recursive s3->web). */
        brix_status_clear(&cst);
        if (recursive_place(dstdir, rel, srcurl, fo, co, retries, &cst) == 0) {
            ok++;
            if (!fo->silent) {
                fprintf(stderr, "[%zu/%zu] %s -> %s/%s\n", ok + fail, n, srcurl, dstdir, rel);
            }
        } else {
            fail++;
            fprintf(stderr, "xrdcp: %s: %s\n", srcurl, cst.msg);
        }
    }
    brix_strv_free(keys, n);
    if (!fo->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu failed (recursive s3)\n", ok, fail);
    }
    return (fail == 0) ? 0 : 1;
}


int
recursive_web_download(const char *src, const char *dstdir, const brix_copy_opts *o,
                       const brix_opts *co, int retries)
{
    brix_weburl    u;
    brix_status    st;
    brix_copy_opts fo;
    char         **paths = NULL;
    char           prefix[XRDC_PATH_MAX];
    const char    *bearer, *scheme;
    size_t         n = 0, i, plen, ok = 0, fail = 0;

    /* Each listed file is a plain (non-recursive) copy; clear the -r flag so the
     * per-file brix_copy doesn't bounce off the "no recursive web" guard. */
    fo = *o;
    fo.recursive = 0;
    brix_status_clear(&st);
    if (brix_weburl_parse(src, &u) != 0) {
        fprintf(stderr, "xrdcp: bad web URL %s\n", src);
        return 1;
    }
    if (u.is_s3) {
        return recursive_s3_download(&u, dstdir, &fo, co, retries);
    }
    bearer = (o != NULL && o->bearer != NULL) ? o->bearer : getenv("BEARER_TOKEN");
    if (brix_webdav_list(&u, bearer, co ? co->verify_host : 1,
                         co ? co->ca_dir : NULL, &paths, &n, &st) != 0) {
        fprintf(stderr, "xrdcp: list %s: %s\n", src, st.msg);
        return 1;
    }
    snprintf(prefix, sizeof(prefix), "%s", u.path);
    plen = strlen(prefix);
    while (plen > 1 && prefix[plen - 1] == '/') { prefix[--plen] = '\0'; }
    scheme = web_scheme_str(u.proto);
    ensure_web_dst_base(dstdir, &fo, co);   /* web->web: create the dst collection */

    for (i = 0; i < n; i++) {
        const char *path = paths[i];
        const char *rel;
        char        relbuf[XRDC_NAME_MAX];
        char        srcurl[XRDC_PATH_MAX + 320];
        brix_status cst;

        if (strncmp(path, prefix, plen) == 0 && (path[plen] == '/' || path[plen] == '\0')) {
            rel = path + plen + (path[plen] == '/' ? 1 : 0);
        } else {
            path_basename(path, relbuf, sizeof(relbuf));   /* fallback: flatten */
            rel = relbuf;
        }
        if (*rel == '\0') {
            continue;
        }
        /* Security: a hostile server must not traverse out of dstdir via the href. */
        if (rel_is_unsafe(rel)) {
            fprintf(stderr, "xrdcp: refusing unsafe path from server: %s\n", path);
            fail++;
            continue;
        }
        if ((size_t) snprintf(srcurl, sizeof(srcurl), "%s://%s:%d%s",
                              scheme, u.host, u.port, path) >= sizeof(srcurl)) {
            fail++;
            continue;
        }
        /* dstdir may be a local dir OR a web collection (recursive web->web). */
        brix_status_clear(&cst);
        if (recursive_place(dstdir, rel, srcurl, &fo, co, retries, &cst) == 0) {
            ok++;
            if (o == NULL || !o->silent) {
                fprintf(stderr, "[%zu/%zu] %s -> %s/%s\n", ok + fail, n, srcurl, dstdir, rel);
            }
        } else {
            fail++;
            fprintf(stderr, "xrdcp: %s: %s\n", srcurl, cst.msg);
        }
    }
    brix_strv_free(paths, n);
    if (o == NULL || !o->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu failed (recursive web)\n", ok, fail);
    }
    return (fail == 0) ? 0 : 1;
}


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
        char        childlocal[XRDC_PATH_MAX];
        char        childrel[XRDC_PATH_MAX];
        struct stat sb;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        if ((size_t) snprintf(childlocal, sizeof(childlocal), "%s/%s",
                              localdir, de->d_name) >= sizeof(childlocal)
            || (rel[0] == '\0'
                    ? (size_t) snprintf(childrel, sizeof(childrel), "%s", de->d_name)
                    : (size_t) snprintf(childrel, sizeof(childrel), "%s/%s",
                                        rel, de->d_name)) >= sizeof(childrel)) {
            fprintf(stderr, "xrdcp: path too long under %s\n", localdir);
            c->fail++;
            continue;
        }
        if (lstat(childlocal, &sb) != 0) {
            fprintf(stderr, "xrdcp: stat %s: %s\n", childlocal, strerror(errno));
            c->fail++;
            continue;
        }
        if (S_ISDIR(sb.st_mode)) {
            /* Create the remote collection (top-down) before descending so the
             * child PUTs/MKCOLs don't hit 409 Conflict. S3 has no real dirs. */
            if (!c->u->is_s3) {
                char        rpath[XRDC_PATH_MAX * 2];
                brix_status mst;
                brix_status_clear(&mst);
                if (web_join(c->base, childrel, rpath, sizeof(rpath)) != 0
                    || brix_webdav_mkcol(c->u, rpath, c->bearer,
                                         c->co ? c->co->verify_host : 1,
                                         c->co ? c->co->ca_dir : NULL, &mst) != 0) {
                    fprintf(stderr, "xrdcp: mkcol %s: %s\n", childrel, mst.msg);
                    c->fail++;
                    continue;   /* skip this subtree — its files would 409 */
                }
            }
            web_upload_walk(c, childlocal, childrel);
        } else if (S_ISREG(sb.st_mode)) {
            char        rurl[XRDC_PATH_MAX * 2 + 320];
            char        rpath[XRDC_PATH_MAX * 2];
            brix_status cst;
            /* Apply --exclude/--include and --dry-run before any I/O. */
            if (c->fo != NULL && !brix_copy_filter_match(c->fo, childrel)) {
                continue;   /* filtered — skip, not a failure */
            }
            if (web_join(c->base, childrel, rpath, sizeof(rpath)) != 0
                || (size_t) snprintf(rurl, sizeof(rurl), "%s://%s:%d%s",
                                     c->scheme, c->u->host, c->u->port, rpath)
                       >= sizeof(rurl)) {
                fprintf(stderr, "xrdcp: remote path too long for %s\n", childrel);
                c->fail++;
                continue;
            }
            if (c->fo != NULL && c->fo->dry_run) {
                printf("[dry-run] copy %s -> %s\n", childlocal, rurl);
                c->ok++;
                continue;
            }
            brix_status_clear(&cst);
            if (copy_one_with_retry(childlocal, rurl, c->fo, c->co, c->retries,
                                    &cst) == 0) {
                c->ok++;
                if (c->fo == NULL || !c->fo->silent) {
                    fprintf(stderr, "[%zu] %s -> %s\n", c->ok + c->fail,
                            childlocal, rurl);
                }
            } else {
                c->fail++;
                fprintf(stderr, "xrdcp: %s: %s\n", rurl, cst.msg);
            }
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
     * and S3 buckets need no MKCOL. */
    if (!u.is_s3 && base[0] != '\0') {
        brix_status mst;
        brix_status_clear(&mst);
        if (brix_webdav_mkcol(&u, base, c.bearer, co ? co->verify_host : 1,
                              co ? co->ca_dir : NULL, &mst) != 0) {
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

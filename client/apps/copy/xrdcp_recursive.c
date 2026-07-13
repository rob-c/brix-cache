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


/* MKCOL each ancestor collection of `rel` under m->base on web endpoint m->du
 * (davs/http only; S3 keys are flat → no-op). Idempotent, created top-down so a
 * deeper PUT never hits 409. 0 / -1 (st set). */
int
mkcol_parents(const mkcol_ctx_t *m, const char *rel, brix_status *st)
{
    char        acc[XRDC_PATH_MAX * 2];
    const char *slash;
    size_t      blen;

    if (m->du->is_s3) { return 0; }
    blen = (size_t) snprintf(acc, sizeof(acc), "%s", m->base);
    if (blen >= sizeof(acc)) { return -1; }
    for (slash = strchr(rel, '/'); slash != NULL; slash = strchr(slash + 1, '/')) {
        int w = snprintf(acc + blen, sizeof(acc) - blen, "/%.*s",
                         (int) (slash - rel), rel);
        if (w < 0 || blen + (size_t) w >= sizeof(acc)) { return -1; }
        if (brix_webdav_mkcol(m->du, acc, m->bearer,
                              m->co ? m->co->verify_host : 1,
                              m->co ? m->co->ca_dir : NULL, st) != 0) {
            return -1;
        }
    }
    return 0;
}


/* WHAT: place one file at `rel` under a WEB collection root `dstroot`.
 * WHY: the web destination needs URL parsing, base-path trimming, and top-down
 * MKCOL of parent collections before the relay copy — a distinct concern from
 * the local-directory case.
 * HOW: parse dstroot, trim trailing slashes off its path, MKCOL each ancestor
 * of `rel` (davs/http only), then relay via copy_one_with_retry. 0 / -1 (st set). */
static int
place_to_web(const char *dstroot, const place_ctx_t *p)
{
    brix_weburl du;
    char        dbase[XRDC_PATH_MAX], dsturl[XRDC_PATH_MAX * 2 + 320];
    const char *dbearer;
    size_t      blen;

    if (brix_weburl_parse(dstroot, &du) != 0) {
        brix_status_set(p->st, XRDC_EUSAGE, 0, "bad web dst URL %s", dstroot);
        return -1;
    }
    snprintf(dbase, sizeof(dbase), "%s", du.path);
    blen = strlen(dbase);
    while (blen > 0 && dbase[blen - 1] == '/') { dbase[--blen] = '\0'; }
    dbearer = (p->fo != NULL && p->fo->bearer != NULL) ? p->fo->bearer
                                                       : getenv("BEARER_TOKEN");
    {
        mkcol_ctx_t m = { &du, dbase, dbearer, p->co };
        if (mkcol_parents(&m, p->rel, p->st) != 0) {
            return -1;
        }
    }
    if ((size_t) snprintf(dsturl, sizeof(dsturl), "%s://%s:%d%s/%s",
                          web_scheme_str(du.proto), du.host, du.port, dbase,
                          p->rel) >= sizeof(dsturl)) {
        brix_status_set(p->st, XRDC_EUSAGE, 0, "web->web dst path too long");
        return -1;
    }
    return copy_one_with_retry(p->srcurl, dsturl, p->fo, p->co, p->retries,
                               p->st);
}


/* WHAT: place one file at `rel` under a LOCAL directory root `dstroot`.
 * WHY: the local case is mkdir -p + a plain download — kept separate from the
 * web case so each placement path stays single-purpose.
 * HOW: join dstroot/rel, create the parent directories, download via
 * copy_one_with_retry. 0 / -1 (st set). */
static int
place_to_local(const char *dstroot, const place_ctx_t *p)
{
    char dstfile[XRDC_PATH_MAX];

    if ((size_t) snprintf(dstfile, sizeof(dstfile), "%s/%s", dstroot, p->rel)
            >= sizeof(dstfile)) {
        brix_status_set(p->st, XRDC_EUSAGE, 0, "dst path too long");
        return -1;
    }
    mkdirs_for(dstfile);
    return copy_one_with_retry(p->srcurl, dstfile, p->fo, p->co, p->retries,
                               p->st);
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
recursive_place(const char *dstroot, const place_ctx_t *p)
{
    if (p->fo != NULL && !brix_copy_filter_match(p->fo, p->rel)) {
        return 0;   /* filtered — not an error, skip silently */
    }
    if (p->fo != NULL && p->fo->dry_run) {
        printf("[dry-run] copy %s -> %s/%s\n", p->srcurl, dstroot, p->rel);
        return 0;
    }
    if (brix_is_web_url(dstroot)) {
        return place_to_web(dstroot, p);
    }
    return place_to_local(dstroot, p);
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
        || du.is_s3 || (fo != NULL && fo->dry_run)) {
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


/* WHAT: shared per-run state for one recursive download (S3 or WebDAV source).
 * WHY: the enumerate/transfer/report phases of both recursive downloads share
 * the destination, per-file opts, progress counters, and the listing size; a
 * struct keeps the extracted loop/transfer helpers under the parameter cap
 * with explicit data flow.
 * HOW: built on the stack by recursive_{s3,web}_download; the transfer helper
 * mutates only `ok`/`fail`. */
typedef struct {
    const char           *dstdir;   /* local dir OR web collection URL */
    const brix_copy_opts *fo;       /* per-file opts (recursive flag cleared) */
    const brix_opts      *co;       /* connection opts (may be NULL) */
    int                   retries;  /* copy retry budget */
    size_t                n;        /* total listed entries (progress denominator) */
    size_t                ok;       /* copied (or filtered/dry-run) count */
    size_t                fail;     /* failed count */
} recdl_ctx_t;


/* WHAT: map a server-listed key/path to a destination-relative path.
 * WHY: both recursive downloads strip the requested prefix off each listed
 * entry to preserve the source tree under dstdir, falling back to a flattened
 * basename when the server returns an entry outside the prefix.
 * HOW: empty prefix (S3 bucket root) → the key itself; a prefix match followed
 * by '/' or NUL → the remainder; otherwise basename into `relbuf`. Returns a
 * pointer into `path` or `relbuf`. */
static const char *
strip_prefix_rel(const char *path, const char *prefix, size_t plen,
                 char *relbuf, size_t relbufsz)
{
    if (plen == 0) {
        return path;
    }
    if (strncmp(path, prefix, plen) == 0
        && (path[plen] == '/' || path[plen] == '\0')) {
        return path + plen + (path[plen] == '/' ? 1 : 0);
    }
    path_basename(path, relbuf, relbufsz);   /* fallback: flatten */
    return relbuf;
}


/* WHAT: transfer one enumerated source file and account for the outcome.
 * WHY: the S3 and WebDAV download loops share the place-then-count-then-report
 * tail exactly; centralising it keeps both loops enumeration-only.
 * HOW: recursive_place handles filter/dry-run/web-vs-local; success bumps `ok`
 * (with a progress line unless silent), failure bumps `fail` with the error.
 * dstdir may be a local dir OR a web collection (recursive s3/web -> web). */
static void
recdl_transfer_one(recdl_ctx_t *c, const char *srcurl, const char *rel)
{
    brix_status cst;
    place_ctx_t p;

    brix_status_clear(&cst);
    p.rel     = rel;
    p.srcurl  = srcurl;
    p.fo      = c->fo;
    p.co      = c->co;
    p.retries = c->retries;
    p.st      = &cst;
    if (recursive_place(c->dstdir, &p) == 0) {
        c->ok++;
        if (c->fo == NULL || !c->fo->silent) {
            fprintf(stderr, "[%zu/%zu] %s -> %s/%s\n", c->ok + c->fail, c->n,
                    srcurl, c->dstdir, rel);
        }
    } else {
        c->fail++;
        fprintf(stderr, "xrdcp: %s: %s\n", srcurl, cst.msg);
    }
}


/* WHAT: split an s3 URL path "/bucket[/prefix]" into bucket + prefix.
 * WHY: the recursive S3 download needs the bucket for per-key source URLs and
 * the prefix (no trailing slash) to compute destination-relative paths.
 * HOW: one guarded memcpy for the bucket covers both the no-slash and prefix
 * cases (brix_s3_list already validated the same split, but stay defensive);
 * trailing slashes are trimmed off the prefix. 0 / -1 (message printed). */
static int
s3_split_bucket_prefix(const brix_weburl *u, char *bucket, size_t bucketsz,
                       char *prefix, size_t prefixsz)
{
    const char *bsl = strchr(u->path + 1, '/');
    size_t      bl = bsl ? (size_t) (bsl - (u->path + 1)) : strlen(u->path + 1);
    size_t      plen;

    if (bl >= bucketsz) {
        fprintf(stderr, "xrdcp: s3 bucket name too long\n");
        return -1;
    }
    memcpy(bucket, u->path + 1, bl);
    bucket[bl] = '\0';
    if (bsl != NULL) {
        snprintf(prefix, prefixsz, "%s", bsl + 1);
    } else {
        prefix[0] = '\0';
    }
    plen = strlen(prefix);
    while (plen > 0 && prefix[plen - 1] == '/') { prefix[--plen] = '\0'; }
    return 0;
}


/* WHAT: transfer every listed S3 key to its destination-relative path.
 * WHY: separates the per-key relativise/validate/transfer loop from the
 * list/split/setup phase of recursive_s3_download.
 * HOW: strip the prefix off each key, reject unsafe (traversing) relatives
 * from the server, build the per-key source URL, and hand off to
 * recdl_transfer_one; counters accumulate in `c`. */
static void
s3_download_loop(recdl_ctx_t *c, const brix_weburl *u, char **keys,
                 const char *bucket, const char *prefix)
{
    const char *scheme = web_scheme_str(u->proto);
    size_t      plen = strlen(prefix), i;

    for (i = 0; i < c->n; i++) {
        const char *key = keys[i];
        char        relbuf[XRDC_NAME_MAX];
        char        srcurl[XRDC_PATH_MAX + 320];
        const char *rel = strip_prefix_rel(key, prefix, plen,
                                           relbuf, sizeof(relbuf));

        if (*rel == '\0') {
            continue;
        }
        if (rel_is_unsafe(rel)) {
            fprintf(stderr, "xrdcp: refusing unsafe key from server: %s\n", key);
            c->fail++;
            continue;
        }
        if ((size_t) snprintf(srcurl, sizeof(srcurl), "%s://%s:%d/%s/%s",
                              scheme, u->host, u->port, bucket, key)
                >= sizeof(srcurl)) {
            c->fail++;
            continue;
        }
        recdl_transfer_one(c, srcurl, rel);
    }
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
    const char *ak, *sk, *region;
    size_t      n = 0;
    recdl_ctx_t c = { dstdir, fo, co, retries, 0, 0, 0 };

    brix_status_clear(&st);
    ak     = fo->s3_access ? fo->s3_access : getenv("AWS_ACCESS_KEY_ID");
    sk     = fo->s3_secret ? fo->s3_secret : getenv("AWS_SECRET_ACCESS_KEY");
    region = fo->s3_region ? fo->s3_region : getenv("AWS_DEFAULT_REGION");
    if (brix_s3_list(u, ak, sk, region, co ? co->verify_host : 1,
                     co ? co->ca_dir : NULL, &keys, &n, &st) != 0) {
        fprintf(stderr, "xrdcp: s3 list: %s\n", st.msg);
        return 1;
    }
    if (s3_split_bucket_prefix(u, bucket, sizeof(bucket),
                               prefix, sizeof(prefix)) != 0) {
        brix_strv_free(keys, n);
        return 1;
    }
    c.n = n;
    ensure_web_dst_base(dstdir, fo, co);   /* s3->web: create the dst collection */
    s3_download_loop(&c, u, keys, bucket, prefix);
    brix_strv_free(keys, n);
    if (!fo->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu failed (recursive s3)\n",
                c.ok, c.fail);
    }
    return (c.fail == 0) ? 0 : 1;
}


/* WHAT: transfer every PROPFIND-listed WebDAV file to its destination-relative
 * path.
 * WHY: separates the per-path relativise/validate/transfer loop from the
 * parse/list/setup phase of recursive_web_download.
 * HOW: strip the collection prefix off each href, reject unsafe (traversing)
 * relatives — a hostile server must not traverse out of dstdir via the href —
 * build the per-file source URL, and hand off to recdl_transfer_one. */
static void
web_download_loop(recdl_ctx_t *c, const brix_weburl *u, char **paths,
                  const char *prefix)
{
    const char *scheme = web_scheme_str(u->proto);
    size_t      plen = strlen(prefix), i;

    for (i = 0; i < c->n; i++) {
        const char *path = paths[i];
        char        relbuf[XRDC_NAME_MAX];
        char        srcurl[XRDC_PATH_MAX + 320];
        const char *rel = strip_prefix_rel(path, prefix, plen,
                                           relbuf, sizeof(relbuf));

        if (*rel == '\0') {
            continue;
        }
        if (rel_is_unsafe(rel)) {
            fprintf(stderr, "xrdcp: refusing unsafe path from server: %s\n",
                    path);
            c->fail++;
            continue;
        }
        if ((size_t) snprintf(srcurl, sizeof(srcurl), "%s://%s:%d%s",
                              scheme, u->host, u->port, path)
                >= sizeof(srcurl)) {
            c->fail++;
            continue;
        }
        recdl_transfer_one(c, srcurl, rel);
    }
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
    const char    *bearer;
    size_t         n = 0, plen;
    recdl_ctx_t    c;

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
    ensure_web_dst_base(dstdir, &fo, co);   /* web->web: create the dst collection */

    c.dstdir  = dstdir;
    c.fo      = &fo;
    c.co      = co;
    c.retries = retries;
    c.n       = n;
    c.ok      = 0;
    c.fail    = 0;
    web_download_loop(&c, &u, paths, prefix);
    brix_strv_free(paths, n);
    if (o == NULL || !o->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu failed (recursive web)\n",
                c.ok, c.fail);
    }
    return (c.fail == 0) ? 0 : 1;
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

        brix_status_clear(&mst);
        if (web_join(c->base, ch->rel, rpath, sizeof(rpath)) != 0
            || brix_webdav_mkcol(c->u, rpath, c->bearer,
                                 c->co ? c->co->verify_host : 1,
                                 c->co ? c->co->ca_dir : NULL, &mst) != 0) {
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

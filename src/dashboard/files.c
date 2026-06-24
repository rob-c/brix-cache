/*
 * dashboard/files.c — admin file browser + downloader for the monitoring UI.
 *
 * Two admin-auth-only endpoints, both confined to xrootd_dashboard_browse_root
 * via the kernel openat2(RESOLVE_BENEATH) primitive (xrootd_open_beneath), so a
 * client-supplied ?path= can never escape the configured root:
 *
 *   GET /xrootd/api/v1/files?path=<rel>     JSON listing of a directory:
 *       each entry's name, type, size, local owner (uid -> username), and
 *       modification + creation (statx btime) timestamps.
 *   GET /xrootd/api/v1/download?path=<rel>  stream one regular file as an
 *       application/octet-stream attachment.
 *
 * SECURITY:
 *   - Always admin-auth (ngx_http_xrootd_dashboard_check_auth) — never the
 *     anonymous read tier, mirroring the config-download endpoint.
 *   - Disabled unless xrootd_dashboard_browse_root is configured (endpoints 404).
 *   - Confinement is the kernel's RESOLVE_BENEATH; per-entry statx uses
 *     AT_SYMLINK_NOFOLLOW so a symlink is reported, never followed.
 */

#include "dashboard_http.h"
#include "../path/beneath.h"
#include "../compat/http_file_response.h"
#include "../compat/http_headers.h"   /* xrootd_http_source_offer (AGPL sec.13) */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <pwd.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DASHBOARD_FILES_MAX_ENTRIES 10000

/* Map a confined-open failure to an HTTP status.  A RESOLVE_BENEATH escape
 * attempt surfaces as EXDEV/ELOOP — report it as 403 (forbidden), not 500. */
static ngx_int_t
dashboard_open_status(int e)
{
    if (e == ENOENT || e == ENOTDIR) {
        return NGX_HTTP_NOT_FOUND;
    }
    if (e == EACCES || e == EPERM || e == EXDEV || e == ELOOP) {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/* ---- helpers ----------------------------------------------------------- */

/* Resolve uid -> local username; falls back to the decimal uid on lookup miss.
 * A 1-deep cache short-circuits the common "whole dir owned by one user" case. */
static void
dashboard_owner_name(uid_t uid, char *out, size_t outsz)
{
    static uid_t s_cached_uid;
    static char  s_cached_name[64];
    static int   s_have_cache;

    struct passwd  pw;
    struct passwd *res = NULL;
    char           buf[1024];

    if (s_have_cache && s_cached_uid == uid) {
        ngx_snprintf((u_char *) out, outsz, "%s%Z", s_cached_name);
        return;
    }
    if (getpwuid_r(uid, &pw, buf, sizeof(buf), &res) == 0 && res != NULL
        && res->pw_name != NULL)
    {
        ngx_snprintf((u_char *) out, outsz, "%s%Z", res->pw_name);
        ngx_snprintf((u_char *) s_cached_name, sizeof(s_cached_name), "%s%Z",
                     res->pw_name);
        s_cached_uid = uid;
        s_have_cache = 1;
        return;
    }
    ngx_snprintf((u_char *) out, outsz, "%ud%Z", (ngx_uint_t) uid);
}

/*
 * Extract + URL-decode the ?path= query argument into out[] as a path RELATIVE
 * to the browse root (leading '/' stripped; empty/"/" => ".").  Rejects an
 * embedded NUL (decode artefact / smuggling).  Returns NGX_OK / NGX_ERROR.
 * The kernel RESOLVE_BENEATH at open time is what actually enforces confinement;
 * this only normalises the input.
 */
static ngx_int_t
dashboard_files_get_path(ngx_http_request_t *r, char *out, size_t outsz)
{
    ngx_str_t  raw;
    u_char    *dst, *src;
    size_t     n;

    if (ngx_http_arg(r, (u_char *) "path", 4, &raw) != NGX_OK
        || raw.len == 0)
    {
        ngx_memcpy(out, ".", 2);
        return NGX_OK;
    }
    if (raw.len >= outsz) {
        return NGX_ERROR;
    }

    /* URL-decode in place into out (decoded length <= encoded length). */
    dst = (u_char *) out;
    src = raw.data;
    ngx_unescape_uri(&dst, &src, raw.len, 0);
    n = (size_t) (dst - (u_char *) out);
    out[n] = '\0';

    if (ngx_strlchr((u_char *) out, (u_char *) out + n, '\0') != NULL) {
        return NGX_ERROR;   /* embedded NUL */
    }

    /* Strip a leading '/' so the value is relative to the browse root; map the
     * root itself to "." (what openat2 wants for the anchor dir). */
    {
        char  *p = out;
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            ngx_memcpy(out, ".", 2);
        } else if (p != out) {
            ngx_memmove(out, p, strlen(p) + 1);
        }
    }
    return NGX_OK;
}

/* Serialise + send a json_t as application/json (no-store).  Takes ownership of
 * root (decref'd here), mirroring api.c's dashboard_send_json. */
static ngx_int_t
dashboard_files_send_json(ngx_http_request_t *r, ngx_int_t status, json_t *root)
{
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_table_elt_t *cc;
    size_t           needed;
    u_char          *buf;
    ngx_int_t        rc;

    needed = json_dumpb(root, NULL, 0, JSON_COMPACT);
    if (needed == 0) { json_decref(root); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    buf = ngx_palloc(r->pool, needed);
    if (buf == NULL) { json_decref(root); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    json_dumpb(root, (char *) buf, needed, JSON_COMPACT);
    json_decref(root);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    b->pos = b->start = buf;
    b->last = b->end = buf + needed;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status           = status;
    r->headers_out.content_length_n = (off_t) needed;
    r->headers_out.content_type     = (ngx_str_t) ngx_string("application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    cc = ngx_list_push(&r->headers_out.headers);
    if (cc != NULL) {
        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        ngx_str_set(&cc->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { return rc; }
    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/* Build one entry object from a statx result.  Returns a json_t (caller owns) or
 * NULL on OOM. */
static json_t *
dashboard_files_entry(const char *name, const struct statx *stx)
{
    json_t *o = json_object();
    char    owner[64];

    if (o == NULL) { return NULL; }
    dashboard_owner_name((uid_t) stx->stx_uid, owner, sizeof(owner));

    json_object_set_new(o, "name", json_string(name));
    json_object_set_new(o, "type",
        S_ISDIR(stx->stx_mode) ? json_string("dir")
        : S_ISREG(stx->stx_mode) ? json_string("file")
        : json_string("other"));
    json_object_set_new(o, "size", json_integer((json_int_t) stx->stx_size));
    json_object_set_new(o, "owner", json_string(owner));
    json_object_set_new(o, "uid", json_integer((json_int_t) stx->stx_uid));
    json_object_set_new(o, "mtime",
        json_integer((json_int_t) stx->stx_mtime.tv_sec));
    /* Creation time (birth) when the filesystem supports it; 0 => client falls
     * back to mtime. */
    json_object_set_new(o, "btime",
        json_integer((json_int_t)
            ((stx->stx_mask & STATX_BTIME) ? stx->stx_btime.tv_sec : 0)));
    return o;
}

/* ---- GET /xrootd/api/v1/files?path=<rel> ------------------------------- */

ngx_int_t
ngx_http_xrootd_dashboard_files_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    char           relpath[PATH_MAX];
    int            rootfd, dirfd;
    DIR           *dp;
    struct dirent *de;
    json_t        *root, *arr;
    ngx_int_t      rc;
    ngx_uint_t     count = 0;
    int            truncated = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);
    if (conf->browse_root_canon[0] == '\0') {
        return NGX_HTTP_NOT_FOUND;   /* feature disabled */
    }
    rc = ngx_http_xrootd_dashboard_check_auth(r, conf, 0);
    if (rc != NGX_OK) { return rc; }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    xrootd_http_source_offer(r);

    if (dashboard_files_get_path(r, relpath, sizeof(relpath)) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    rootfd = xrootd_beneath_open_root(conf->browse_root_canon);
    if (rootfd < 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    dirfd = xrootd_open_beneath(rootfd, relpath,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    close(rootfd);
    if (dirfd < 0) {
        return dashboard_open_status(ngx_errno);
    }
    dp = fdopendir(dirfd);
    if (dp == NULL) {
        close(dirfd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    root = json_object();
    arr  = json_array();
    if (root == NULL || arr == NULL) {
        if (root) { json_decref(root); }
        if (arr) { json_decref(arr); }
        closedir(dp);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    while ((de = readdir(dp)) != NULL) {
        struct statx stx;
        json_t      *e;

        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;   /* skip "." and ".." (UI navigates via breadcrumb) */
        }
        if (count >= DASHBOARD_FILES_MAX_ENTRIES) {
            truncated = 1;
            break;
        }
        if (statx(dirfd, de->d_name, AT_SYMLINK_NOFOLLOW,
                  STATX_TYPE | STATX_SIZE | STATX_UID | STATX_MTIME
                  | STATX_BTIME, &stx) != 0)
        {
            continue;   /* vanished mid-scan / unreadable — skip */
        }
        e = dashboard_files_entry(de->d_name, &stx);
        if (e == NULL || json_array_append_new(arr, e) != 0) {
            continue;
        }
        count++;
    }
    closedir(dp);   /* also closes dirfd */

    /* Re-derive the normalised path for echo (strip the "." root sentinel). */
    json_object_set_new(root, "schema", json_string("xrootd-dashboard.v1"));
    json_object_set_new(root, "path",
        json_string((relpath[0] == '.' && relpath[1] == '\0') ? "/" : relpath));
    json_object_set_new(root, "truncated", truncated ? json_true() : json_false());
    json_object_set_new(root, "entries", arr);

    return dashboard_files_send_json(r, NGX_HTTP_OK, root);
}

/* ---- GET /xrootd/api/v1/download?path=<rel> ---------------------------- */

/* Build a safe Content-Disposition filename from the basename of relpath:
 * strip the directory, then any byte that could break the header (quote,
 * control, backslash) becomes '_'. */
static void
dashboard_download_filename(const char *relpath, char *out, size_t outsz)
{
    const char *base = strrchr(relpath, '/');
    size_t      i;

    base = (base != NULL) ? base + 1 : relpath;
    if (base[0] == '\0') {
        base = "download";
    }
    for (i = 0; base[i] != '\0' && i + 1 < outsz; i++) {
        unsigned char c = (unsigned char) base[i];
        out[i] = (c < 0x20 || c == '"' || c == '\\' || c == 0x7f) ? '_'
                 : (char) c;
    }
    out[i] = '\0';
}

ngx_int_t
ngx_http_xrootd_dashboard_download_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    char             relpath[PATH_MAX];
    char             fname[256];
    char             disp[320];
    int              rootfd, fd;
    struct stat      sb;
    ngx_int_t        rc;
    ngx_table_elt_t *h;
    int              n;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);
    if (conf->browse_root_canon[0] == '\0') {
        return NGX_HTTP_NOT_FOUND;
    }
    rc = ngx_http_xrootd_dashboard_check_auth(r, conf, 0);
    if (rc != NGX_OK) { return rc; }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    xrootd_http_source_offer(r);

    if (dashboard_files_get_path(r, relpath, sizeof(relpath)) != NGX_OK
        || (relpath[0] == '.' && relpath[1] == '\0'))
    {
        return NGX_HTTP_BAD_REQUEST;   /* the root itself is not a download */
    }

    rootfd = xrootd_beneath_open_root(conf->browse_root_canon);
    if (rootfd < 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    fd = xrootd_open_beneath(rootfd, relpath,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
    close(rootfd);
    if (fd < 0) {
        return dashboard_open_status(ngx_errno);
    }
    if (fstat(fd, &sb) != 0) {
        close(fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!S_ISREG(sb.st_mode)) {
        close(fd);
        return NGX_HTTP_NOT_FOUND;   /* only regular files are downloadable */
    }

    dashboard_download_filename(relpath, fname, sizeof(fname));

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) sb.st_size;
    r->headers_out.content_type     =
        (ngx_str_t) ngx_string("application/octet-stream");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.last_modified_time = sb.st_mtime;

    n = ngx_snprintf((u_char *) disp, sizeof(disp),
                     "attachment; filename=\"%s\"", fname) - (u_char *) disp;
    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Disposition");
        h->value.len = (size_t) n;
        h->value.data = ngx_pnalloc(r->pool, (size_t) n);
        if (h->value.data == NULL) { close(fd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        ngx_memcpy(h->value.data, disp, (size_t) n);
    }
    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Cache-Control");
        ngx_str_set(&h->value, "no-store");
    }

    if (r->method == NGX_HTTP_HEAD || sb.st_size == 0) {
        rc = ngx_http_send_header(r);
        close(fd);
        if (rc == NGX_ERROR || rc > NGX_OK) { return rc; }
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    /* Stream the file (sendfile on cleartext; nginx reads it for TLS).  The
     * helper sends headers, builds the file buf, and closes fd via pool cleanup. */
    return xrootd_http_send_file_range(r, fd, relpath, 0, (off_t) sb.st_size, 1);
}

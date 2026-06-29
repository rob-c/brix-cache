/*
 * xrd_battery.c - extracted concern
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"


/* endpoint diagnostic report (shared by the verbs below + doctor) */


/* One endpoint's diagnostic facts (filled piecemeal by the gatherers; doctor fills
 * all of it, the standalone verbs fill their own slice). */

/* Defined further down (with the diagnostic verbs); forward-declared so doctor can
 * compose them. */

/* functional method battery (doctor --rw / multi-protocol) */


/* One protocol face's functional results. */

/* Append a result. status: >0 pass, 0 fail, <0 skipped. */
void
bat_add(xrd_battery *b, const char *name, int status, const char *fmt, ...)
{
    xrd_check *c;
    va_list    ap;
    if (b->n >= XRD_MAX_CHECKS) { return; }
    c = &b->checks[b->n++];
    snprintf(c->name, sizeof(c->name), "%s", name);
    c->ok      = (status > 0);
    c->skipped = (status < 0);
    va_start(ap, fmt);
    vsnprintf(c->detail, sizeof(c->detail), fmt, ap);
    va_end(ap);
    if (status < 0)      { b->nskip++; }
    else if (status > 0) { b->npass++; }
    else                 { b->nfail++; }
}


/* Fill `buf` (size n) with a deterministic, position-dependent pattern. */
void
fill_pattern(uint8_t *buf, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) { buf[i] = (uint8_t) ((i * 7u + 3u) & 0xff); }
}


/* Write `buf` to an anonymous tmpfile and return its fd (rewound), or -1. */
int
tmpfile_with(const uint8_t *buf, size_t n)
{
    FILE *f = tmpfile();
    int   fd;
    if (f == NULL) { return -1; }
    if (n > 0 && fwrite(buf, 1, n, f) != n) { fclose(f); return -1; }
    fflush(f);
    fd = dup(fileno(f));
    fclose(f);
    if (fd >= 0) { lseek(fd, 0, SEEK_SET); }
    return fd;
}


/* fd-backed pull source for xrdc_http_upload: the battery's body is an anonymous
 * tmpfile (generated diagnostic payload, not export storage), so a plain pread by
 * offset is the source — storage callers pass a VFS-backed source instead. */
static ssize_t
bat_upload_src_fd(void *ctx, uint8_t *buf, int64_t off, size_t cap, xrdc_status *st)
{
    ssize_t r = pread(*(int *) ctx, buf, cap, (off_t) off);  /* vfs-seam-allow: anonymous tmpfile diagnostic payload, not export storage */
    if (r < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "pread: %s", strerror(errno));
    }
    return r;
}


/* The native root:// functional battery: always-safe reads, then (do_write) a full
 * write/read/verify/checksum/metadata cycle under a temp dir that is cleaned up. */
void
battery_root(const xrdc_url *u, const xrdc_opts *o, int do_write, xrd_battery *b)
{
    xrdc_conn     c;
    xrdc_status   st;
    xrdc_statinfo si;
    xrdc_dirent  *ents = NULL;
    size_t        nents = 0;
    char          reply[1024];
    int           ext_sa = 0, ext_sl = 0, ext_rl = 0, ext_ln = 0;

    snprintf(b->protocol, sizeof(b->protocol), "root");
    xrdc_status_clear(&st);
    if (xrdc_connect(&c, u, o, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        return;
    }
    b->reachable = 1;

    /* read-only methods */    xrdc_status_clear(&st);
    if (xrdc_stat(&c, "/", &si, &st) == 0) { bat_add(b, "stat", 1, "/ flags=0x%x", si.flags); }
    else { bat_add(b, "stat", 0, "%s", st.msg); }

    xrdc_status_clear(&st);
    if (xrdc_dirlist(&c, "/", 0, &ents, &nents, &st) == 0) {
        bat_add(b, "dirlist", 1, "%zu entries", nents);
        free(ents); ents = NULL;
    } else { bat_add(b, "dirlist", 0, "%s", st.msg); }

    xrdc_status_clear(&st);
    if (xrdc_statvfs(&c, "/", reply, sizeof(reply), &st) == 0) { bat_add(b, "statvfs", 1, "ok"); }
    else { bat_add(b, "statvfs", 0, "%s", st.msg); }

    xrdc_status_clear(&st);
    if (xrdc_query(&c, kXR_Qconfig, "chksum", reply, sizeof(reply), &st) == 0) {
        char *nl = strchr(reply, '\n'); if (nl) { *nl = '\0'; }
        bat_add(b, "query-config", 1, "%s", reply);
    } else { bat_add(b, "query-config", 0, "%s", st.msg); }

    /* negative: a traversal path must not resolve outside the export */
    xrdc_status_clear(&st);
    {
        int rc = xrdc_stat(&c, "/../../../../etc/passwd", &si, &st);
        bat_add(b, "path-confinement", rc != 0 ? 1 : 0,
                rc != 0 ? "escape rejected" : "LEAKED /etc/passwd");
    }

    (void) xrdc_ext_probe(&c, &ext_sa, &ext_sl, &ext_rl, &ext_ln, &st);

    if (!do_write) {
        bat_add(b, "write-suite", -1, "skipped (pass --rw to run write tests)");
        xrdc_close(&c);
        return;
    }

    /* read/write cycle under a temp dir */    {
        char     dir[128], file[200], file2[200];
        uint8_t  payload[8192], rbuf[8192];
        char     srvck[160], locck[160];
        long     pid = (long) getpid();
        int      ok, rc, sym_left = 0;

        snprintf(dir,   sizeof(dir),   "/.xrd_doctor_%ld", pid);
        snprintf(file,  sizeof(file),  "%s/probe.bin", dir);
        snprintf(file2, sizeof(file2), "%s/probe.moved.bin", dir);
        fill_pattern(payload, sizeof(payload));

        xrdc_status_clear(&st);
        rc = xrdc_mkdir(&c, dir, 0755, 1, &st);
        bat_add(b, "mkdir", rc == 0 ? 1 : 0, "%s", rc == 0 ? dir : st.msg);

        /* write */
        {
            xrdc_file f;
            ok = 0;
            xrdc_status_clear(&st);
            if (xrdc_file_open_write(&c, file, 1, 0, &f, &st) == 0) {
                ok = (xrdc_file_write(&c, &f, 0, payload, sizeof(payload), &st) == 0);
                xrdc_file_close(&c, &f, &st);
            }
            bat_add(b, "write", ok ? 1 : 0, ok ? "%zu bytes" : "%s",
                    ok ? sizeof(payload) : (size_t) 0, ok ? "" : st.msg);
        }
        /* read-back + byte-exact verify */
        {
            xrdc_file f;
            ssize_t   got = -1;
            int       match = 0;
            xrdc_status_clear(&st);
            if (xrdc_file_open_read(&c, file, &f, &st) == 0) {
                got = xrdc_file_read(&c, &f, 0, rbuf, sizeof(rbuf), &st);
                xrdc_file_close(&c, &f, &st);
                match = (got == (ssize_t) sizeof(payload)
                         && memcmp(rbuf, payload, sizeof(payload)) == 0);
            }
            bat_add(b, "read-verify", match ? 1 : 0,
                    match ? "byte-exact %zd bytes" : "mismatch/short (%s)",
                    match ? got : 0, match ? "" : st.msg);
        }
        /* readv (two segments) */
        {
            xrdc_file      f;
            xrdc_readv_seg segs[2];
            int            match = 0;
            uint8_t        s0[64], s1[128];
            segs[0].offset = 0;    segs[0].len = sizeof(s0); segs[0].buf = s0; segs[0].got = 0;
            segs[1].offset = 1000; segs[1].len = sizeof(s1); segs[1].buf = s1; segs[1].got = 0;
            xrdc_status_clear(&st);
            if (xrdc_file_open_read(&c, file, &f, &st) == 0) {
                if (xrdc_file_readv(&c, &f, segs, 2, &st) >= 0) {
                    match = (memcmp(s0, payload, sizeof(s0)) == 0
                             && memcmp(s1, payload + 1000, sizeof(s1)) == 0);
                }
                xrdc_file_close(&c, &f, &st);
            }
            bat_add(b, "readv", match ? 1 : 0, match ? "2 segs verified" : "%s", st.msg);
        }
        /* checksum: server adler32 vs locally computed adler32 of the payload */
        {
            int fd = tmpfile_with(payload, sizeof(payload));
            int verified = 0;
            xrdc_status_clear(&st);
            if (fd >= 0
                && xrdc_cksum_fd(fd, XRDC_CK_ADLER32, locck, sizeof(locck), &st) == 0
                && xrdc_query_cksum(&c, file, "adler32", srvck, sizeof(srvck), &st) == 0) {
                verified = (strcmp(locck, srvck) == 0);
            }
            if (fd >= 0) { close(fd); }
            bat_add(b, "checksum-verify", verified ? 1 : 0,
                    verified ? "adler32 %s matches" : "server/local differ or n/a",
                    verified ? srvck : "");
        }
        /* setattr times (xrdfs.ext) */
        if (ext_sa) {
            struct timespec ts[2];
            ts[0].tv_sec = ts[1].tv_sec = 0;
            ts[0].tv_nsec = ts[1].tv_nsec = UTIME_NOW;
            xrdc_status_clear(&st);
            rc = xrdc_setattr(&c, file, 1, ts, 0, (uint32_t) -1, (uint32_t) -1, &st);
            bat_add(b, "setattr-times", rc == 0 ? 1 : 0, "%s", rc == 0 ? "mtime set" : st.msg);
        } else { bat_add(b, "setattr-times", -1, "server lacks xrdfs.ext"); }
        /* xattr set/get/del (xrdfs.ext fattr is always present, but gate on a probe) */
        {
            char   val[64]; size_t vlen = 0;
            int    okset, okget, okdel;
            xrdc_status_clear(&st);
            okset = (xrdc_fattr_set(&c, file, "doctor", "ok", 2, 0, &st) == 0);
            okget = okset && (xrdc_fattr_get(&c, file, "doctor", val, sizeof(val), &vlen, &st) == 0
                              && vlen == 2 && memcmp(val, "ok", 2) == 0);
            okdel = okget && (xrdc_fattr_del(&c, file, "doctor", &st) == 0);
            bat_add(b, "xattr", okdel ? 1 : (okset ? 0 : -1),
                    okdel ? "set/get/del roundtrip" : (okset ? "%s" : "not supported"),
                    okdel ? "" : st.msg);
        }
        /* symlink + readlink (xrdfs.ext). Note: if the server's rm resolves through
         * the final symlink it cannot unlink the link itself — we detect that and skip
         * the dir's rmdir rather than report a phantom "not empty" failure. */
        if (ext_sl && ext_rl) {
            char    lp[200], tgt[256];
            ssize_t rl;
            int     made;
            snprintf(lp, sizeof(lp), "%s/probe.link", dir);
            xrdc_status_clear(&st);
            made = (xrdc_symlink(&c, file, lp, &st) == 0);
            if (made && (rl = xrdc_readlink(&c, lp, tgt, sizeof(tgt), &st)) > 0
                && strcmp(tgt, file) == 0) {
                xrdc_status rs;
                xrdc_status_clear(&rs);
                if (xrdc_rm(&c, lp, &rs) != 0) {
                    sym_left = 1;
                    bat_add(b, "symlink+readlink", 1,
                            "create+readlink ok; unlink unsupported (rm follows the link)");
                } else {
                    bat_add(b, "symlink+readlink", 1, "create/readlink/unlink ok");
                }
            } else {
                bat_add(b, "symlink+readlink", made ? 0 : 0, "%s", st.msg);
                if (made) { xrdc_status rs; xrdc_status_clear(&rs);
                            if (xrdc_rm(&c, lp, &rs) != 0) { sym_left = 1; } }
            }
        } else { bat_add(b, "symlink+readlink", -1, "server lacks xrdfs.ext"); }
        /* rename */
        xrdc_status_clear(&st);
        rc = xrdc_mv(&c, file, file2, &st);
        bat_add(b, "rename", rc == 0 ? 1 : 0, "%s", rc == 0 ? "moved" : st.msg);
        /* truncate */
        xrdc_status_clear(&st);
        rc = xrdc_truncate(&c, file2, 10, &st);
        bat_add(b, "truncate", rc == 0 ? 1 : 0, "%s", rc == 0 ? "to 10 bytes" : st.msg);
        /* rm the file, then rmdir the now-empty temp dir (cleanup) */
        xrdc_status_clear(&st);
        rc = xrdc_rm(&c, file2, &st);
        bat_add(b, "rm", rc == 0 ? 1 : 0, "%s", rc == 0 ? "removed" : st.msg);
        if (sym_left) {
            bat_add(b, "rmdir", -1,
                    "skipped: temp dir retains a symlink the server cannot unlink");
        } else {
            xrdc_status_clear(&st);
            rc = xrdc_rmdir(&c, dir, &st);
            bat_add(b, "rmdir", rc == 0 ? 1 : 0, "%s", rc == 0 ? "removed" : st.msg);
        }
    }
    xrdc_close(&c);
}


/* The WebDAV/HTTP functional battery: OPTIONS + PROPFIND (read), then (do_write) a
 * MKCOL/PUT/GET-verify/PROPFIND/MOVE/DELETE cycle under a temp collection. bearer NULL
 * = anonymous. */
void
battery_web(const xrdc_weburl *u, int do_write, const char *bearer, int verify,
            xrd_battery *b)
{
    xrdc_http_resp resp;
    xrdc_status    st;
    const char    *ca = xrdc_resolve_ca_dir(NULL);
    char           authhdr[1200];
    const char    *xtra = NULL;

    snprintf(b->protocol, sizeof(b->protocol), "%s", u->tls ? "https" : "http");
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(authhdr, sizeof(authhdr), "Authorization: Bearer %s\r\n", bearer);
        xtra = authhdr;
    }

    xrdc_status_clear(&st);
    if (xrdc_http_req(u->host, u->port, u->tls, "OPTIONS", "/", xtra, NULL, 0,
                      5000, verify, ca, &resp, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        bat_add(b, "OPTIONS", 0, "%s", st.msg);
        return;
    }
    b->reachable = 1;
    {
        char dav[160] = "";
        xrdc_http_header(&resp, "DAV", dav, sizeof(dav));
        bat_add(b, "OPTIONS", (resp.status >= 200 && resp.status < 500) ? 1 : 0,
                "HTTP %d%s%s", resp.status, dav[0] ? " DAV=" : "", dav);
    }
    xrdc_http_resp_free(&resp);

    {
        const char *body = "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/></propfind>";
        char        hdr[1400];
        snprintf(hdr, sizeof(hdr), "Depth: 0\r\nContent-Type: application/xml\r\n%s",
                 xtra ? xtra : "");
        xrdc_status_clear(&st);
        if (xrdc_http_req(u->host, u->port, u->tls, "PROPFIND", "/", hdr, body,
                          strlen(body), 5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "PROPFIND", resp.status == 207 ? 1 : 0, "HTTP %d", resp.status);
            xrdc_http_resp_free(&resp);
        } else { bat_add(b, "PROPFIND", 0, "%s", st.msg); }
    }

    if (!do_write) { bat_add(b, "write-suite", -1, "skipped (pass --rw)"); return; }

    {
        char     dir[160], fpath[256], mpath[256], dst[2048];
        uint8_t  payload[4096], rbuf[4096];
        long     pid = (long) getpid();
        int      fd, st_code = 0, ok;
        long long blen = 0;

        snprintf(dir,   sizeof(dir),   "/.xrd_doctor_%ld/", pid);
        snprintf(fpath, sizeof(fpath), "%.150sprobe.bin", dir);
        snprintf(mpath, sizeof(mpath), "%.150sprobe.moved.bin", dir);
        fill_pattern(payload, sizeof(payload));

        /* MKCOL */
        xrdc_status_clear(&st);
        if (xrdc_http_req(u->host, u->port, u->tls, "MKCOL", dir, xtra, NULL, 0,
                          5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "MKCOL", (resp.status == 201 || resp.status == 405) ? 1 : 0,
                    "HTTP %d", resp.status);
            xrdc_http_resp_free(&resp);
        } else { bat_add(b, "MKCOL", 0, "%s", st.msg); }

        /* PUT */
        fd = tmpfile_with(payload, sizeof(payload));
        xrdc_status_clear(&st);
        if (fd >= 0 && xrdc_http_upload(u->host, u->port, u->tls, fpath, xtra,
                                        bat_upload_src_fd, &fd,
                                        (long long) sizeof(payload), verify, ca, 10000,
                                        &st_code, &st) == 0) {
            bat_add(b, "PUT", (st_code >= 200 && st_code < 300) ? 1 : 0, "HTTP %d", st_code);
        } else { bat_add(b, "PUT", 0, "%s", st.msg); }
        if (fd >= 0) { close(fd); }

        /* GET + byte-exact verify */
        fd = tmpfile_with(NULL, 0);
        xrdc_status_clear(&st);
        if (fd >= 0 && xrdc_http_download(u->host, u->port, u->tls, fpath, xtra, verify,
                                          ca, fd, 10000, &st_code, &blen, &st) == 0
            && blen == (long long) sizeof(payload)) {
            lseek(fd, 0, SEEK_SET);
            ok = (read(fd, rbuf, sizeof(rbuf)) == (ssize_t) sizeof(payload)
                  && memcmp(rbuf, payload, sizeof(payload)) == 0);
            bat_add(b, "GET-verify", ok ? 1 : 0, ok ? "byte-exact %lld" : "mismatch", blen);
        } else { bat_add(b, "GET-verify", 0, "HTTP %d %s", st_code, st.msg); }
        if (fd >= 0) { close(fd); }

        /* MOVE */
        snprintf(dst, sizeof(dst), "Destination: %s://%s:%d%s\r\n%s",
                 u->tls ? "https" : "http", u->host, u->port, mpath, xtra ? xtra : "");
        xrdc_status_clear(&st);
        if (xrdc_http_req(u->host, u->port, u->tls, "MOVE", fpath, dst, NULL, 0,
                          5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "MOVE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                    "HTTP %d", resp.status);
            xrdc_http_resp_free(&resp);
        } else { bat_add(b, "MOVE", 0, "%s", st.msg); }

        /* DELETE the (moved) file and the collection */
        xrdc_status_clear(&st);
        if (xrdc_http_req(u->host, u->port, u->tls, "DELETE", mpath, xtra, NULL, 0,
                          5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "DELETE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                    "HTTP %d", resp.status);
            xrdc_http_resp_free(&resp);
        } else { bat_add(b, "DELETE", 0, "%s", st.msg); }
        { xrdc_status rs; xrdc_status_clear(&rs);
          if (xrdc_http_req(u->host, u->port, u->tls, "DELETE", dir, xtra, NULL, 0,
                            5000, verify, ca, &resp, &rs) == 0) { xrdc_http_resp_free(&resp); } }
    }
}


/* The S3 functional battery: ListObjectsV2 (read), then (do_write) a SigV4-signed
 * PUT/GET-verify/DELETE of a temp object. ak/sk NULL = anonymous (writes skipped). */
void
battery_s3(const xrdc_weburl *u, int do_write, const char *ak, const char *sk,
           const char *region, int verify, xrd_battery *b)
{
    xrdc_status st;
    const char *ca = xrdc_resolve_ca_dir(NULL);
    char      **keys = NULL;
    size_t      nk = 0;

    snprintf(b->protocol, sizeof(b->protocol), "s3");
    xrdc_status_clear(&st);
    if (xrdc_s3_list(u, ak, sk, region, verify, ca, &keys, &nk, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        bat_add(b, "list-objects", 0, "%s", st.msg);
        return;
    }
    b->reachable = 1;
    bat_add(b, "list-objects", 1, "%zu keys", nk);
    xrdc_strv_free(keys, nk);

    if (!do_write) { bat_add(b, "write-suite", -1, "skipped (pass --rw)"); return; }
    if (ak == NULL || sk == NULL) {
        bat_add(b, "write-suite", -1, "no AWS_ACCESS_KEY_ID/SECRET — writes skipped");
        return;
    }
    {
        uint8_t  payload[2048], rbuf[2048];
        char     uri[320], phash[80], hdrs[2048], reqhdr[2100];
        long     pid = (long) getpid();
        int      fd, st_code = 0, ok;
        long long blen = 0;
        const char *bucket_path = (u->path[0] == '/') ? u->path : "/";

        fill_pattern(payload, sizeof(payload));
        snprintf(uri, sizeof(uri), "%.250s/.xrd_doctor_%ld.bin",
                 (strcmp(bucket_path, "/") == 0) ? "" : bucket_path, pid);
        if (uri[0] != '/') {   /* ensure path-style leading slash */
            memmove(uri + 1, uri, strlen(uri) + 1);
            uri[0] = '/';
        }

        /* PUT (body hash signed) */
        xrdc_s3_sha256_hex(payload, sizeof(payload), phash);
        xrdc_status_clear(&st);
        if (xrdc_s3_sign_v4("PUT", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) == 0) {
            fd = tmpfile_with(payload, sizeof(payload));
            if (fd >= 0 && xrdc_http_upload(u->host, u->port, u->tls, uri, hdrs,
                                            bat_upload_src_fd, &fd,
                                            (long long) sizeof(payload), verify, ca, 10000,
                                            &st_code, &st) == 0) {
                bat_add(b, "PUT", (st_code >= 200 && st_code < 300) ? 1 : 0, "HTTP %d", st_code);
            } else { bat_add(b, "PUT", 0, "%s", st.msg); }
            if (fd >= 0) { close(fd); }
        } else { bat_add(b, "PUT", 0, "sign failed"); }

        /* GET + verify (empty-body hash) */
        xrdc_s3_sha256_hex("", 0, phash);
        xrdc_status_clear(&st);
        if (xrdc_s3_sign_v4("GET", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) == 0) {
            fd = tmpfile_with(NULL, 0);
            if (fd >= 0 && xrdc_http_download(u->host, u->port, u->tls, uri, hdrs, verify,
                                              ca, fd, 10000, &st_code, &blen, &st) == 0
                && blen == (long long) sizeof(payload)) {
                lseek(fd, 0, SEEK_SET);
                ok = (read(fd, rbuf, sizeof(rbuf)) == (ssize_t) sizeof(payload)
                      && memcmp(rbuf, payload, sizeof(payload)) == 0);
                bat_add(b, "GET-verify", ok ? 1 : 0, ok ? "byte-exact %lld" : "mismatch", blen);
            } else { bat_add(b, "GET-verify", 0, "HTTP %d %s", st_code, st.msg); }
            if (fd >= 0) { close(fd); }
        } else { bat_add(b, "GET-verify", 0, "sign failed"); }

        /* DELETE */
        xrdc_s3_sha256_hex("", 0, phash);
        xrdc_status_clear(&st);
        if (xrdc_s3_sign_v4("DELETE", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) == 0) {
            xrdc_http_resp resp;
            (void) reqhdr;
            if (xrdc_http_req(u->host, u->port, u->tls, "DELETE", uri, hdrs, NULL, 0,
                              5000, verify, ca, &resp, &st) == 0) {
                bat_add(b, "DELETE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                        "HTTP %d", resp.status);
                xrdc_http_resp_free(&resp);
            } else { bat_add(b, "DELETE", 0, "%s", st.msg); }
        } else { bat_add(b, "DELETE", 0, "sign failed"); }
    }
}


/* Route an endpoint to the right functional battery (root:// / WebDAV / S3). */
void
xrd_run_battery(const char *endpoint, int do_write, int verify, xrd_battery *b)
{
    memset(b, 0, sizeof(*b));
    snprintf(b->endpoint, sizeof(b->endpoint), "%s", endpoint);

    if (xrdc_is_web_url(endpoint)) {
        xrdc_weburl w;
        if (xrdc_weburl_parse(endpoint, &w) != 0) {
            snprintf(b->protocol, sizeof(b->protocol), "web");
            snprintf(b->err, sizeof(b->err), "unparseable web URL");
            return;
        }
        if (w.is_s3) {
            const char *region = getenv("AWS_DEFAULT_REGION");
            battery_s3(&w, do_write, getenv("AWS_ACCESS_KEY_ID"),
                       getenv("AWS_SECRET_ACCESS_KEY"),
                       region ? region : "us-east-1", verify, b);
        } else {
            char *tok = xrdc_token_discover();
            battery_web(&w, do_write, tok, verify, b);
            if (tok != NULL) { free(tok); }
        }
        return;
    }
    {
        xrdc_url    u;
        xrdc_opts   o;
        xrdc_status st;
        memset(&o, 0, sizeof(o));
        o.verify_host = verify;
        xrdc_status_clear(&st);
        snprintf(b->protocol, sizeof(b->protocol), "root");
        if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
            snprintf(b->err, sizeof(b->err), "%s", st.msg);
            return;
        }
        battery_root(&u, &o, do_write, b);
    }
}

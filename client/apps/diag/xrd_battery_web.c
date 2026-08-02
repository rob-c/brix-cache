/*
 * xrd_battery_web.c - WebDAV + S3 functional battery suites.
 * Phase-38 split of xrd_battery.c; behavior-identical.
 */
#include "xrd_internal.h"

/* WebDAV read probes: OPTIONS (sets b->reachable) then PROPFIND. Returns 0 on a
 * reachable endpoint, -1 if OPTIONS could not connect (b->err filled). */
static int
web_read_suite(const brix_weburl *u, const char *xtra, int verify, const char *ca,
               xrd_battery *b)
{
    brix_http_resp resp;
    brix_status    st;

    brix_status_clear(&st);
    if (brix_http_req(u->host, u->port, u->tls, "OPTIONS", "/", xtra, NULL, 0,
                      5000, verify, ca, &resp, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        bat_add(b, "OPTIONS", 0, "%s", st.msg);
        return -1;
    }
    b->reachable = 1;
    {
        char dav[160] = "";
        brix_http_header(&resp, "DAV", dav, sizeof(dav));
        bat_add(b, "OPTIONS", (resp.status >= 200 && resp.status < 500) ? 1 : 0,
                "HTTP %d%s%s", resp.status, dav[0] ? " DAV=" : "", dav);
    }
    brix_http_resp_free(&resp);

    {
        const char *body = "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/></propfind>";
        char        hdr[1400];
        snprintf(hdr, sizeof(hdr), "Depth: 0\r\nContent-Type: application/xml\r\n%s",
                 xtra ? xtra : "");
        brix_status_clear(&st);
        if (brix_http_req(u->host, u->port, u->tls, "PROPFIND", "/", hdr, body,
                          strlen(body), 5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "PROPFIND", resp.status == 207 ? 1 : 0, "HTTP %d", resp.status);
            brix_http_resp_free(&resp);
        } else { bat_add(b, "PROPFIND", 0, "%s", st.msg); }
    }
    return 0;
}

/* PUT a temp file then GET it back and byte-compare. */
static void
web_put_get_verify(const brix_weburl *u, const char *fpath, const char *xtra,
                   int verify, const char *ca, xrd_battery *b)
{
    brix_status st;
    uint8_t     payload[4096], rbuf[4096];
    int         fd, st_code = 0, ok;
    long long   blen = 0;

    fill_pattern(payload, sizeof(payload));

    /* PUT */
    fd = tmpfile_with(payload, sizeof(payload));
    brix_status_clear(&st);
    if (fd >= 0 && brix_http_upload(u->host, u->port, u->tls, fpath, xtra,
                                    bat_upload_src_fd, &fd,
                                    (long long) sizeof(payload), verify, ca, 10000,
                                    &st_code, &st) == 0) {
        bat_add(b, "PUT", (st_code >= 200 && st_code < 300) ? 1 : 0, "HTTP %d", st_code);
    } else { bat_add(b, "PUT", 0, "%s", st.msg); }
    if (fd >= 0) { close(fd); }

    /* GET + byte-exact verify */
    fd = tmpfile_with(NULL, 0);
    brix_status_clear(&st);
    if (fd >= 0 && brix_http_download(u->host, u->port, u->tls, fpath, xtra, verify,
                                      ca, fd, 10000, &st_code, &blen, &st) == 0
        && blen == (long long) sizeof(payload)) {
        lseek(fd, 0, SEEK_SET);
        ok = (read(fd, rbuf, sizeof(rbuf)) == (ssize_t) sizeof(payload)
              && memcmp(rbuf, payload, sizeof(payload)) == 0);
        bat_add(b, "GET-verify", ok ? 1 : 0, ok ? "byte-exact %lld" : "mismatch", blen);
    } else { bat_add(b, "GET-verify", 0, "HTTP %d %s", st_code, st.msg); }
    if (fd >= 0) { close(fd); }
}

/* MOVE the file, DELETE the moved file, then DELETE the collection. */
static void
web_move_delete(const brix_weburl *u, const char *dir, const char *fpath,
                const char *mpath, const char *xtra, int verify, const char *ca,
                xrd_battery *b)
{
    brix_http_resp resp;
    brix_status    st;
    char           dst[2048];

    snprintf(dst, sizeof(dst), "Destination: %s://%s:%d%s\r\n%s",
             u->tls ? "https" : "http", u->host, u->port, mpath, xtra ? xtra : "");
    brix_status_clear(&st);
    if (brix_http_req(u->host, u->port, u->tls, "MOVE", fpath, dst, NULL, 0,
                      5000, verify, ca, &resp, &st) == 0) {
        bat_add(b, "MOVE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                "HTTP %d", resp.status);
        brix_http_resp_free(&resp);
    } else { bat_add(b, "MOVE", 0, "%s", st.msg); }

    /* DELETE the (moved) file and the collection */
    brix_status_clear(&st);
    if (brix_http_req(u->host, u->port, u->tls, "DELETE", mpath, xtra, NULL, 0,
                      5000, verify, ca, &resp, &st) == 0) {
        bat_add(b, "DELETE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                "HTTP %d", resp.status);
        brix_http_resp_free(&resp);
    } else { bat_add(b, "DELETE", 0, "%s", st.msg); }
    { brix_status rs; brix_status_clear(&rs);
      if (brix_http_req(u->host, u->port, u->tls, "DELETE", dir, xtra, NULL, 0,
                        5000, verify, ca, &resp, &rs) == 0) { brix_http_resp_free(&resp); } }
}

/* MKCOL/PUT/GET-verify/MOVE/DELETE cycle under a temp collection. */
static void
web_write_suite(const brix_weburl *u, const char *xtra, int verify, const char *ca,
                xrd_battery *b)
{
    brix_http_resp resp;
    brix_status    st;
    char           dir[160], fpath[256], mpath[256];
    long           pid = (long) getpid();

    snprintf(dir,   sizeof(dir),   "/.xrd_doctor_%ld/", pid);
    snprintf(fpath, sizeof(fpath), "%.150sprobe.bin", dir);
    snprintf(mpath, sizeof(mpath), "%.150sprobe.moved.bin", dir);

    /* MKCOL */
    brix_status_clear(&st);
    if (brix_http_req(u->host, u->port, u->tls, "MKCOL", dir, xtra, NULL, 0,
                      5000, verify, ca, &resp, &st) == 0) {
        bat_add(b, "MKCOL", (resp.status == 201 || resp.status == 405) ? 1 : 0,
                "HTTP %d", resp.status);
        brix_http_resp_free(&resp);
    } else { bat_add(b, "MKCOL", 0, "%s", st.msg); }

    web_put_get_verify(u, fpath, xtra, verify, ca, b);
    web_move_delete(u, dir, fpath, mpath, xtra, verify, ca, b);
}

/* The WebDAV/HTTP functional battery: OPTIONS + PROPFIND (read), then (do_write) a
 * MKCOL/PUT/GET-verify/PROPFIND/MOVE/DELETE cycle under a temp collection. bearer NULL
 * = anonymous. */
void
battery_web(const brix_weburl *u, int do_write, const char *bearer, int verify,
            xrd_battery *b)
{
    const char *ca = brix_resolve_ca_dir(NULL);
    char        authhdr[1200];
    const char *xtra = NULL;

    snprintf(b->protocol, sizeof(b->protocol), "%s", u->tls ? "https" : "http");
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(authhdr, sizeof(authhdr), "Authorization: Bearer %s\r\n", bearer);
        xtra = authhdr;
    }

    if (web_read_suite(u, xtra, verify, ca, b) != 0) { return; }

    if (!do_write) { bat_add(b, "write-suite", -1, "skipped (pass --rw)"); return; }

    web_write_suite(u, xtra, verify, ca, b);
}


/* SigV4-signed PUT of the payload to `uri`. */
static void
s3_put(const brix_weburl *u, const char *uri, const char *ak, const char *sk,
       const char *region, int verify, const char *ca,
       const uint8_t *payload, size_t payload_len, xrd_battery *b)
{
    brix_status st;
    char        phash[80], hdrs[2048];
    int         fd, st_code = 0;

    brix_s3_sha256_hex(payload, payload_len, phash);
    brix_status_clear(&st);
    if (brix_s3_sign_v4("PUT", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) != 0) {
        bat_add(b, "PUT", 0, "sign failed");
        return;
    }
    fd = tmpfile_with(payload, payload_len);
    if (fd >= 0 && brix_http_upload(u->host, u->port, u->tls, uri, hdrs,
                                    bat_upload_src_fd, &fd,
                                    (long long) payload_len, verify, ca, 10000,
                                    &st_code, &st) == 0) {
        bat_add(b, "PUT", (st_code >= 200 && st_code < 300) ? 1 : 0, "HTTP %d", st_code);
    } else { bat_add(b, "PUT", 0, "%s", st.msg); }
    if (fd >= 0) { close(fd); }
}

/* SigV4-signed GET of `uri`, byte-compared against the expected payload. */
static void
s3_get_verify(const brix_weburl *u, const char *uri, const char *ak, const char *sk,
              const char *region, int verify, const char *ca,
              const uint8_t *payload, size_t payload_len, xrd_battery *b)
{
    brix_status st;
    char        phash[80], hdrs[2048];
    uint8_t     rbuf[2048];
    int         fd, st_code = 0, ok;
    long long   blen = 0;

    brix_s3_sha256_hex("", 0, phash);
    brix_status_clear(&st);
    if (brix_s3_sign_v4("GET", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) != 0) {
        bat_add(b, "GET-verify", 0, "sign failed");
        return;
    }
    fd = tmpfile_with(NULL, 0);
    if (fd >= 0 && brix_http_download(u->host, u->port, u->tls, uri, hdrs, verify,
                                      ca, fd, 10000, &st_code, &blen, &st) == 0
        && blen == (long long) payload_len) {
        lseek(fd, 0, SEEK_SET);
        ok = (read(fd, rbuf, sizeof(rbuf)) == (ssize_t) payload_len
              && memcmp(rbuf, payload, payload_len) == 0);
        bat_add(b, "GET-verify", ok ? 1 : 0, ok ? "byte-exact %lld" : "mismatch", blen);
    } else { bat_add(b, "GET-verify", 0, "HTTP %d %s", st_code, st.msg); }
    if (fd >= 0) { close(fd); }
}

/* SigV4-signed DELETE of `uri`. */
static void
s3_delete(const brix_weburl *u, const char *uri, const char *ak, const char *sk,
          const char *region, int verify, const char *ca, xrd_battery *b)
{
    brix_status st;
    char        phash[80], hdrs[2048];

    brix_s3_sha256_hex("", 0, phash);
    brix_status_clear(&st);
    if (brix_s3_sign_v4("DELETE", u->host, uri, ak, sk, region, phash, hdrs, sizeof(hdrs)) != 0) {
        bat_add(b, "DELETE", 0, "sign failed");
        return;
    }
    {
        brix_http_resp resp;
        if (brix_http_req(u->host, u->port, u->tls, "DELETE", uri, hdrs, NULL, 0,
                          5000, verify, ca, &resp, &st) == 0) {
            bat_add(b, "DELETE", (resp.status >= 200 && resp.status < 300) ? 1 : 0,
                    "HTTP %d", resp.status);
            brix_http_resp_free(&resp);
        } else { bat_add(b, "DELETE", 0, "%s", st.msg); }
    }
}

/* Build the path-style temp-object URI for this run into `uri` (size n). */
static void
s3_temp_uri(const brix_weburl *u, char *uri, size_t n)
{
    long        pid = (long) getpid();
    const char *bucket_path = (u->path[0] == '/') ? u->path : "/";

    snprintf(uri, n, "%.250s/.xrd_doctor_%ld.bin",
             (strcmp(bucket_path, "/") == 0) ? "" : bucket_path, pid);
    if (uri[0] != '/') {   /* ensure path-style leading slash */
        memmove(uri + 1, uri, strlen(uri) + 1);
        uri[0] = '/';
    }
}

/* SigV4-signed PUT/GET-verify/DELETE of a temp object. */
static void
s3_write_suite(const brix_weburl *u, const char *ak, const char *sk,
               const char *region, int verify, const char *ca, xrd_battery *b)
{
    uint8_t payload[2048];
    char    uri[320];

    fill_pattern(payload, sizeof(payload));
    s3_temp_uri(u, uri, sizeof(uri));

    s3_put(u, uri, ak, sk, region, verify, ca, payload, sizeof(payload), b);
    s3_get_verify(u, uri, ak, sk, region, verify, ca, payload, sizeof(payload), b);
    s3_delete(u, uri, ak, sk, region, verify, ca, b);
}

/* The S3 functional battery: ListObjectsV2 (read), then (do_write) a SigV4-signed
 * PUT/GET-verify/DELETE of a temp object. ak/sk NULL = anonymous (writes skipped). */
void
battery_s3(const brix_weburl *u, int do_write, const char *ak, const char *sk,
           const char *region, int verify, xrd_battery *b)
{
    brix_status st;
    const char *ca = brix_resolve_ca_dir(NULL);
    char      **keys = NULL;
    size_t      nk = 0;

    snprintf(b->protocol, sizeof(b->protocol), "s3");
    brix_status_clear(&st);
    if (brix_s3_list(u, ak, sk, region, verify, ca, &keys, &nk, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        bat_add(b, "list-objects", 0, "%s", st.msg);
        return;
    }
    b->reachable = 1;
    bat_add(b, "list-objects", 1, "%zu keys", nk);
    brix_strv_free(keys, nk);

    if (!do_write) { bat_add(b, "write-suite", -1, "skipped (pass --rw)"); return; }
    if (ak == NULL || sk == NULL) {
        bat_add(b, "write-suite", -1, "no AWS_ACCESS_KEY_ID/SECRET — writes skipped");
        return;
    }
    s3_write_suite(u, ak, sk, region, verify, ca, b);
}


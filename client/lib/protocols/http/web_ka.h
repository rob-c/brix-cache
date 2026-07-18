/*
 * web_ka.h — persistent keep-alive HTTP/1.1 transport + WebDAV PROPFIND.
 * Private split contract; include only from client/lib/.
 */
#ifndef BRIX_WEB_KA_H
#define BRIX_WEB_KA_H

#include "brix.h"

/* A persistent, keep-alive HTTP/1.1 connection to one origin (cleartext/TLS).
 * One request in flight; NOT thread-safe (pool it via brix_cpool). */
typedef struct {
    brix_io io;
    void   *tls_ctx;              /* SSL_CTX* when tls, else NULL */
    int     connected;
    char    host[256];
    int     port;
    int     tls;
    int     verify;
    char    ca_dir[512];          /* "" => default resolver */
    char    hostport[300];        /* Host: header value (IPv6-bracketed) */
    int     timeout_ms;
} brix_kaconn;

typedef struct {
    int       status;
    long long clen;               /* -1 when absent */
    char     *body_start;         /* into caller hbuf, just past CRLFCRLF */
    size_t    body_buffered;      /* body bytes already sitting in hbuf */
} brix_ka_hdr;

void brix_kaconn_init(brix_kaconn *k, const char *host, int port, int tls,
                      int verify, const char *ca_dir, int timeout_ms);
int  brix_kaconn_connect(brix_kaconn *k, brix_status *st);
void brix_kaconn_disconnect(brix_kaconn *k);
int  brix_kaconn_read_headers(brix_kaconn *k, char *hbuf, size_t hbufsz,
                              brix_ka_hdr *out, brix_status *st);
int  brix_kaconn_read_body(brix_kaconn *k, const brix_ka_hdr *hdr,
                           char **body_out, size_t *len_out, brix_status *st);

typedef struct {
    brix_kaconn ka;
    char        auth[2200];       /* "Authorization: Bearer ...\r\n" or "" */
} brix_webmeta;

void brix_webmeta_init(brix_webmeta *m, const char *host, int port, int tls,
                       int verify, const char *ca_dir, const char *bearer,
                       int timeout_ms);
/* Keep-alive PROPFIND of `path` at `depth` (0=stat, 1=readdir). On success
 * body_out/len_out own the NUL-terminated response body (free()). Deadline-
 * bounded reconnect-on-sever (webfile_window_ms()). status→kXR: 404 NotFound,
 * 401/403 NotAuthorized, 207/200 ok, else EPROTO. -1 err / 0 ok. */
int  brix_webmeta_propfind(brix_webmeta *m, const char *path, int depth,
                           char **body_out, size_t *len_out, brix_status *st);

#endif /* BRIX_WEB_KA_H */

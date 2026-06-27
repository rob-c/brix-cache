/*
 * webfile_internal.h - private split contract for webfile.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_WEBFILE_INTERNAL_H
#define XROOTD_WEBFILE_INTERNAL_H

#include "xrdc.h"
#include "compat/uri.h"
#include "compat/host_format.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#define WEB_TIMEOUT_MS   30000
#define WEB_HDR_MAX      16384         

struct xrdc_webfile {
    char     host[256];
    int      port;
    int      tls;
    int      verify;
    char     ca_dir[512];
    char     hostport[300];        /* Host: header value (IPv6-bracketed) */
    char     path[XRDC_PATH_MAX];
    char     auth[2200];           /* "Authorization: Bearer ...\r\n" or "" */
    int      timeout_ms;
    int64_t  size;
    /* persistent transport */
    xrdc_io  io;
    void    *tls_ctx;
    int      connected;
};


/* webfile.c */
const char * tag_val(const char *p, const char *end, const char *name, size_t *vlen);
long parse_http_date(const char *v, size_t n);
int parse_response(const char *p, const char *end, xrdc_statinfo *si, char *href, size_t hrefsz);
void web_auth(const char *bearer, char *out, size_t outsz);
int xml_name_char(char c);
const char * next_response_open(const char *p, const char *end);
const char * next_response_close(const char *p, const char *end);
int has_collection_element(const char *p, const char *end);
void path_basename(const char *path, char *out, size_t outsz);

/* webfile_io.c */
void web_disconnect(xrdc_webfile *wf);
int web_connect(xrdc_webfile *wf, xrdc_status *st);
ssize_t web_read_some(xrdc_webfile *wf, void *buf, size_t n, xrdc_status *st);
long long hdr_clen(const char *hdrs);
ssize_t web_get_range(xrdc_webfile *wf, int64_t off, void *buf, size_t len, xrdc_status *st);
int webfile_window_ms(void);

#endif /* XROOTD_WEBFILE_INTERNAL_H */

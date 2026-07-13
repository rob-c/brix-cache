/*
 * xrdhttp_stats.c — ?xrd.stats XML statistics endpoint for the XrdHttp protocol.
 *
 * WHAT: Serves the XRootD statistics XML format at any URL that includes
 * the query parameter "xrd.stats".  The response is consumed by XRootD
 * collector infrastructure (xrd_mon, XrdCns) and by xrdfs "query stats".
 *
 * WHY: XrdHttp clients and monitoring agents poll "GET /path?xrd.stats" to
 * obtain server performance data in the same format that the native XRootD
 * protocol serves via kXR_query / kXR_QStats.  Providing this endpoint makes
 * nginx-xrootd observable by the same monitoring stack without requiring a
 * separate sidecar.
 *
 * HOW: Reads WebDAV metrics from the shared-memory zone (atomic reads, safe
 * from any worker) and formats them into a minimal XML document compatible
 * with XRootD 5.x stats output.  Fields that have no direct mapping (e.g.,
 * scheduler threads, poll-set state) are emitted as zero to avoid parse
 * failures in collector software.
 *
 * SECURITY: The response contains only aggregate counters — no path names,
 * bucket names, principal names, or IP addresses are included.  Collectors
 * that wish to restrict access to this endpoint should do so via nginx
 * location blocks (allow/deny directives or auth_basic).
 */

#include "xrdhttp.h"
#include "webdav.h"
#include "core/ident.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Maximum size of the generated XML document.  All stats fit comfortably in 4 KiB. */
#define XRDHTTP_STATS_BUF_MAX  4096

/*
 * Build the XRootD-compatible stats XML document into buf (null-terminated).
 * Returns the number of bytes written (excluding the terminating NUL), or -1
 * on overflow.
 */
static int
build_stats_xml(char *buf, size_t bufsz, ngx_http_request_t *r)
{
    ngx_brix_metrics_t      *shm;
    ngx_brix_webdav_metrics_t zero;
    ngx_brix_webdav_metrics_t *m;
    char                        hostname[256];
    time_t                      now;
    ngx_atomic_t                gets, puts, deletes, total_req;
    ngx_atomic_t                bytes_in, bytes_out;
    ngx_atomic_t                auth_ok, auth_fail;
    int                         listen_port;
    int                         len;

    shm = brix_metrics_shared();
    if (shm != NULL) {
        m = &shm->webdav;
    } else {
        ngx_memzero(&zero, sizeof(zero));
        m = &zero;
    }

    now = time(NULL);

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        ngx_cpystrn((u_char *) hostname, (u_char *) "localhost",
                    sizeof(hostname));
    }
    hostname[sizeof(hostname) - 1] = '\0';

    /* Derive the actual listening port from the incoming connection. */
    {
        struct sockaddr_storage  ss;
        socklen_t                sslen = sizeof(ss);

        ngx_memzero(&ss, sizeof(ss));   /* getsockname may not set ss_family on error */
        if (getsockname(r->connection->fd, (struct sockaddr *)(void *) &ss,
                        &sslen) == 0) {
            if (ss.ss_family == AF_INET) {
                listen_port = ntohs(((struct sockaddr_in *)(void *) &ss)->sin_port);
            } else if (ss.ss_family == AF_INET6) {
                listen_port = ntohs(((struct sockaddr_in6 *)(void *) &ss)->sin6_port);
            } else {
                listen_port = 8443;
            }
        } else {
            listen_port = 8443;
        }
    }

    gets    = m->requests_total[BRIX_WEBDAV_METHOD_GET]
            + m->requests_total[BRIX_WEBDAV_METHOD_HEAD];
    puts    = m->requests_total[BRIX_WEBDAV_METHOD_PUT];
    deletes = m->requests_total[BRIX_WEBDAV_METHOD_DELETE];

    total_req = 0;
    for (ngx_uint_t i = 0; i < BRIX_WEBDAV_NMETHODS; i++) {
        total_req += m->requests_total[i];
    }

    bytes_in  = m->bytes_rx_total;
    bytes_out = m->bytes_tx_total;

    auth_ok   = m->auth_total[BRIX_WEBDAV_AUTH_RESULT_CERT_OK]
              + m->auth_total[BRIX_WEBDAV_AUTH_RESULT_TOKEN_OK]
              + m->auth_total[BRIX_WEBDAV_AUTH_RESULT_ANONYMOUS];
    auth_fail = m->auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED];

    len = snprintf(buf, bufsz,
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<statistics tod=\"%ld\" ver=\"" BRIX_SERVER_VERSION "\" src=\"%s:%d\""
        " ins=\"anon\" pid=\"%d\" pgm=\"" BRIX_SERVER_NAME "\">\n"

        "  <stats id=\"info\">\n"
        "    <host>%s</host>\n"
        "    <port>%d</port>\n"
        "    <name>" BRIX_SERVER_NAME "</name>\n"
        "    <role>server</role>\n"
        "  </stats>\n"

        "  <stats id=\"sched\">\n"
        "    <jobs>0</jobs><inq>0</inq><maxinq>0</maxinq>\n"
        "    <threads>0</threads><idle>0</idle>\n"
        "    <tcr>0</tcr><tde>0</tde><tlimr>0</tlimr>\n"
        "  </stats>\n"

        "  <stats id=\"link\">\n"
        "    <num>%lld</num><maxn>0</maxn>\n"
        "    <tot>%lld</tot>\n"
        "    <in>%lld</in><out>%lld</out>\n"
        "    <ctime>0</ctime><tmo>0</tmo><stall>0</stall><sfps>0</sfps>\n"
        "  </stats>\n"

        "  <stats id=\"poll\">\n"
        "    <att>0</att><en>0</en><ev>0</ev><int>0</int>\n"
        "  </stats>\n"

        "  <stats id=\"buff\">\n"
        "    <reqs>0</reqs><mem>0</mem><buffs>0</buffs>\n"
        "    <adj>0</adj><xlreqs>0</xlreqs>\n"
        "  </stats>\n"

        "  <stats id=\"xrootd\">\n"
        "    <ops>\n"
        "      <open>%lld</open>\n"
        "      <getf>%lld</getf>\n"
        "      <put>%lld</put>\n"
        "      <rf>%lld</rf>\n"
        "      <rd>%lld</rd>\n"
        "      <pr>0</pr><rv>0</rv>\n"
        "    </ops>\n"
        "    <aio><num>0</num><max>0</max><rej>0</rej></aio>\n"
        "    <err>%lld</err><dly>0</dly><rdr>0</rdr>\n"
        "    <lgn>\n"
        "      <num>%lld</num>\n"
        "      <af>%lld</af><ua>0</ua><ur>0</ur>\n"
        "    </lgn>\n"
        "  </stats>\n"

        "  <stats id=\"http\">\n"
        "    <requests>%lld</requests>\n"
        "    <bytes_in>%lld</bytes_in>\n"
        "    <bytes_out>%lld</bytes_out>\n"
        "    <tpc_pull>%lld</tpc_pull>\n"
        "    <tpc_push>%lld</tpc_push>\n"
        "    <range_partial>%lld</range_partial>\n"
        "  </stats>\n"

        "</statistics>\n",

        /* header */
        (long) now, hostname, listen_port, (int) ngx_getpid(),
        /* info */
        hostname, listen_port,
        /* link */
        (long long) total_req,         /* num — approximated as total requests */
        (long long) total_req,         /* tot */
        (long long) bytes_in,          /* in */
        (long long) bytes_out,         /* out */
        /* xrootd ops */
        (long long) (gets + puts),     /* open */
        (long long) gets,              /* getf */
        (long long) puts,              /* put */
        (long long) deletes,           /* rf (remove file) */
        (long long) m->requests_total[BRIX_WEBDAV_METHOD_GET], /* rd */
        /* err */
        (long long) (m->auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED]
                   + m->responses_total[0][BRIX_HTTP_STATUS_5XX]),
        /* lgn */
        (long long) auth_ok,
        (long long) auth_fail,
        /* http */
        (long long) total_req,
        (long long) bytes_in,
        (long long) bytes_out,
        (long long) m->tpc_total[BRIX_WEBDAV_TPC_PULL_STARTED],
        (long long) m->tpc_total[BRIX_WEBDAV_TPC_PUSH_STARTED],
        (long long) m->range_total[BRIX_WEBDAV_RANGE_PARTIAL]
    );

    if (len < 0 || (size_t) len >= bufsz) {
        return -1;
    }

    return len;
}

ngx_int_t
xrdhttp_handle_stats_query(ngx_http_request_t *r)
{
    char             buf[XRDHTTP_STATS_BUF_MAX];
    int              len;
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_table_elt_t *h;

    len = build_stats_xml(buf, sizeof(buf), r);
    if (len < 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->allow_ranges = 0;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "text/xml; charset=utf-8");

    /* Cache-Control: no-store — stats are always current. */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Cache-Control");
    ngx_str_set(&h->value, "no-store");

    (void) xrdhttp_add_response_headers(r, NGX_HTTP_OK);

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, (size_t) len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, buf, (size_t) len);
    b->last         = b->pos + len;
    b->last_buf     = 1;
    b->last_in_chain = 1;

    out.buf  = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

/*
 * sts_http.c — STS transport + response parsing (phase-79 split).
 *
 * WHAT: fetch the signed STS URL over http/https with libcurl and parse the
 *       AssumeRole/GetSessionToken XML reply into AccessKeyId / SecretAccessKey
 *       / SessionToken. Returns the HTTP status to the caller and the extracted
 *       credentials in the caller's fixed buffers.
 * WHY:  split out of sts.c (formerly 815 lines) as the side-effecting edge —
 *       network I/O and XML parsing — kept apart from the pure request builder
 *       (sts_sign.c) and the orchestrator (sts.c). Behaviour is byte-for-byte
 *       the pre-split code: same curl hardening, same bounded body, same
 *       name-directed XML descent, same log strings (secrets never logged).
 * HOW:  sts_http_get mirrors webdav/tpc_curl.c — TLS verified, protocols pinned
 *       to http/https, body streamed into a BRIX_STS_RESP_MAX-bounded buffer.
 *       sts_parse_response walks the libxml2 tree for the credential elements;
 *       a no-libxml2 build fails closed with an explicit message.
 *
 * The reused building blocks:
 *   - outbound HTTP:  libcurl, mirroring src/protocols/webdav/tpc_curl.c
 *   - XML parsing:    libxml2 (guarded by BRIX_HAVE_LIBXML2)
 */
#include "sts_internal.h"

#include <curl/curl.h>

#if (BRIX_HAVE_LIBXML2)
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif


/* ------------------------------------------------------------------------- *
 * HTTP transport (libcurl, mirroring webdav/tpc_curl.c)                     *
 * ------------------------------------------------------------------------- */

/*
 * libcurl write callback: append the response body into a growable pool buffer,
 * bounded by BRIX_STS_RESP_MAX so a hostile/huge response cannot exhaust memory.
 * Returns 0 (short write → curl aborts) on overflow or OOM.
 */
static size_t
sts_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    sts_resp_t *r  = userdata;
    size_t      n  = size * nmemb;

    if (n == 0) {
        return 0;
    }
    if (r->len + n > BRIX_STS_RESP_MAX) {
        return 0;
    }
    ngx_memcpy(r->buf + r->len, ptr, n);
    r->len += n;
    return n;
}


/*
 * sts_http_get — GET the signed STS URL and capture the response body.
 *
 * Restricts the transfer to http/https, enforces TLS verification, and streams
 * the body into `resp` (a pre-sized pool buffer). Returns NGX_OK with the HTTP
 * status in *http_status, or NGX_ERROR on a transport error (logged, no
 * secrets). Mirrors the curl setup in webdav_tpc_run_curl_core().
 */
ngx_int_t
sts_http_get(const char *url, sts_resp_t *resp, long *http_status,
    ngx_log_t *log)
{
    CURL     *curl;
    CURLcode  res;
    char      errbuf[CURL_ERROR_SIZE];
    ngx_int_t rc = NGX_ERROR;

    curl = curl_easy_init();
    if (curl == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "brix_sts: curl_easy_init failed");
        return NGX_ERROR;
    }

    errbuf[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);
#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
        (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sts_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_status);
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_WARN, log, 0, "brix_sts: STS request failed: %s",
            errbuf[0] ? errbuf : curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    return rc;
}


/* ------------------------------------------------------------------------- *
 * Response parsing (libxml2)                                                *
 * ------------------------------------------------------------------------- */

#if (BRIX_HAVE_LIBXML2)

/*
 * Recursively search the parse tree for the first element named `name` and copy
 * its text content into out[outsz]. Returns 1 if found, 0 otherwise. The STS
 * AssumeRole/GetSessionToken responses nest <Credentials> under result and
 * response wrappers, so a name-directed descent is simpler than a fixed path.
 */
static int
sts_xml_find(xmlNodePtr node, const char *name, char *out, size_t outsz)
{
    xmlNodePtr n;

    for (n = node; n != NULL; n = n->next) {
        if (n->type == XML_ELEMENT_NODE
            && xmlStrcmp(n->name, (const xmlChar *) name) == 0)
        {
            xmlChar *txt = xmlNodeGetContent(n);
            if (txt != NULL) {
                ngx_snprintf((u_char *) out, outsz, "%s%Z", (char *) txt);
                xmlFree(txt);
                return 1;
            }
        }
        if (n->children != NULL
            && sts_xml_find(n->children, name, out, outsz))
        {
            return 1;
        }
    }
    return 0;
}


/*
 * sts_parse_response — extract AccessKeyId / SecretAccessKey / SessionToken
 * from the STS XML body into the caller's fixed buffers. Returns NGX_OK when at
 * least AccessKeyId and SecretAccessKey are present; NGX_ERROR (with the fault
 * logged, secrets excluded) otherwise. SessionToken is optional.
 */
ngx_int_t
sts_parse_response(const u_char *body, size_t len,
    const sts_creds_buf_t *creds, ngx_log_t *log)
{
    xmlDocPtr  doc;
    xmlNodePtr root;
    ngx_int_t  rc = NGX_ERROR;

    creds->ak[0] = creds->sk[0] = creds->session[0] = '\0';

    doc = xmlReadMemory((const char *) body, (int) len, "sts.xml", NULL,
            XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix_sts: unparseable STS response");
        return NGX_ERROR;
    }

    root = xmlDocGetRootElement(doc);
    if (root != NULL
        && sts_xml_find(root, "AccessKeyId", creds->ak, creds->aksz)
        && sts_xml_find(root, "SecretAccessKey", creds->sk, creds->sksz)
        && creds->ak[0] != '\0' && creds->sk[0] != '\0')
    {
        (void) sts_xml_find(root, "SessionToken", creds->session,
            creds->sesssz);
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix_sts: STS response missing credential fields");
    }

    xmlFreeDoc(doc);
    return rc;
}

#else  /* !BRIX_HAVE_LIBXML2 */

ngx_int_t
sts_parse_response(const u_char *body, size_t len,
    const sts_creds_buf_t *creds, ngx_log_t *log)
{
    (void) body; (void) len; (void) creds;
    ngx_log_error(NGX_LOG_ERR, log, 0,
        "brix_sts: built without libxml2; STS exchange unavailable");
    return NGX_ERROR;
}

#endif /* BRIX_HAVE_LIBXML2 */

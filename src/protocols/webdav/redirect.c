/*
 * webdav/redirect.c — §6.1: HTTP redirect-to-dataserver + brix_http_secretkey
 * signed-CGI identity handoff.
 *
 * WHAT: The HTTP plane's redirector.  Manager half: for GET/HEAD/PUT on a
 * node with brix_webdav_redirect_dataserver on, select a data server from
 * the CMS registry (the same brix_srv_select the root:// plane uses) and
 * answer 307 with a Location carrying the client's own CGI plus, when
 * brix_http_secretkey is set, the authenticated identity signed as
 * brixrdr.exp/usr/vo/mac.  Data-server half: verify that CGI (HMAC-SHA256,
 * constant-time, bounded expiry) and adopt the identity, so the client's
 * redirected request needs no second authentication round.
 *
 * WHY: The dormant XrdHttp redirect scaffolding was removed in phase-95 with
 * the verdict "a real implementation starts from a mesh-selection call
 * site"; this is that call site.  Without it a WebDAV manager must proxy
 * every byte itself.  The signed CGI is the http.secretkey analog: BriX
 * dialect (documented, not byte-compatible with stock XrdHttp's hash — the
 * upstream tree was unavailable to verify its exact format), same trust
 * model: possession of the shared key proves the redirector vouches for the
 * identity.
 *
 * HOW: Manager: loop-guard (already-signed requests are never re-redirected)
 * → registry select (write direction for PUT) → build Location (escaped
 * path + client args + signed CGI) → 307.  Data server: extract brixrdr.*,
 * enforce expiry then recompute the MAC over "method\npath\nexp\nusr\nvo"
 * and compare with CRYPTO_memcmp; on success fill the request identity.
 */

#include "webdav.h"
#include "redirect.h"
#include "net/manager/registry.h"     /* brix_srv_select — mesh selection */
#include "core/http/http_query.h"     /* brixrdr.* CGI extraction */
#include "core/compat/crypto.h"       /* brix_hmac_sha256 */
#include "observability/metrics/unified.h"

#include <openssl/crypto.h>           /* CRYPTO_memcmp — constant time */

#define BRIX_RDR_MAC_HEX_LEN  64      /* HMAC-SHA256 as lowercase hex */

/*
 * rdr_mac_hex — compute the signed-CGI MAC for one (method, path, exp, usr,
 * vo) tuple as lowercase hex.
 *
 * WHAT: HMAC-SHA256 over the newline-joined canonical string, hex-encoded
 *       into out_hex (BRIX_RDR_MAC_HEX_LEN + NUL).  Returns NGX_OK/NGX_ERROR.
 * WHY:  One function used by both signer and verifier — the canonical string
 *       can never drift between them.  Binding method+path prevents replaying
 *       a GET grant as a PUT or against another file; exp bounds the window.
 * HOW:  Assemble in a bounded stack buffer (components are already bounded
 *       by their extraction), HMAC with the shared key, ngx_hex_dump.
 */
static ngx_int_t
rdr_mac_hex(const ngx_str_t *key, const ngx_str_t *method, const char *path,
    const char *exp, const char *usr, const char *vo,
    char out_hex[BRIX_RDR_MAC_HEX_LEN + 1])
{
    u_char   canon[4096];
    u_char  *cursor = canon;
    u_char  *end = canon + sizeof(canon);
    uint8_t  mac[32];

    cursor = ngx_slprintf(cursor, end, "%V\n%s\n%s\n%s\n%s",
                          method, path, exp, usr, vo);
    if (cursor == end) {
        return NGX_ERROR;    /* over-long component — refuse, never truncate */
    }

    if (!brix_hmac_sha256(key->data, key->len, canon,
                            (size_t) (cursor - canon), mac))
    {
        return NGX_ERROR;
    }

    ngx_hex_dump((u_char *) out_hex, mac, sizeof(mac));
    out_hex[BRIX_RDR_MAC_HEX_LEN] = '\0';
    return NGX_OK;
}

/*
 * rdr_append_signed_cgi — manager side: append &brixrdr.exp/usr/vo/mac.
 *
 * WHAT: Writes the signed identity CGI at *cursor (bounded by end), taking
 *       the identity from the request context (anonymous → empty usr/vo,
 *       still signed — the data server then knows the manager vouched for an
 *       anonymous principal).  Returns the advanced cursor, or NULL when the
 *       CGI does not fit or signing fails (caller redirects unsigned).
 * WHY:  The signature must cover the UNESCAPED values; the CGI carries them
 *       escaped.  Component escaping uses NGX_ESCAPE_ARGS so '&'/'=' inside
 *       a DN cannot splice extra parameters.
 * HOW:  Format exp as absolute unix seconds (now + window), sign, then emit
 *       each key=value with ngx_escape_uri on the values.
 */
static u_char *
rdr_append_signed_cgi(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    u_char *cursor, u_char *end)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    const char *usr = "";
    const char *vo = "";
    char        exp[24];
    char        mac_hex[BRIX_RDR_MAC_HEX_LEN + 1];
    uintptr_t   esc;

    if (rx != NULL && rx->identity != NULL) {
        usr = brix_identity_dn_cstr(rx->identity);
        if (usr[0] == '\0') {
            usr = brix_identity_subject_cstr(rx->identity);
        }
        vo = brix_identity_vo_csv_cstr(rx->identity);
    }

    ngx_snprintf((u_char *) exp, sizeof(exp), "%T%Z",
                 ngx_time() + (time_t) conf->redirect_window);

    if (rdr_mac_hex(&conf->http_secretkey, &r->method_name, path, exp, usr,
                      vo, mac_hex) != NGX_OK)
    {
        return NULL;
    }

    cursor = ngx_slprintf(cursor, end, "%c" "brixrdr.exp=%s",
                          (r->args.len > 0) ? '&' : '?', exp);

    cursor = ngx_slprintf(cursor, end, "&brixrdr.usr=");
    esc = ngx_escape_uri(NULL, (u_char *) usr, ngx_strlen(usr),
                         NGX_ESCAPE_ARGS);
    if (cursor + ngx_strlen(usr) + 2 * esc >= end) {
        return NULL;
    }
    cursor = (u_char *) ngx_escape_uri(cursor, (u_char *) usr,
                                       ngx_strlen(usr), NGX_ESCAPE_ARGS);

    cursor = ngx_slprintf(cursor, end, "&brixrdr.vo=");
    esc = ngx_escape_uri(NULL, (u_char *) vo, ngx_strlen(vo),
                         NGX_ESCAPE_ARGS);
    if (cursor + ngx_strlen(vo) + 2 * esc >= end) {
        return NULL;
    }
    cursor = (u_char *) ngx_escape_uri(cursor, (u_char *) vo,
                                       ngx_strlen(vo), NGX_ESCAPE_ARGS);

    cursor = ngx_slprintf(cursor, end, "&brixrdr.mac=%s", mac_hex);
    return (cursor < end) ? cursor : NULL;
}

/*
 * rdr_send_307 — emit the finished 307 with the given Location value.
 *
 * WHAT: Adds the Location header, sends an empty-body 307, and returns the
 *       metrics-counted status.
 * WHY:  nginx auto-emits Location only for 301/302 via headers_out.location's
 *       special-case; a 307 needs the header pushed explicitly (same shape
 *       webdav_dispatch_not_allowed uses for Allow).
 * HOW:  ngx_list_push + send_header + ngx_http_send_special.
 */
static ngx_int_t
rdr_send_307(ngx_http_request_t *r, u_char *loc, size_t loc_len)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return webdav_metrics_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "Location");
    h->value.data = loc;
    h->value.len  = loc_len;

    r->headers_out.status = NGX_HTTP_TEMPORARY_REDIRECT;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return webdav_metrics_return(r, ngx_http_send_special(r, NGX_HTTP_LAST));
}

/*
 * rdr_eligible — may this request be handed off to a data server at all?
 *
 * WHAT: Returns 1 when the redirect leg applies, 0 to serve locally.
 * WHY:  Loop guard: a request that already carries a signed handoff landed on
 *       a node that (mis)configures BOTH roles — serve locally rather than
 *       bouncing the client around the mesh.  Only the three body-bearing
 *       methods are worth a round trip; everything else is cheaper here.
 * HOW:  1. the directive must be on.  2. GET/HEAD/PUT only.  3. no
 *       brixrdr.mac in the query (brix_http_query_has returns 1 on a match, 0
 *       otherwise — NOT an NGX_OK code; HAS_VALUE_OK is required because the
 *       key carries the hex MAC as its value).  4. the URI must fit the
 *       caller's path buffer.
 */
static int
rdr_eligible(ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf,
    size_t path_cap)
{
    if (!conf->redirect_dataserver) {
        return 0;
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD
        && r->method != NGX_HTTP_PUT)
    {
        return 0;
    }
    if (brix_http_query_has(r->args, "brixrdr.mac",
                              BRIX_HTTP_QUERY_HAS_VALUE_OK) == 1)
    {
        return 0;
    }

    return (r->uri.len != 0 && r->uri.len < path_cap);
}


/*
 * rdr_build_location — render the absolute redirect target.
 *
 * WHAT: Allocates and fills the Location value; returns it with *out_len set,
 *       or NULL when the allocation failed.
 * WHY:  The buffer is sized from the escaped URI up front, so every writer
 *       below is bounded by `end` and no length can be recomputed wrongly
 *       halfway through.  A signed-CGI overflow degrades to an unsigned
 *       redirect rather than a truncated (and therefore forged-looking) one.
 * HOW:  scheme + host + port, then the escaped path, the client's own args,
 *       and finally the signed identity CGI when a secret key is configured.
 */
static u_char *
rdr_build_location(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    const char *ds_host, uint16_t ds_port, size_t *out_len)
{
    u_char     *loc, *cursor, *end, *signed_cursor;
    size_t      loc_size;
    uintptr_t   esc;

    /* scheme + host + port + escaped path + client args + signed CGI. */
    esc = ngx_escape_uri(NULL, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
    loc_size = sizeof("https://:65535") + ngx_strlen(ds_host)
             + r->uri.len + 2 * esc + 1 + r->args.len
             + 512 /* signed CGI incl. escaped usr/vo */
             + 1024;
    loc = ngx_pnalloc(r->pool, loc_size);
    if (loc == NULL) {
        return NULL;
    }
    end = loc + loc_size;

    cursor = ngx_slprintf(loc, end, "%s://%s:%d",
                          conf->redirect_scheme == BRIX_WEBDAV_RDR_HTTPS
                              ? "https" : "http",
                          ds_host, (int) ds_port);
    cursor = (u_char *) ngx_escape_uri(cursor, r->uri.data, r->uri.len,
                                       NGX_ESCAPE_URI);
    if (r->args.len > 0) {
        cursor = ngx_slprintf(cursor, end, "?%V", &r->args);
    }

    if (conf->http_secretkey.len > 0) {
        signed_cursor = rdr_append_signed_cgi(r, conf, path, cursor, end);

        if (signed_cursor != NULL) {
            cursor = signed_cursor;
        } else {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "brix_webdav: redirect identity CGI overflow — "
                "redirecting unsigned");
        }
    }

    *out_len = (size_t) (cursor - loc);
    return loc;
}


ngx_int_t
webdav_redirect_dataserver(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    char        path[WEBDAV_MAX_PATH];
    char        ds_host[256];
    uint16_t    ds_port;
    int         for_write;
    u_char     *loc;
    size_t      loc_len;

    if (!rdr_eligible(r, conf, sizeof(path))) {
        return NGX_DECLINED;
    }

    ngx_memcpy(path, r->uri.data, r->uri.len);
    path[r->uri.len] = '\0';

    for_write = (r->method == NGX_HTTP_PUT);
    if (!brix_srv_select(path, for_write, ds_host, sizeof(ds_host),
                           &ds_port))
    {
        return NGX_DECLINED;   /* no registered data server — serve locally */
    }
    if (conf->redirect_port > 0) {
        ds_port = (uint16_t) conf->redirect_port;
    }

    loc = rdr_build_location(r, conf, path, ds_host, ds_port, &loc_len);
    if (loc == NULL) {
        return webdav_metrics_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: redirecting %V %s to %s:%d%s",
                  &r->method_name, path, ds_host, (int) ds_port,
                  conf->http_secretkey.len > 0 ? " (signed)" : "");

    return rdr_send_307(r, loc, loc_len);
}

/*
 * rdr_adopt_identity — data-server side: install the verified principal.
 *
 * WHAT: Fills the request context (identity object, dn buffer, source tag)
 *       from the verified usr/vo strings.  NGX_OK / NGX_ERROR (OOM).
 * WHY:  Downstream authorization (authdb, VO ACLs, scope checks) reads the
 *       same identity object every other credential source fills — the
 *       redirect principal must be indistinguishable from a locally
 *       authenticated one.
 * HOW:  brix_identity_alloc + set_dn/set_vos_csv; BRIX_AUTHN_SSS is the
 *       honest method bit — the trust derives from a pre-shared secret.
 *       An empty usr stays anonymous (verified=0): the manager vouched only
 *       that an anonymous client came through it.
 */
static ngx_int_t
rdr_adopt_identity(ngx_http_request_t *r, const char *usr, const char *vo)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    /* Get-or-create: on a plain-http listener no earlier tier (TLS cert /
     * token) has attached the ctx, so this may be the first to need it —
     * mirrors wb_ensure_ctx in the Basic tier. */
    if (rx == NULL) {
        rx = ngx_pcalloc(r->pool, sizeof(*rx));
        if (rx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, rx, ngx_http_brix_webdav_module);
    }
    if (usr[0] == '\0') {
        rx->auth_source = "redirect-anon";
        return NGX_OK;
    }

    if (rx->identity == NULL) {
        rx->identity = brix_identity_alloc(r->pool);
        if (rx->identity == NULL) {
            return NGX_ERROR;
        }
    }
    if (brix_identity_set_dn(rx->identity, r->pool, usr,
                               BRIX_AUTHN_SSS) != NGX_OK
        || (vo[0] != '\0'
            && brix_identity_set_vos_csv(rx->identity, r->pool, vo)
               != NGX_OK))
    {
        return NGX_ERROR;
    }

    rx->verified = 1;
    rx->auth_source = "redirect";
    ngx_cpystrn((u_char *) rx->dn, (u_char *) usr, sizeof(rx->dn));
    brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_SSS, 1);
    return NGX_OK;
}

ngx_int_t
webdav_redirect_signed_auth(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    char       mac_cgi[BRIX_RDR_MAC_HEX_LEN + 2];
    char       exp[24];
    char       usr[1024];
    char       vo[1024];
    char       path[WEBDAV_MAX_PATH];
    char       mac_hex[BRIX_RDR_MAC_HEX_LEN + 1];
    ngx_int_t  exp_secs;

    /* brix_http_query_get returns 1 on a match, 0 for absent, -1 on error —
     * NOT an NGX_OK code.  Only a real match (1) enters the verify path. */
    if (brix_http_query_get(r->args, "brixrdr.mac", mac_cgi, sizeof(mac_cgi),
                              0) != 1)
    {
        return NGX_DECLINED;   /* no handoff CGI — normal authentication */
    }

    /* The CGI is present: from here every deviation is a FAIL-CLOSED 403 —
     * a tampered or replayed handoff must never fall back to anonymous. */

    if (conf->http_secretkey.len == 0) {
        /* Not part of the trust scheme: treat the CGI as opaque noise and
         * let normal authentication decide.  (A key-less server cannot
         * verify anything, and refusing would break clients whose path
         * legitimately contains a brixrdr.mac param.) */
        return NGX_DECLINED;
    }

    if (brix_http_query_get(r->args, "brixrdr.exp", exp, sizeof(exp), 0)
            != 1
        || brix_http_query_get(r->args, "brixrdr.usr", usr, sizeof(usr),
               BRIX_HTTP_QUERY_DECODE_VALUE | BRIX_HTTP_QUERY_REJECT_NUL
               | BRIX_HTTP_QUERY_ALLOW_EMPTY) != 1
        || brix_http_query_get(r->args, "brixrdr.vo", vo, sizeof(vo),
               BRIX_HTTP_QUERY_DECODE_VALUE | BRIX_HTTP_QUERY_REJECT_NUL
               | BRIX_HTTP_QUERY_ALLOW_EMPTY) != 1)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_webdav: signed redirect CGI incomplete — refused");
        return NGX_HTTP_FORBIDDEN;
    }

    exp_secs = ngx_atoi((u_char *) exp, ngx_strlen(exp));
    if (exp_secs == NGX_ERROR || (time_t) exp_secs < ngx_time()) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_webdav: signed redirect expired — refused");
        return NGX_HTTP_FORBIDDEN;
    }

    if (r->uri.len == 0 || r->uri.len >= sizeof(path)) {
        return NGX_HTTP_FORBIDDEN;
    }
    ngx_memcpy(path, r->uri.data, r->uri.len);
    path[r->uri.len] = '\0';

    if (rdr_mac_hex(&conf->http_secretkey, &r->method_name, path, exp, usr,
                      vo, mac_hex) != NGX_OK
        || ngx_strlen(mac_cgi) != BRIX_RDR_MAC_HEX_LEN
        || CRYPTO_memcmp(mac_hex, mac_cgi, BRIX_RDR_MAC_HEX_LEN) != 0)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_webdav: signed redirect MAC mismatch — refused");
        BRIX_WEBDAV_METRIC_INC(auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED]);
        return NGX_HTTP_FORBIDDEN;
    }

    if (rdr_adopt_identity(r, usr, vo) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix_webdav: signed redirect accepted (usr=%s)",
        usr[0] ? usr : "<anonymous>");
    return NGX_OK;
}

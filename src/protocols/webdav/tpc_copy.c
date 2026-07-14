/*
 * tpc_copy.c - HTTP-TPC COPY request parsing, credential delegation, and the
 * per-user proxy/bearer forwarding helpers for the WebDAV module.
 *
 * WHAT: Owns the request-level parsing and credential decisions the COPY
 *       dispatcher makes before any data moves: pull-xor-push header validation,
 *       X-Number-Of-Streams / Overwrite parsing, Source-URL validation, the
 *       OAuth2/OIDC Credential token-exchange delegation for the pull source, the
 *       opportunistic user-bearer forwarding, and the per-user x509 proxy
 *       resolution into the pull context.
 * WHY:  Split from tpc.c (which was over the 500-line cap) so the security-load-
 *       bearing credential/authorization decisions are grouped and individually
 *       reviewable, separate from the dispatcher and the staged pull execution.
 * HOW:  Each entry point declared in tpc_internal_split.h is called by the COPY
 *       dispatcher (ngx_http_brix_webdav_tpc_handle_copy in tpc.c) in the same
 *       order as before. The shared request helpers (subject-token extract, bearer
 *       append) live in tpc.c and are reached through the split header. No
 *       behaviour change: the delegation order (Credential parse -> subject-token
 *       -> token-exchange -> inject; then opportunistic user-bearer; then per-user
 *       proxy) and every metric slot are preserved exactly.
 */

#include "tpc_internal_split.h"

#include "webdav.h"
#include "tpc_user_proxy.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"
#include "core/http/http_headers.h"
#include "core/compat/staged_file.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "observability/sesslog/sesslog_ngx.h"
#include "fs/xfer/xfer.h"     /* unified transfer audit ledger (kind=tpc) */
#include "tpc/common/auth.h"
#include "tpc/common/metrics.h"
#include "tpc/common/registry.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* OAuth2/OIDC credential delegation for an HTTP-TPC pull: parse the Credential /
 * Credentials request header and, unless it is absent or "none", obtain a
 * delegated token for source_url and inject it as an "Authorization: Bearer"
 * entry into transfer_headers (consumed by the curl subprocess).  Returns NGX_OK
 * to continue (whether or not delegation happened), or an NGX_HTTP_* status the
 * caller must return on a parse/obtain/alloc failure. */
ngx_int_t
webdav_tpc_apply_credential_delegation(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *source_url,
    ngx_array_t *transfer_headers)
{
    ngx_table_elt_t       *credential_hdr;
    brix_tpc_cred_mode_e mode;
    ngx_str_t              delegated_token;
    ngx_table_elt_t       *auth_hdr;
    const char            *subject_token = NULL;
    ngx_int_t              rc;

    credential_hdr = webdav_tpc_find_header(r, "Credential",
                                            sizeof("Credential") - 1);
    if (credential_hdr == NULL) {
        credential_hdr = webdav_tpc_find_header(r, "Credentials",
                                                sizeof("Credentials") - 1);
    }
    if (credential_hdr == NULL
        || webdav_tpc_header_value_equals(&credential_hdr->value, "none"))
    {
        return NGX_OK;
    }

    mode = webdav_tpc_cred_parse_mode(
        (const char *) credential_hdr->value.data,
        credential_hdr->value.len);

    if (mode == BRIX_TPC_CRED_UNKNOWN) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: unsupported HTTP-TPC credential "
                      "delegation mode \"%V\"", &credential_hdr->value);
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Extract the subject token from the request's Authorization header. */
    auth_hdr = webdav_tpc_find_header(r, "Authorization",
                                      sizeof("Authorization") - 1);
    rc = webdav_tpc_extract_subject_token(r, auth_hdr, &subject_token);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = webdav_tpc_cred_obtain_token(r, mode, source_url,
                                      subject_token,
                                      conf->tpc_cred.token_scope.len > 0
                                          ? (const char *) conf->tpc_cred.token_scope.data
                                          : "storage.read",
                                      &delegated_token);
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_GATEWAY;
    }

    /* Inject delegated token as Authorization header. */
    {
        size_t total_len = sizeof("Authorization: Bearer ") - 1
                           + delegated_token.len;
        ngx_str_t *dst = ngx_array_push(transfer_headers);
        if (dst == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        dst->data = ngx_pnalloc(r->pool, total_len + 1);
        if (dst->data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(dst->data, "Authorization: Bearer ",
                   sizeof("Authorization: Bearer ") - 1);
        ngx_memcpy(dst->data + sizeof("Authorization: Bearer ") - 1,
                   delegated_token.data, delegated_token.len);
        dst->len = total_len;
        dst->data[dst->len] = '\0';
    }

    return NGX_OK;
}

ngx_int_t
webdav_tpc_validate_copy_headers(ngx_table_elt_t *source_hdr,
    ngx_table_elt_t *dest_hdr)
{
    if ((source_hdr == NULL && dest_hdr == NULL)
        || (source_hdr != NULL && dest_hdr != NULL))
    {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }
    return NGX_OK;
}

ngx_uint_t
webdav_tpc_parse_stream_count(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_table_elt_t *streams_hdr;
    ngx_uint_t       n_streams = 1;

    streams_hdr = webdav_tpc_find_header(r, "X-Number-Of-Streams",
                                         sizeof("X-Number-Of-Streams") - 1);
    if (streams_hdr != NULL && streams_hdr->value.len > 0) {
        ngx_int_t v = ngx_atoi(streams_hdr->value.data, streams_hdr->value.len);
        if (v > 1) {
            n_streams = (ngx_uint_t) v;
        }
    }
    if (n_streams > conf->tpc_max_streams && conf->tpc_max_streams > 0) {
        n_streams = conf->tpc_max_streams;
    }
    return n_streams;
}

ngx_int_t
webdav_tpc_source_url(ngx_http_request_t *r, ngx_table_elt_t *source_hdr,
    char **source_url)
{
    if (source_hdr->value.len < sizeof("https://") - 1
        || ngx_strncasecmp(source_hdr->value.data, (u_char *) "https://",
                           sizeof("https://") - 1) != 0
        || webdav_tpc_str_has_ctl(source_hdr->value.data,
                                  source_hdr->value.len))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: HTTP-TPC Source must be an https URL");
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    *source_url = webdav_tpc_pstrndup0(r->pool, source_hdr->value.data,
                                       source_hdr->value.len);
    return (*source_url == NULL) ? NGX_HTTP_INTERNAL_SERVER_ERROR : NGX_OK;
}

ngx_int_t
webdav_tpc_parse_overwrite(ngx_http_request_t *r, ngx_flag_t *overwrite)
{
    ngx_table_elt_t *overwrite_hdr;

    overwrite_hdr = webdav_tpc_find_header(r, "Overwrite",
                                           sizeof("Overwrite") - 1);
    *overwrite = 1;
    if (overwrite_hdr == NULL) {
        return NGX_OK;
    }
    if (webdav_tpc_header_value_equals(&overwrite_hdr->value, "F")) {
        *overwrite = 0;
        return NGX_OK;
    }
    if (webdav_tpc_header_value_equals(&overwrite_hdr->value, "T")) {
        *overwrite = 1;
        return NGX_OK;
    }
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
    return NGX_HTTP_BAD_REQUEST;
}

/*
 * webdav_tpc_transfer_headers_have_authorization — does the outbound header set
 * already carry an Authorization entry?
 *
 * WHAT: scans the collected "Name: value" transfer-header strings for one whose
 *       name (up to the ':') is "Authorization", case-insensitively.
 * WHY:  the opportunistic default bearer-forward must never override a bearer the
 *       client explicitly delegated — an explicit TransferHeaderAuthorization, or
 *       a Credential-mode token-exchange result, already sits in this array and
 *       must win over the requesting user's ambient token.
 * HOW:  matches the fixed prefix "authorization:"; returns 1 on the first hit,
 *       0 when none is present (or the array is empty/NULL).
 */
static int
webdav_tpc_transfer_headers_have_authorization(const ngx_array_t *headers)
{
    static const u_char  name[] = "authorization";
    const size_t         name_len = sizeof(name) - 1;
    const ngx_str_t     *elts;
    ngx_uint_t           i;

    if (headers == NULL) {
        return 0;
    }

    elts = headers->elts;
    for (i = 0; i < headers->nelts; i++) {
        if (elts[i].len > name_len
            && elts[i].data[name_len] == ':'
            && ngx_strncasecmp(elts[i].data, (u_char *) name, name_len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/*
 * webdav_tpc_forward_user_bearer — opportunistic default: present the requesting
 * user's own captured bearer token to the pull source.
 *
 * WHAT: when credential forwarding is enabled (the default) and the outbound
 *       header set does not already carry an Authorization entry, appends the raw
 *       JWT the request authenticated with (rctx->bearer_token) as an
 *       "Authorization: Bearer <token>" transfer header.
 * WHY:  a TPC pull should act as the END USER against the source by default —
 *       this is the HTTP equivalent of the native root:// bearer passthrough. It
 *       is OPPORTUNISTIC: the absence of a captured token is not an error (the leg
 *       falls back to the service x509 cert / anonymous exactly as before), and a
 *       client-supplied Authorization is never overridden.
 * HOW:  no-ops (NGX_OK) when the toggle is off, no rctx/token is present, or an
 *       Authorization header already exists; otherwise reuses
 *       webdav_tpc_add_bearer_header. Returns its NGX_HTTP_* only on an allocation
 *       failure — never a denial.
 */
ngx_int_t
webdav_tpc_forward_user_bearer(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_array_t *transfer_headers)
{
    ngx_http_brix_webdav_req_ctx_t *rctx;

    if (!conf->tpc_credential_forward) {
        return NGX_OK;
    }

    rctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (rctx == NULL || rctx->bearer_token.len == 0
        || rctx->bearer_token.data == NULL)
    {
        return NGX_OK;
    }

    if (webdav_tpc_transfer_headers_have_authorization(transfer_headers)) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: TPC pull forwarding requesting user's bearer"
                  " token to source (opportunistic default)");
    return webdav_tpc_add_bearer_header(r, transfer_headers,
                                        &rctx->bearer_token);
}

/* ---- Resolve the per-user pull-leg x509 proxy into the pull context ----
 *
 * WHAT: When brix_webdav_tpc_credential_forward is on, resolves the requesting
 *       user's delegated x509 proxy and records its cert/key paths in
 *       pl->user_cert / pl->user_key. Returns NGX_OK on success (leaving both
 *       fields NULL when no per-user proxy is available, so the leg falls back to
 *       the static service cert). Returns NGX_HTTP_INTERNAL_SERVER_ERROR only when
 *       an explicitly delegated proxy could not be materialised (up.deny).
 *
 * WHY:  Presents the END USER's identity to the source (not our service cert) as
 *       the default, independent of brix_backend_delegation which governs the
 *       data-plane backend leg. Kept OPPORTUNISTIC: absence of a per-user proxy
 *       leaves the fields NULL and downgrades to the service cert exactly as
 *       before; only a proxy we were told to use but could not build aborts, so we
 *       never silently transfer under the wrong identity. Forwarding off leaves
 *       the fields untouched (service-cert only).
 *
 * HOW:  1. No-op (NGX_OK) when conf->tpc_credential_forward is off — pl fields keep
 *          their memzero'd NULLs.
 *       2. Resolve the user proxy via webdav_tpc_user_proxy_resolve.
 *       3. On up.deny, count a bad-request metric and return 500.
 *       4. Otherwise copy the resolved cert/key paths into pl when up.have, else
 *          leave them NULL.
 */
ngx_int_t
webdav_tpc_apply_user_proxy(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, webdav_tpc_pull_ctx_t *pl)
{
    webdav_tpc_user_proxy_t up;

    if (!conf->tpc_credential_forward) {
        return NGX_OK;
    }

    webdav_tpc_user_proxy_resolve(r, conf, &up);
    if (up.deny) {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    pl->user_cert = up.have ? up.cert_path : NULL;
    pl->user_key  = up.have ? up.key_path  : NULL;
    return NGX_OK;
}

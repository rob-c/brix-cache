/*
 * dashboard/config_download_classify.c - fail-closed directive classification.
 *
 * Split verbatim from config_download.c: the curated secret denylist, the
 * forward-looking secret-name substring net, the non-secret exceptions, the
 * safe stock-nginx allowlist, and the case-insensitive name-matching helpers
 * that drive the fail-closed keep/redact decision. See config_download.c for
 * the full security model.
 */

#include "dashboard_http.h"
#include "core/http/http_headers.h"   /* brix_http_source_offer (AGPL sec.13) */
#include "core/compat/cstr.h"         /* brix_str_cbuf */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config_download_internal.h"

/*
 * Secret directives whose value MUST always be masked, even though some begin
 * with "brix_" (which the fail-closed core would otherwise pass through). This
 * is belt-and-suspenders: the secret-name net below also catches all of these
 * except brix_webdav_proxy_auth (whose name carries no secret keyword), so
 * that one in particular relies on this list.
 */
static const char *const dashboard_secret_directives[] = {
    "brix_dashboard_password",
    "brix_dashboard_users",
    "brix_admin_secret",
    "brix_macaroon_secret",
    "brix_macaroon_secret_old",
    "brix_webdav_macaroon_secret",
    "brix_webdav_macaroon_secret_old",
    "brix_s3_access_key",
    "brix_s3_secret_key",
    "brix_tpc_outbound_client_secret",
    "brix_tpc_outbound_bearer_file",
    "brix_webdav_tpc_token_client_secret",
    "brix_webdav_proxy_auth",
    /* brix_mirror_token is an inline bearer credential whose name carries no
     * secret keyword the substring net catches ("token" is excluded there so
     * the non-secret token_issuer/audience/endpoint stay visible) — list it
     * explicitly, like brix_webdav_proxy_auth above. */
    "brix_mirror_token",
    "brix_upstream_token_file",
    "brix_certificate_key",
    "brix_webdav_tpc_key",
    "brix_webdav_tpc_cert",
    "brix_sss_keytab",
    "brix_cms_server_sss_keytab",
    "brix_krb5_keytab",
    "brix_token_jwks",
    "brix_webdav_token_jwks",
    /* stock nginx secret-bearing directives that may share the same file */
    "ssl_certificate_key",
    "ssl_password_file",
    "ssl_session_ticket_key",
    "proxy_ssl_password_file",
    "proxy_ssl_certificate_key",
    NULL
};

/*
 * Substrings that, if present in a (lowercased) directive name, mark it secret.
 * This is the forward-looking net: a NEW secret directive added later whose name
 * follows the project convention is masked automatically, with no code change.
 */
static const char *const dashboard_secret_name_substrings[] = {
    "secret", "passwd", "password", "passphrase", "keytab", "privatekey",
    "private_key", "accesskey", "access_key", "secretkey", "secret_key",
    "apikey", "api_key", "client_secret", "credential", "bearer", "macaroon",
    "hmac", "jwks",
    NULL
};

/*
 * Names that MATCH the secret net by substring but are demonstrably NOT secret
 * (public identifiers / numbers / booleans). Listed so the export stays useful;
 * the explicit denylist always overrides this, so nothing secret can be
 * un-masked here.
 */
static const char *const dashboard_secret_exceptions[] = {
    "brix_token_issuer",
    "brix_token_audience",
    "brix_token_jwks_refresh_interval",
    "brix_token_cache",
    "brix_webdav_token_issuer",
    "brix_webdav_token_audience",
    "brix_webdav_token_introspect_ttl",
    "brix_webdav_token_introspect_loc",
    "brix_webdav_token_introspect_fail_open",
    NULL
};

/*
 * Stock (non-xrootd) nginx directives whose values are safe to show. Structural
 * keywords and common operational settings only - deliberately conservative.
 * Anything not here (and not an brix_* non-secret directive) is redacted.
 */
static const char *const dashboard_safe_stock_directives[] = {
    "user", "worker_processes", "worker_connections", "worker_rlimit_nofile",
    "pid", "daemon", "master_process", "events", "use", "multi_accept",
    "http", "stream", "server", "location", "upstream", "types", "include_off",
    "default_type", "server_name", "listen", "root", "alias", "index",
    "sendfile", "tcp_nopush", "tcp_nodelay", "keepalive_timeout",
    "keepalive_requests", "client_max_body_size", "client_body_buffer_size",
    "client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path",
    "uwsgi_temp_path", "scgi_temp_path", "output_buffers", "thread_pool",
    "access_log", "error_log", "log_format", "log_not_found", "autoindex",
    "gzip", "gzip_types", "gzip_min_length", "dav_methods", "dav_ext_methods",
    "ssl_certificate", "ssl_protocols", "ssl_ciphers",
    "ssl_prefer_server_ciphers", "ssl_verify_client", "ssl_verify_depth",
    "ssl_buffer_size", "ssl_session_cache", "ssl_session_timeout",
    "ssl_conf_command", "ssl_ecdh_curve", "ssl_dhparam", "ssl_trusted_certificate",
    "ssl_client_certificate", "ssl_crl", "resolver", "resolver_timeout",
    "limit_rate", "limit_conn", "limit_req", "expires", "etag", "charset",
    "merge_slashes", "server_tokens", "reset_timedout_connection",
    "send_timeout", "proxy_connect_timeout", "proxy_read_timeout",
    "proxy_send_timeout", "proxy_buffering", "proxy_request_buffering",
    "underscores_in_headers", "large_client_header_buffers",
    NULL
};

/* lowercase one ASCII byte. */
static u_char dashboard_lc(u_char c)
{
    return (c >= 'A' && c <= 'Z') ? (u_char) (c - 'A' + 'a') : c;
}

/* Case-insensitive compare of [name,len) against a NUL-terminated literal. */
ngx_uint_t
dashboard_name_eq(const u_char *name, size_t len, const char *lit)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (lit[i] == '\0' || dashboard_lc(name[i]) != (u_char) lit[i]) {
            return 0;
        }
    }
    return lit[len] == '\0';
}

/* Is [name,len) one of the NULL-terminated literals in `set`? */
static ngx_uint_t
dashboard_name_in(const u_char *name, size_t len, const char *const *set)
{
    size_t i;

    for (i = 0; set[i] != NULL; i++) {
        if (dashboard_name_eq(name, len, set[i])) {
            return 1;
        }
    }
    return 0;
}

/* Does the lowercased [name,len) contain `sub` (NUL-terminated, lowercase)? */
static ngx_uint_t
dashboard_name_contains(const u_char *name, size_t len, const char *sub)
{
    size_t sublen = ngx_strlen(sub);
    size_t i, j;

    if (sublen == 0 || sublen > len) {
        return 0;
    }
    for (i = 0; i + sublen <= len; i++) {
        for (j = 0; j < sublen; j++) {
            if (dashboard_lc(name[i + j]) != (u_char) sub[j]) {
                break;
            }
        }
        if (j == sublen) {
            return 1;
        }
    }
    return 0;
}

/* True when the directive name marks a secret (denylist OR name net), after
 * subtracting the explicit non-secret exceptions. */
static ngx_uint_t
dashboard_name_is_secret(const u_char *name, size_t len)
{
    size_t i;

    if (dashboard_name_in(name, len, dashboard_secret_directives)) {
        return 1;
    }
    if (dashboard_name_in(name, len, dashboard_secret_exceptions)) {
        return 0;
    }
    for (i = 0; dashboard_secret_name_substrings[i] != NULL; i++) {
        if (dashboard_name_contains(name, len, dashboard_secret_name_substrings[i])) {
            return 1;
        }
    }
    /* trailing "_key" or a bare "key" directive (e.g. ...tpc_key) */
    if (len == 3 && dashboard_name_eq(name, len, "key")) {
        return 1;
    }
    if (len >= 4 && dashboard_name_eq(name + (len - 4), 4, "_key")) {
        return 1;
    }
    return 0;
}

/*
 * Fail-closed value-keep decision for a directive name.
 * Keep (show value) ONLY when: not secret AND (a project brix_* directive OR a
 * safe stock directive). Everything else -> redact the value.
 */
ngx_uint_t
dashboard_keep_value(const u_char *name, size_t len)
{
    if (dashboard_name_is_secret(name, len)) {
        return 0;
    }
    if (len >= 5 && dashboard_name_eq(name, 5, "brix_")) {
        return 1;
    }
    if (dashboard_name_in(name, len, dashboard_safe_stock_directives)) {
        return 1;
    }
    return 0;
}

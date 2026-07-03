/*
 * net_target.h — shared external transfer target parser and SSRF policy.
 *
 * Centralises URL parsing and DNS-based address classification for all
 * outbound connections made by the module: native root:// TPC, WebDAV
 * HTTP-TPC (curl), and any future S3 remote-copy feature.
 *
 * Two public helpers:
 *   brix_net_target_parse()     — split URL into scheme/host/port/path
 *   brix_net_target_check_dns() — resolve host and reject prohibited addrs
 *
 * check_dns() calls getaddrinfo(), which blocks.  It MUST be called only
 * from a background thread (ngx_thread_pool_run or equivalent), never from
 * the nginx event-loop worker.
 */

#ifndef BRIX_NET_TARGET_H
#define BRIX_NET_TARGET_H

#include <ngx_http.h>
#include <stdint.h>
#include <sys/socket.h>

/*
 * Parsed view of an outbound URL.  All ngx_str_t fields point into the
 * original URL buffer — no pool allocation is performed by the parser.
 * The caller must keep the original buffer alive while this struct is used.
 */
typedef struct {
    ngx_str_t  raw_url;  /* the full original URL */
    ngx_str_t  scheme;   /* e.g. "https", "root" (no trailing colon) */
    ngx_str_t  host;     /* hostname or IP literal (no brackets for IPv6) */
    ngx_str_t  path;     /* everything from the first "/" onward, or empty */
    uint16_t   port;     /* 0 when not explicitly present in the URL */
    ngx_flag_t has_port; /* 1 when port was explicitly present */
} brix_net_target_t;

/*
 * Policy controlling which destinations are acceptable.
 *
 * require_https:       1 → reject any non-https scheme URL
 * allow_root_scheme:   1 → also accept root:// URLs (used by native TPC)
 * allow_local:         0 → reject loopback (127/8, ::1) and link-local
 * allow_private:       0 → reject RFC-1918 (10/8, 172.16/12, 192.168/16)
 *                         and IPv6 ULA (fc00::/7)
 * default_https_port:  port substituted when URL has no port and scheme=https
 * default_root_port:   port substituted when URL has no port and scheme=root
 */
typedef struct {
    ngx_flag_t require_https;
    ngx_flag_t allow_root_scheme;
    ngx_flag_t allow_local;
    ngx_flag_t allow_private;
    uint16_t   default_https_port;
    uint16_t   default_root_port;
} brix_net_target_policy_t;

/*
 * brix_net_target_parse — split a URL string into its components.
 *
 * The pool parameter is accepted for API consistency but not used; all
 * fields in *out point into url->data.  Returns NGX_OK on success.
 * On failure writes a NUL-terminated message into err[0..errsz) and
 * returns NGX_ERROR.
 *
 * Recognised URL forms:
 *   scheme://host/path
 *   scheme://host:port/path
 *   scheme://[ipv6addr]:port/path
 */
ngx_int_t brix_net_target_parse(ngx_pool_t *pool,
    const ngx_str_t *url, brix_net_target_t *out,
    char *err, size_t errsz);

/*
 * brix_net_target_check_addr — classify a single resolved sockaddr.
 *
 * Returns NGX_ERROR when the address is in a prohibited range under policy,
 * NGX_OK otherwise.  Can be called from any context (no DNS, no blocking).
 * Used by native TPC connect loop to check each resolved address inline.
 */
ngx_int_t brix_net_target_check_addr(const struct sockaddr *sa,
    const brix_net_target_policy_t *policy,
    char *err, size_t errsz);

/*
 * brix_net_target_check_dns — resolve host and verify against policy.
 *
 * Calls getaddrinfo(3) on target->host (BLOCKING — call from thread only).
 * Rejects the target if any resolved address is in a prohibited range under
 * the given policy.  Returns NGX_OK when all addresses are permitted.
 * On rejection writes a NUL-terminated message into err[0..errsz).
 */
ngx_int_t brix_net_target_check_dns(
    const brix_net_target_t *target,
    const brix_net_target_policy_t *policy,
    char *err, size_t errsz);

/*
 * brix_net_target_check_dns_pin — like check_dns, but also returns the first
 * permitted resolved address as a numeric string in out_ip[0..out_ipsz).
 *
 * Closes the DNS-rebind TOCTOU window: the caller validates and resolves once,
 * then pins out_ip into the transfer agent (e.g. curl CURLOPT_RESOLVE) so the
 * connection target cannot differ from the address that passed policy.  Same
 * BLOCKING/thread-only contract as check_dns().  Returns NGX_OK with out_ip
 * filled, NGX_ERROR otherwise (err filled).
 */
ngx_int_t brix_net_target_check_dns_pin(
    const brix_net_target_t *target,
    const brix_net_target_policy_t *policy,
    char *out_ip, size_t out_ipsz,
    char *err, size_t errsz);

/*
 * brix_net_host_chars_valid — reject host strings that could inject control
 * bytes or alternate schemes into a redirect/registration string.
 *
 * Allows only the characters legal in a hostname or IPv4/IPv6 literal:
 * [A-Za-z0-9.:-].  Rejects empty, anything with '/', whitespace, NUL, or any
 * byte outside that set (so "evil\r\nLocation:" or "http://x" never reach a
 * client that parses a redirect host).  Returns 1 if valid, 0 otherwise.
 */
int brix_net_host_chars_valid(const char *host, size_t len);

#endif /* BRIX_NET_TARGET_H */

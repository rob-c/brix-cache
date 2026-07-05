/* proxy_env.h — resolve an HTTP(S) proxy from the standard environment variables
 * (pure C, no ngx, no alloc).
 *
 * WHAT: given a target (scheme, host, port), decide whether a forward/CONNECT
 *       proxy from http_proxy / https_proxy / all_proxy applies, honouring
 *       no_proxy. One report line per process makes the choice visible.
 * WHY:  every brix client (the libcurl-based brixcvmfs AND the hand-rolled
 *       root:///https tools via sock.c) must transparently use a site's env
 *       proxy for external connectivity — and say so.
 * HOW:  lowercase var wins over UPPERCASE; https targets prefer https_proxy,
 *       everything else http_proxy, both falling back to all_proxy; no_proxy is a
 *       comma/space list matched by exact host, dotted-suffix, or "*". Per the
 *       agreed policy the env proxy OVERRIDES any in-config proxy, but no_proxy
 *       still forces a direct connection. Fixed buffers, no allocation.
 */
#ifndef BRIX_PROXY_ENV_H
#define BRIX_PROXY_ENV_H

#include <stddef.h>

typedef struct {
    int  active;         /* 1 = a proxy applies; 0 = go direct */
    char host[256];
    int  port;
    char url[300];       /* "http://<host>:<port>" (for CURLOPT_PROXY) */
    char source[24];     /* which env var: "http_proxy"/"https_proxy"/"all_proxy" */
} brix_proxy_t;

/* Resolve the proxy for a target. `scheme` may be NULL/""; when it is "https" or
 * "roots" (or port 443) https_proxy is preferred. Returns 1 and fills *out when a
 * proxy applies, 0 for direct. */
int brix_proxy_resolve(const char *scheme, const char *host, int port, brix_proxy_t *out);

/* Print (once per process, to stderr) that `p` is being used for `host:port`. */
void brix_proxy_report(const brix_proxy_t *p, const char *host, int port);

#endif /* BRIX_PROXY_ENV_H */

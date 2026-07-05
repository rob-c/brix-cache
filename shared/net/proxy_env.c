/* proxy_env.c — resolve an HTTP(S) proxy from the environment. See proxy_env.h. */
#include "net/proxy_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* lowercase var wins; fall back to the UPPERCASE form. */
static const char *getenv_ci(const char *lower, const char *upper) {
    const char *v = getenv(lower);
    if (v != NULL && *v != '\0') return v;
    v = getenv(upper);
    return (v != NULL && *v != '\0') ? v : NULL;
}

/* Does `host` match a single no_proxy entry? "*" matches all; a bare or
 * dotted-suffix entry matches the host or any subdomain. */
static int no_proxy_entry_matches(const char *host, const char *entry) {
    if (entry[0] == '*') return 1;
    while (*entry == '.') entry++;                 /* strip leading dot */
    size_t hl = strlen(host), el = strlen(entry);
    if (el == 0) return 0;
    if (hl == el) return strcasecmp(host, entry) == 0;
    if (hl > el)  return host[hl - el - 1] == '.' && strcasecmp(host + hl - el, entry) == 0;
    return 0;
}

static int host_in_no_proxy(const char *host) {
    const char *np = getenv_ci("no_proxy", "NO_PROXY");
    if (np == NULL) return 0;

    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", np);
    for (char *p = buf; *p; ) {
        while (*p == ',' || *p == ' ' || *p == '\t') p++;   /* skip separators */
        char *start = p;
        while (*p && *p != ',' && *p != ' ' && *p != '\t') p++;
        if (p > start) {
            char save = *p; *p = '\0';
            int m = no_proxy_entry_matches(host, start);
            *p = save;
            if (m) return 1;
        }
    }
    return 0;
}

/* Parse "[scheme://]host[:port][/...]" into out->host/port (default port 80). */
static int parse_proxy_url(const char *v, brix_proxy_t *out) {
    const char *p = v;
    if (strncmp(p, "http://", 7) == 0)  p += 7;
    else if (strncmp(p, "https://", 8) == 0) p += 8;
    else { const char *s = strstr(p, "://"); if (s) p = s + 3; }

    char hostport[256];
    size_t n = 0;
    while (p[n] && p[n] != '/' && n < sizeof(hostport) - 1) { hostport[n] = p[n]; n++; }
    hostport[n] = '\0';
    if (n == 0) return -1;

    char *colon = strrchr(hostport, ':');
    if (colon) { *colon = '\0'; out->port = atoi(colon + 1); }
    else       { out->port = 80; }
    if (out->port <= 0) out->port = 80;
    snprintf(out->host, sizeof(out->host), "%s", hostport);
    return out->host[0] ? 0 : -1;
}

int brix_proxy_resolve(const char *scheme, const char *host, int port, brix_proxy_t *out) {
    memset(out, 0, sizeof(*out));

    int https = (port == 443)
             || (scheme && (strcmp(scheme, "https") == 0 || strcmp(scheme, "roots") == 0));

    const char *v = NULL, *src = NULL;
    if (https && (v = getenv_ci("https_proxy", "HTTPS_PROXY")) != NULL) src = "https_proxy";
    if (v == NULL && (v = getenv_ci("http_proxy", "HTTP_PROXY")) != NULL) src = "http_proxy";
    if (v == NULL && (v = getenv_ci("all_proxy", "ALL_PROXY")) != NULL)  src = "all_proxy";
    if (v == NULL) return 0;

    if (host != NULL && host_in_no_proxy(host)) return 0;
    if (parse_proxy_url(v, out) != 0) return 0;

    out->active = 1;
    snprintf(out->source, sizeof(out->source), "%s", src);
    snprintf(out->url, sizeof(out->url), "http://%s:%d", out->host, out->port);
    return 1;
}

void brix_proxy_report(const brix_proxy_t *p, const char *host, int port) {
    static int reported = 0;
    if (reported || p == NULL || !p->active) return;
    reported = 1;
    fprintf(stderr,
        "brix: using HTTP proxy %s:%d (from $%s) for external connectivity (e.g. %s:%d)\n",
        p->host, p->port, p->source, host ? host : "?", port);
}

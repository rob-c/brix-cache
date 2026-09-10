/*
 * resolv_conf.h — resolv.conf(5) parser (phase-116 W1).
 *
 * WHAT: Parses the resolver configuration file the process can see
 *       (nameserver / search / domain / options ndots,timeout,attempts,rotate)
 *       plus the LOCALDOMAIN and RES_OPTIONS environment overrides, into a
 *       fixed-size, allocation-free struct with glibc's defaults pre-applied.
 * WHY:  nginx open-source never reads resolv.conf — every `resolver` directive
 *       is hand-written.  BriX fills nginx's resolver slots from this struct
 *       (resolver_build.c) and drives search/ndots semantics (resolve.c), so
 *       one file is the single truth for "what the host resolver would do".
 * HOW:  Pure C, no nginx headers — the same code is compiled standalone by
 *       resolv_conf_unittest.c.  Parsing is line-oriented; unknown keywords and
 *       options are ignored (glibc behaviour); limits match glibc (3
 *       nameservers, 6 search domains, ndots<=15, timeout<=30, attempts<=5).
 *       A missing or unreadable file yields the glibc defaults (127.0.0.1,
 *       ndots:1, timeout:5, attempts:2) and reports `defaulted = 1`.
 */
#ifndef BRIX_NET_DNS_RESOLV_CONF_H
#define BRIX_NET_DNS_RESOLV_CONF_H

#include <stddef.h>

#define BRIX_RESOLV_MAX_NS       3
#define BRIX_RESOLV_MAX_SEARCH   6
#define BRIX_RESOLV_NS_LEN       64    /* longest IPv6 literal + NUL */
#define BRIX_RESOLV_DOMAIN_LEN   256   /* RFC 1035 name limit + NUL */
#define BRIX_RESOLV_DEFAULT_PATH "/etc/resolv.conf"

typedef struct {
    char      nameservers[BRIX_RESOLV_MAX_NS][BRIX_RESOLV_NS_LEN];
    unsigned  nnameservers;
    char      search[BRIX_RESOLV_MAX_SEARCH][BRIX_RESOLV_DOMAIN_LEN];
    unsigned  nsearch;
    unsigned  ndots;        /* options ndots:N   (default 1, max 15) */
    unsigned  timeout;      /* options timeout:N (seconds, default 5, max 30) */
    unsigned  attempts;     /* options attempts:N (default 2, max 5) */
    unsigned  rotate:1;     /* options rotate */
    unsigned  defaulted:1;  /* file unreadable: glibc defaults in force */
    unsigned  env_search:1; /* LOCALDOMAIN replaced the file's search list */
} brix_resolv_conf_t;

/* Reset *rc to the glibc defaults (one nameserver 127.0.0.1, empty search
 * list, ndots 1, timeout 5, attempts 2, rotate off). */
void brix_resolv_conf_defaults(brix_resolv_conf_t *rc);

/* Parse `len` bytes of resolv.conf text into *rc (which must already hold the
 * defaults).  Never fails: malformed lines are skipped like glibc does.  A
 * `nameserver` line clears the default 127.0.0.1 on first use. */
void brix_resolv_conf_parse_text(brix_resolv_conf_t *rc, const char *text,
    size_t len);

/* Apply the LOCALDOMAIN (search list) and RES_OPTIONS (options) environment
 * overrides; either pointer may be NULL to mean "unset". */
void brix_resolv_conf_apply_env(brix_resolv_conf_t *rc,
    const char *localdomain, const char *res_options);

/* Load `path` (NULL = /etc/resolv.conf) with defaults + env applied.  Returns
 * 0 when the file was read, -1 when it was missing/unreadable and the defaults
 * are in force (rc->defaulted is set either way). */
int brix_resolv_conf_load(brix_resolv_conf_t *rc, const char *path);

/* Number of label separators ('.') in a hostname, ignoring a trailing dot. */
unsigned brix_resolv_conf_count_dots(const char *name, size_t len);

#endif /* BRIX_NET_DNS_RESOLV_CONF_H */

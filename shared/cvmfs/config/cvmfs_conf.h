/* cvmfs_conf.h — stock CVMFS_* config-file parsing (pure C, no ngx).
 *
 * WHAT: parse the shell-style KEY=value cascade a stock CVMFS client reads
 *       (default.conf, default.d entries, domain.d/<domain>.conf,
 *       config.d/<repo>.conf, default.local) and resolve the keys brixcvmfs
 *       needs into a repo config + failover engine.
 * WHY:  drop-in parity — an operator's existing /etc/cvmfs setup (server list,
 *       proxy hierarchy, key dir, timeouts) just works.
 * HOW:  a last-wins KEY→value store; resolvers expand CVMFS_SERVER_URL templating
 *       (@fqrn@/@org@/@fqdn@) and CVMFS_HTTP_PROXY groups ('|' = load-balance
 *       within a group, ';' = failover between groups, DIRECT = no proxy) straight
 *       into the shared failover engine's proxy groups + host list. libc only.
 */
#ifndef BRIX_CVMFS_CONF_H
#define BRIX_CVMFS_CONF_H

#include <stddef.h>
#include "cvmfs/config/repo.h"
#include "cvmfs/failover/failover.h"

#define CVMFS_CONF_MAX_KEYS 128

typedef struct {
    char key[CVMFS_CONF_MAX_KEYS][128];
    char val[CVMFS_CONF_MAX_KEYS][512];
    size_t n;
} cvmfs_conf_t;

void cvmfs_conf_init(cvmfs_conf_t *c);

/* Merge KEY=value lines from a text buffer (last value wins). Returns keys added. */
int cvmfs_conf_parse_text(cvmfs_conf_t *c, const char *text, size_t len);

/* Merge a file if it exists (a missing file is not an error). Returns 0/-1. */
int cvmfs_conf_parse_file(cvmfs_conf_t *c, const char *path);

/* Walk the stock cascade for `fqrn` under `etc_root` (default "/etc/cvmfs" if
 * NULL): default.conf, then default.d entries, domain.d/<domain>.conf,
 * config.d/<fqrn>.conf, default.local. Missing files are skipped. */
int cvmfs_conf_load_cascade(cvmfs_conf_t *c, const char *etc_root, const char *fqrn);

/* Latest value for `key`, or NULL. */
const char *cvmfs_conf_get(const cvmfs_conf_t *c, const char *key);

/* Expand @fqrn@/@org@/@fqdn@ in `tmpl` for `fqrn` into `out`. Returns 0/-1. */
int cvmfs_conf_expand(const char *tmpl, const char *fqrn, char *out, size_t outlen);

/* Populate `rc` (timeouts, master key path) and `fo` (server hosts as full
 * repo-URL prefixes + proxy groups) from the parsed config for `fqrn`. Returns
 * the number of hosts added, or -1 on error. Applies stock defaults for anything
 * unset (DIRECT proxy, TIMEOUT=5/DIRECT=10). */
int cvmfs_conf_apply(const cvmfs_conf_t *c, const char *fqrn,
                     cvmfs_repo_config_t *rc, cvmfs_failover_t *fo);

#endif /* BRIX_CVMFS_CONF_H */

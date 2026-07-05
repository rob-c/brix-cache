/* repo.h — CVMFS repository trust + endpoint configuration (pure C).
 *
 * WHAT: the resolved set a mount needs — FQRN, Stratum server URLs, proxy
 *       hierarchy, master public-key path, timeouts.
 * WHY:  one struct the failover engine (SP-B) and the FUSE driver (SP-F)
 *       consume; CVMFS_* config-file parsing (SP-F) fills the same struct.
 * HOW:  the FQRN "<repo>.<domain>" derives stock defaults; no allocation,
 *       fixed small arrays.
 */
#ifndef BRIX_CVMFS_REPO_H
#define BRIX_CVMFS_REPO_H

#include <stddef.h>

typedef struct {
    char   name[256];
    char   server_urls[8][256];  size_t n_servers;
    char   proxies[8][256];      size_t n_proxies;
    char   master_pub_path[512];
    long   timeout_s;            /* proxied connect/stall ceiling */
    long   timeout_direct_s;     /* DIRECT connect/stall ceiling */
} cvmfs_repo_config_t;

/* Derive stock defaults (master key path, timeouts) from a "<repo>.<domain>"
 * FQRN. Returns 0 on success, -1 if the name has no domain component. */
int cvmfs_repo_config_defaults(const char *repo_name, cvmfs_repo_config_t *out);

/* Append a Stratum server URL. 0 on success, -1 if full/too long. */
int cvmfs_repo_config_add_server(cvmfs_repo_config_t *c, const char *url);

/* Append a proxy (accepts "DIRECT"). 0 on success, -1 if full/too long. */
int cvmfs_repo_config_add_proxy(cvmfs_repo_config_t *c, const char *proxy);

#endif /* BRIX_CVMFS_REPO_H */

/* repo.c — CVMFS repository trust + endpoint configuration. See repo.h. */
#include "cvmfs/config/repo.h"

#include <string.h>
#include <stdio.h>

int cvmfs_repo_config_defaults(const char *repo_name, cvmfs_repo_config_t *out) {
    memset(out, 0, sizeof(*out));

    const char *dot = strchr(repo_name, '.');
    if (dot == NULL || dot[1] == '\0') return -1;   /* need <repo>.<domain> */

    size_t nl = strlen(repo_name);
    if (nl >= sizeof(out->name)) return -1;
    memcpy(out->name, repo_name, nl + 1);

    snprintf(out->master_pub_path, sizeof(out->master_pub_path),
             "/etc/cvmfs/keys/%s.pub", dot + 1);
    out->timeout_s = 5;
    out->timeout_direct_s = 10;
    return 0;
}

int cvmfs_repo_config_add_server(cvmfs_repo_config_t *c, const char *url) {
    size_t len = strlen(url);
    if (c->n_servers >= 8 || len >= sizeof(c->server_urls[0])) return -1;
    memcpy(c->server_urls[c->n_servers++], url, len + 1);   /* bound proven above */
    return 0;
}

int cvmfs_repo_config_add_proxy(cvmfs_repo_config_t *c, const char *proxy) {
    size_t len = strlen(proxy);
    if (c->n_proxies >= 8 || len >= sizeof(c->proxies[0])) return -1;
    memcpy(c->proxies[c->n_proxies++], proxy, len + 1);     /* bound proven above */
    return 0;
}

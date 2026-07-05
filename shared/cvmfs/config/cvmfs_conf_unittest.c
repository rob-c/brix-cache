/*
 * cvmfs_conf_unittest.c — tests for stock CVMFS_* config parsing + resolution.
 *
 * gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_conf_ut \
 *     shared/cvmfs/config/cvmfs_conf_unittest.c shared/cvmfs/config/cvmfs_conf.c \
 *     shared/cvmfs/config/repo.c shared/cvmfs/failover/failover.c && /tmp/cvmfs_conf_ut
 */
#include "cvmfs/config/cvmfs_conf.h"

#include <stdio.h>
#include <string.h>

static int g_checks, g_failed;
#define CHECK(c,n) do{ g_checks++; if(c){printf("  ok   %s\n",n);} \
    else{printf("  FAIL %s (line %d)\n",n,__LINE__); g_failed++;} }while(0)

int main(void) {
    const char cfg[] =
        "# a stock-style config\n"
        "CVMFS_SERVER_URL=\"http://s1.cern.ch/cvmfs/@fqrn@;http://s2.cern.ch/cvmfs/@fqrn@\"\n"
        "export CVMFS_HTTP_PROXY='http://pa:3128|http://pb:3128;DIRECT'\n"
        "CVMFS_KEYS_DIR=/etc/cvmfs/keys\n"
        "CVMFS_TIMEOUT=7\n"
        "CVMFS_TIMEOUT = 3\n"           /* last wins + spaces around = */
        "CVMFS_TIMEOUT_DIRECT=20\n";

    cvmfs_conf_t c; cvmfs_conf_init(&c);
    cvmfs_conf_parse_text(&c, cfg, sizeof(cfg) - 1);

    CHECK(strcmp(cvmfs_conf_get(&c, "CVMFS_TIMEOUT"), "3") == 0, "last-wins override");
    CHECK(cvmfs_conf_get(&c, "CVMFS_KEYS_DIR") != NULL, "quoted/plain values parsed");

    char url[256];
    cvmfs_conf_expand("http://x/cvmfs/@fqrn@", "atlas.cern.ch", url, sizeof(url));
    CHECK(strcmp(url, "http://x/cvmfs/atlas.cern.ch") == 0, "@fqrn@ expansion");
    cvmfs_conf_expand("@org@.@fqdn@", "atlas.cern.ch", url, sizeof(url));
    CHECK(strcmp(url, "atlas.cern.ch") == 0, "@org@/@fqdn@ expansion");

    cvmfs_repo_config_t rc; memset(&rc, 0, sizeof(rc));
    cvmfs_failover_t fo; cvmfs_failover_init(&fo, 60);
    int hosts = cvmfs_conf_apply(&c, "atlas.cern.ch", &rc, &fo);

    CHECK(hosts == 2 && fo.n_hosts == 2
          && strcmp(fo.hosts[0].url, "http://s1.cern.ch/cvmfs/atlas.cern.ch") == 0,
          "server URLs expanded into failover hosts");
    CHECK(fo.n_proxies == 3
          && fo.proxies[0].group == 0 && fo.proxies[1].group == 0
          && fo.proxies[2].group == 1 && strcmp(fo.proxies[2].url, "DIRECT") == 0,
          "proxy groups: '|' same group, ';' next group, DIRECT");
    CHECK(rc.timeout_s == 3 && rc.timeout_direct_s == 20, "timeouts applied");
    CHECK(strcmp(rc.master_pub_path, "/etc/cvmfs/keys/cern.ch.pub") == 0,
          "keys dir → master pub path");

    /* unset proxy → DIRECT default */
    cvmfs_conf_t c2; cvmfs_conf_init(&c2);
    cvmfs_conf_parse_text(&c2, "CVMFS_SERVER_URL=http://only/cvmfs/@fqrn@\n", 40);
    cvmfs_failover_t fo2; cvmfs_failover_init(&fo2, 60);
    cvmfs_repo_config_t rc2; memset(&rc2, 0, sizeof(rc2));
    cvmfs_conf_apply(&c2, "x.y", &rc2, &fo2);
    CHECK(fo2.n_proxies == 1 && strcmp(fo2.proxies[0].url, "DIRECT") == 0,
          "no proxy config → DIRECT");

    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

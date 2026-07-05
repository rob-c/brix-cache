/*
 * proxy_env_unittest.c — tests for env-proxy resolution + no_proxy matching.
 *
 * gcc -Wall -Wextra -Werror -I shared -o /tmp/proxy_env_ut \
 *     shared/net/proxy_env_unittest.c shared/net/proxy_env.c && /tmp/proxy_env_ut
 */
#include "net/proxy_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks, g_failed;
#define CHECK(c,n) do{ g_checks++; if(c){printf("  ok   %s\n",n);} \
    else{printf("  FAIL %s (line %d)\n",n,__LINE__); g_failed++;} }while(0)

static void clear_env(void) {
    unsetenv("http_proxy"); unsetenv("HTTP_PROXY");
    unsetenv("https_proxy"); unsetenv("HTTPS_PROXY");
    unsetenv("all_proxy"); unsetenv("ALL_PROXY");
    unsetenv("no_proxy"); unsetenv("NO_PROXY");
}

int main(void) {
    brix_proxy_t p;

    clear_env();
    CHECK(brix_proxy_resolve("http", "s1.cern.ch", 80, &p) == 0, "no env → direct");

    clear_env();
    setenv("http_proxy", "http://proxy.site:3128", 1);
    CHECK(brix_proxy_resolve("http", "s1.cern.ch", 80, &p) == 1
          && strcmp(p.host, "proxy.site") == 0 && p.port == 3128
          && strcmp(p.source, "http_proxy") == 0, "http_proxy parsed");
    CHECK(strcmp(p.url, "http://proxy.site:3128") == 0, "proxy url built");

    clear_env();
    setenv("http_proxy", "proxy.bare:8080/", 1);   /* no scheme, trailing slash */
    CHECK(brix_proxy_resolve("root", "eos.cern.ch", 1094, &p) == 1
          && strcmp(p.host, "proxy.bare") == 0 && p.port == 8080,
          "scheme-less proxy + root:// target");

    clear_env();
    setenv("http_proxy", "http://ph:1", 1);
    setenv("https_proxy", "http://ps:2", 1);
    CHECK(brix_proxy_resolve("https", "x", 443, &p) == 1 && p.port == 2
          && strcmp(p.source, "https_proxy") == 0, "https target prefers https_proxy");
    CHECK(brix_proxy_resolve("http", "x", 80, &p) == 1 && p.port == 1
          && strcmp(p.source, "http_proxy") == 0, "http target uses http_proxy");

    clear_env();
    setenv("http_proxy", "http://ph:1", 1);
    setenv("no_proxy", "localhost,.cern.ch,internal.example", 1);
    CHECK(brix_proxy_resolve("http", "s1.cern.ch", 80, &p) == 0, "no_proxy dotted-suffix → direct");
    CHECK(brix_proxy_resolve("http", "cern.ch", 80, &p) == 0, "no_proxy bare domain → direct");
    CHECK(brix_proxy_resolve("http", "localhost", 80, &p) == 0, "no_proxy exact → direct");
    CHECK(brix_proxy_resolve("http", "s1.desy.de", 80, &p) == 1, "non-matching host → proxied");

    clear_env();
    setenv("http_proxy", "http://ph:1", 1);
    setenv("no_proxy", "*", 1);
    CHECK(brix_proxy_resolve("http", "anything", 80, &p) == 0, "no_proxy=* disables all");

    clear_env();
    setenv("all_proxy", "http://ap:9", 1);
    CHECK(brix_proxy_resolve("http", "x", 80, &p) == 1 && p.port == 9
          && strcmp(p.source, "all_proxy") == 0, "all_proxy fallback");

    clear_env();
    setenv("HTTP_PROXY", "http://upper:7", 1);     /* uppercase fallback */
    CHECK(brix_proxy_resolve("http", "x", 80, &p) == 1 && p.port == 7,
          "UPPERCASE var honored");

    clear_env();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

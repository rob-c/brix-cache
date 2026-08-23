#include "oci/challenge.h"
#include "oci/url.h"

#include <stdio.h>
#include <string.h>

static int failed;

#define CHECK(condition, name) do {                                      \
    if (!(condition)) {                                                  \
        fprintf(stderr, "FAIL: %s\n", name);                            \
        failed++;                                                        \
    }                                                                    \
} while (0)

int
main(void)
{
    brix_oci_challenge_t  challenge;
    brix_oci_url_t        url;
    char                  host[256];
    int                   port = 443;
    const char           *valid = "Bearer realm=\"https://auth.example/token\"," 
                                  "service=registry,scope=\"repo:a:pull\"";

    CHECK(brix_oci_challenge_parse(valid, strlen(valid), &challenge) == 0,
          "valid bearer challenge");
    CHECK(strcmp(challenge.service, "registry") == 0,
          "challenge token value");
    CHECK(brix_oci_challenge_parse("Basic realm=x", 13, &challenge) == -1,
          "wrong challenge scheme refused");
    CHECK(brix_oci_challenge_parse("Bearer service=x", 16, &challenge) == -1,
          "missing realm refused");

    CHECK(brix_oci_url_parse("https://registry.example:5000/v2", 32, &url) == 0,
          "registry URL parses");
    CHECK(strcmp(url.host, "registry.example") == 0 && url.port == 5000
          && url.tls == 1 && strcmp(url.path, "/v2") == 0,
          "registry URL fields");
    CHECK(brix_oci_url_authority("[::1]:5443", 10, host, sizeof(host), &port) == 0
          && strcmp(host, "::1") == 0 && port == 5443,
          "IPv6 authority parses");
    CHECK(brix_oci_url_parse("https://evil@registry.example/v2", 32, &url) == -1,
          "userinfo authority refused");
    CHECK(brix_oci_url_parse("https://registry.example/a//b", 29, &url) == -1,
          "empty path component refused");
    return failed == 0 ? 0 : 1;
}

/*
 * provider_unittest.c — standalone unit test for the SSI provider registry.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/ssi_provider_ut \
 *       src/ssi/provider_unittest.c src/ssi/provider.c src/ssi/ssi_service.c \
 *       src/ssi/svc_cta/cta_service.c src/ssi/svc_cta/cta_pb.c \
 *       src/ssi/svc_cta/cta_queue.c src/ssi/svc_cta/cta_exec.c \
 *       src/ssi/svc_cta/pb_wire.c && /tmp/ssi_provider_ut
 */
#include "provider.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static void test_known_service(void)
{
    xrootd_ssi_provider_t p;
    CHECK(xrootd_ssi_provider_lookup("echo", &p) == 1);
    CHECK(p.process != NULL);
    CHECK(strcmp(p.name, "echo") == 0);
}

static void test_unknown_service(void)
{
    xrootd_ssi_provider_t p;
    memset(&p, 0xff, sizeof(p));
    CHECK(xrootd_ssi_provider_lookup("nope", &p) == 0);
}

static void test_null_name(void)
{
    xrootd_ssi_provider_t p;
    CHECK(xrootd_ssi_provider_lookup(NULL, &p) == 0);
}

int main(void)
{
    test_known_service();
    test_unknown_service();
    test_null_name();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}

/*
 * test_sd_xroot_fwd_key.c — standalone unit test for the forwarding-proxy key
 * parser + permit allowlist (2.0 F5).  Built by tests/test_sd_xroot_fwd_key.py
 * with -DXRDPROTO_NO_NGX next to egress_guard.c and host_split.c.
 */
#include "fs/backend/xroot/sd_xroot_fwd_key.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int fails;

#define CHECK(cond) do { \
        if (!(cond)) { fails++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } \
    } while (0)

static void
expect_target(const char *key, const char *host, int port, int tls,
    const char *path)
{
    brix_sd_xroot_fwd_target_t t;
    int rc = brix_sd_xroot_fwd_parse_key(key, &t);

    if (rc != 0) {
        fails++;
        printf("FAIL parse %s -> errno %d (%s)\n", key, rc, strerror(rc));
        return;
    }
    CHECK(strcmp(t.host, host) == 0);
    CHECK(t.port == port);
    CHECK(t.tls == tls);
    CHECK(strcmp(t.path, path) == 0);
}

static void
expect_errno(const char *key, int want)
{
    brix_sd_xroot_fwd_target_t t;
    int rc = brix_sd_xroot_fwd_parse_key(key, &t);

    if (rc != want) {
        fails++;
        printf("FAIL parse %s -> %d, want %d\n", key, rc, want);
    }
}

static void
test_shapes(void)
{
    /* wire shape (what a root:// client sends) */
    expect_target("/root://origin.example.org:1094//data/f.bin",
                  "origin.example.org", 1094, 0, "/data/f.bin");
    /* VFS shape (brix_candidate_append_req collapsed the slash runs) */
    expect_target("/root:/origin.example.org:1094/data/f.bin",
                  "origin.example.org", 1094, 0, "/data/f.bin");
    expect_target("root://origin.example.org//f", "origin.example.org",
                  1094, 0, "/f");
    expect_target("/roots://sec.example.org:2094//f", "sec.example.org",
                  2094, 1, "/f");
    expect_target("/root://[::1]:1095//f", "::1", 1095, 0, "/f");
    expect_target("/root://[fe80::1]//f", "fe80::1", 1094, 0, "/f");
    expect_target("/root://h", "h", 1094, 0, "/");
    expect_target("/root://h/", "h", 1094, 0, "/");
    expect_target("/root://h//a//b", "h", 1094, 0, "/a//b");
    /* slash runs collapse before the driver sees the key, so a third slash
     * cannot mean "empty host": the next component IS the host */
    expect_target("/root:///f", "f", 1094, 0, "/");
}

static void
test_errors(void)
{
    expect_errno("/plain/file", ENOENT);
    expect_errno("/", ENOENT);
    expect_errno("", ENOENT);
    expect_errno("/:/h//f", ENOENT);
    expect_errno("/http://h//f", ENOTSUP);
    expect_errno("/xroot://h//f", ENOTSUP);
    expect_errno("/root://", EINVAL);
    expect_errno("/root://h:0//f", EINVAL);
    expect_errno("/root://h:70000//f", EINVAL);
    expect_errno("/root://h:abc//f", EINVAL);
    expect_errno("/root://[::1//f", EINVAL);
    expect_errno("/root://h%00x//f", EINVAL);
    expect_errno("/root://ho st//f", EINVAL);
    expect_errno("/root://h;x//f", EINVAL);
    expect_errno(NULL, EINVAL);
}

static void
test_too_long(void)
{
    char key[BRIX_SD_XROOT_FWD_PATH_MAX + 64];
    size_t n;

    memset(key, 'a', sizeof(key));
    memcpy(key, "/root://", 8);
    key[sizeof(key) - 1] = '\0';
    expect_errno(key, ENAMETOOLONG);

    n = strlen("/root://h//");
    memcpy(key, "/root://h//", n);
    memset(key + n, 'b', sizeof(key) - n - 1);
    key[sizeof(key) - 1] = '\0';
    expect_errno(key, ENAMETOOLONG);

    /* exactly fits: path buffer holds "/" + rest + NUL */
    key[n + BRIX_SD_XROOT_FWD_PATH_MAX - 2] = '\0';
    CHECK(brix_sd_xroot_fwd_parse_key(key,
              &(brix_sd_xroot_fwd_target_t){0}) == 0);
}

static void
test_permit(void)
{
    CHECK(brix_sd_xroot_fwd_host_permitted("a.example.org", "a.example.org"));
    CHECK(brix_sd_xroot_fwd_host_permitted("A.Example.ORG", "a.example.org"));
    CHECK(brix_sd_xroot_fwd_host_permitted(".example.org", "a.example.org"));
    CHECK(brix_sd_xroot_fwd_host_permitted(".example.org",
                                           "deep.a.example.org"));
    CHECK(brix_sd_xroot_fwd_host_permitted("x.org  .example.org",
                                           "a.example.org"));
    CHECK(brix_sd_xroot_fwd_host_permitted(" x.org y.org ", "y.org"));
    /* security-negatives: must fail closed */
    CHECK(!brix_sd_xroot_fwd_host_permitted("", "a.example.org"));
    CHECK(!brix_sd_xroot_fwd_host_permitted(NULL, "a.example.org"));
    CHECK(!brix_sd_xroot_fwd_host_permitted("   ", "a.example.org"));
    CHECK(!brix_sd_xroot_fwd_host_permitted(".example.org", "example.org"));
    CHECK(!brix_sd_xroot_fwd_host_permitted(".example.org",
                                            "notexample.org"));
    CHECK(!brix_sd_xroot_fwd_host_permitted("a.example.org",
                                            "a.example.org.evil"));
    CHECK(!brix_sd_xroot_fwd_host_permitted("a.example.org",
                                            "xa.example.org"));
    CHECK(!brix_sd_xroot_fwd_host_permitted("a.example.org", ""));
    CHECK(!brix_sd_xroot_fwd_host_permitted("a.example.org", NULL));
}

int
main(void)
{
    test_shapes();
    test_errors();
    test_too_long();
    test_permit();
    if (fails) {
        printf("%d FAILED\n", fails);
        return 1;
    }
    printf("ALL PASS\n");
    return 0;
}

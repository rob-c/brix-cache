/*
 * test_cache_open_nofollow.c — unit test for security fix #6 (O_NOFOLLOW on the
 * cache-hit open in read/open_resolved_file.c).
 *
 * The cache tree is server-managed, but a symlink planted in cache_root must
 * never be followed to a file OUTSIDE the cache when serving a cache hit. The fix
 * adds O_NOFOLLOW to that open(2). This reproduces the property end-to-end on the
 * filesystem: a symlink in a temp "cache" dir pointing at a secret file is
 *
 *   - FOLLOWED by a plain open()                     (the pre-fix behaviour), but
 *   - REFUSED (ELOOP) by open(..., O_NOFOLLOW|...)   (exactly the flags the fix uses),
 *
 * so the cache-hit path can no longer be tricked into serving the link target.
 */
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok: %s\n", msg); } \
    else { printf("  FAIL: %s\n", msg); g_fail = 1; } } while (0)

int main(void)
{
    char  dir[]    = "/tmp/xrd_cache_nofollow_XXXXXX";
    char  secret[512], link[512];
    int   fd;

    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    /* A "secret" file OUTSIDE what the cache should ever serve. */
    snprintf(secret, sizeof(secret), "%s/secret_target", dir);
    fd = open(secret, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("create secret"); return 1; }
    (void) write(fd, "TOPSECRET", 9);
    close(fd);

    /* A symlink standing in for a planted cache entry. */
    snprintf(link, sizeof(link), "%s/cache_entry", dir);
    if (symlink(secret, link) != 0) { perror("symlink"); return 1; }

    printf("[cache open] fix #6 — O_NOFOLLOW on the cache-hit open\n");

    /* Pre-fix behaviour: a plain open follows the symlink to the secret. */
    fd = open(link, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0, "plain open() follows the planted symlink (the pre-fix risk)");
    if (fd >= 0) close(fd);

    /* The fix: O_NOFOLLOW refuses the final-component symlink with ELOOP, so the
     * cache-hit open can never serve the link target. */
    fd = open(link, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd < 0 && errno == ELOOP,
          "open(O_NOFOLLOW) REFUSES the planted symlink (ELOOP)");
    if (fd >= 0) close(fd);

    /* Sanity: O_NOFOLLOW still opens a real regular cache file. */
    fd = open(secret, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0, "open(O_NOFOLLOW) still opens a regular (non-symlink) file");
    if (fd >= 0) close(fd);

    unlink(link);
    unlink(secret);
    rmdir(dir);

    printf(g_fail ? "cache O_NOFOLLOW test: FAIL\n" : "cache O_NOFOLLOW test: OK\n");
    return g_fail;
}

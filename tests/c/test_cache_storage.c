/*
 * test_cache_storage.c — the cache-key derivation (pure, libc-only). Links the
 * compiled cache_storage.o; exercises only brix_cache_key_from (the resolvers
 * need an nginx conf and are covered by the e2e tests).
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

int brix_cache_key_from(const char *cache_root_canon, const char *root_canon,
                          const char *resolved, char *dst, size_t dstsz);

int main(void) {
    char k[256];

    /* resolved under the export root → re-rooted under cache_root → logical key */
    assert(brix_cache_key_from("/cache", "/exp", "/exp/a/b.bin", k, sizeof k) == 0);
    assert(strcmp(k, "/a/b.bin") == 0);

    /* nested */
    assert(brix_cache_key_from("/srv/xc", "/data", "/data/x/y/z", k, sizeof k) == 0);
    assert(strcmp(k, "/x/y/z") == 0);

    /* not under the export root → error */
    assert(brix_cache_key_from("/cache", "/exp", "/other/x", k, sizeof k) != 0);

    printf("test_cache_storage: ALL PASS\n");
    return 0;
}

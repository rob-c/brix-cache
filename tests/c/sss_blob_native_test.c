/* Verify independently minted SSS bytes through the real server crypto chain. */
#include "auth/sss/sss_internal.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
    assert(argc == 3);
    ngx_time_init();
    ngx_cached_time->sec = 1800000000;
    brix_sss_key_t key = {.id = 7, .key_len = 16};
    memcpy(key.key, "0123456789abcdef", 16);
    if (!strcmp(argv[1], "expired")) { key.exp = ngx_time(); }
    if (!strcmp(argv[1], "live-expiry")) { key.exp = ngx_time() + 1; }
    if (!strcmp(argv[1], "zero-key")) { key.key_len = 0; }
    if (!strcmp(argv[1], "wrong-key")) { key.key[0] ^= 1; }
    ngx_array_t keys = {.elts = &key, .nelts = 1, .size = sizeof(key)};
    u_char blob[16384];
    size_t length = fread(blob, 1, sizeof(blob), stdin);
    assert(!ferror(stdin) && length < sizeof(blob));
    struct { u_char before[16]; brix_sss_identity_t identity; u_char after[16]; } result;
    memset(&result, 0xa5, sizeof(result));
    char error[256] = {0};
    const brix_sss_key_t *selected = &key;
    brix_sss_identity_t *identity = !strcmp(argv[1], "no-identity") ? NULL : &result.identity;
    const brix_sss_key_t **key_out = !strcmp(argv[1], "no-key-out") ? NULL : &selected;
    ngx_array_t *keytab = !strcmp(argv[1], "null-keytab") ? NULL : &keys;
    const u_char *input = !strcmp(argv[1], "null-blob") ? NULL : blob;
    ngx_int_t rc = brix_sss_verify_blob(keytab, (time_t) strtol(argv[2], NULL, 10),
                        input, length, identity, key_out, error, sizeof(error));
    for (size_t i = 0; i < sizeof(result.before); i++) {
        assert(result.before[i] == 0xa5 && result.after[i] == 0xa5);
    }
    if (rc != NGX_OK && key_out != NULL) { assert(selected == NULL); }
    printf("%ld %d\n", (long) rc, selected == &key);
    if (rc == NGX_OK && identity != NULL) {
        for (size_t i = 0; i < strlen(identity->name); i++) {
            printf("%02x", (unsigned char) identity->name[i]);
        }
    }
    printf("\n%s\n", error);
    return 0;
}

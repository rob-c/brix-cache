#include "../../src/token/b64url.h"
#include <stdio.h>
#include <string.h>

int main() {
    const char *b64url = "SGVsbG8td29ybGQ";
    uint8_t out[32];
    ssize_t len = b64url_decode(b64url, strlen(b64url), out, sizeof(out));
    const char *expected = "Hello-world";
    if (len == 11 && memcmp(out, expected, 11) == 0) {
        printf("b64url_decode passed\n");
        return 0;
    }
    printf("b64url_decode failed: len=%zd\n", len);
    printf("Decoded bytes: ");
    for (int i = 0; i < (len > 0 && len < 32 ? len : 11); i++) printf("%02x ", out[i]);
    printf("\n");
    return 1;
}

#include "../../src/token/scopes.h"
#include <stdio.h>
#include <string.h>

int main() {
    xrootd_token_scope_t scopes[4];
    int n = xrootd_token_parse_scopes("storage.read:/foo storage.write:/bar", scopes, 4);
    if (n != 2 || !scopes[0].read || strcmp(scopes[0].path, "/foo") != 0 || !scopes[1].write || strcmp(scopes[1].path, "/bar") != 0) {
        printf("scope parse failed\n");
        return 1;
    }
    if (!xrootd_token_check_read(scopes, n, "/foo") || !xrootd_token_check_write(scopes, n, "/bar")) {
        printf("scope check failed\n");
        return 1;
    }
    printf("scope helpers passed\n");
    return 0;
}

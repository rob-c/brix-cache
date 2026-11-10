/* Both protocol planes must bucket anonymous clients and avoid raw subject keys. */
#include "net/ratelimit/ratelimit.h"
#include "protocols/webdav/webdav.h"
#include <assert.h>

int main(int argc, char **argv)
{
    assert(argc == 6);
    brix_ctx_t stream = {0};
    brix_identity_t identity = {0};
    ngx_http_brix_webdav_req_ctx_t web = {0};
    brix_rl_rule_t rule = {.key_type = atoi(argv[2])};
    ngx_str_t ip = ngx_string("192.0.2.17");
    ngx_str_set(&rule.key_match, "/store/");
    strcpy(stream.login.peer_ip, "192.0.2.17");
    if (!strcmp(argv[3], "full")) {
        ngx_str_set(&identity.vo_csv, "atlas");
        ngx_str_set(&identity.issuer, "https://issuer.invalid");
        ngx_str_set(&identity.subject, "private@example.org");
        ngx_str_set(&identity.dn, "/CN=private@example.org");
        strcpy(stream.login.primary_vo, "atlas");
        strcpy(stream.login.dn, "/CN=private@example.org");
    }
    if (!strcmp(argv[3], "cert")) { strcpy(web.dn, "/CN=private@example.org"); }
    stream.identity = !strcmp(argv[3], "none") ? NULL : &identity;
    const char *path = !strcmp(argv[5], "<null>") ? NULL : argv[5];
    rl_key_req_t request = {.id = stream.identity, .wctx = &web, .ip = &ip, .path = path};
    if (!strcmp(argv[3], "none")) { request.wctx = NULL; }
    unsigned char output[144]; memset(output, 0xa5, sizeof(output));
    size_t capacity = strtoul(argv[4], NULL, 10); assert(capacity >= 1 && capacity <= 128);
    char *buffer = (char *) output + 8;
    ngx_int_t rc = !strcmp(argv[1], "stream")
        ? brix_rl_key_stream(&rule, &stream, path, buffer, capacity)
        : brix_rl_key_http(&rule, &request, buffer, capacity);
    for (int i = 0; i < 8; i++) { assert(output[i] == 0xa5 && output[8 + capacity + i] == 0xa5); }
    printf("%ld\n", (long) rc);
    if (rc == NGX_OK) {
        size_t length = strnlen(buffer, capacity); assert(length < capacity);
        assert(fwrite(buffer, 1, length, stdout) == length);
    } else { assert((unsigned char) buffer[0] == 0xa5); }
    return 0;
}

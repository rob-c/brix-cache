/* File and descriptor query adapters preserve checksum, confinement and fd ownership. */
#include "protocols/root/query/query_internal.h"
#include "core/compat/checksum.h"
#include <assert.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    assert(argc == 6);
    ngx_log_t log = {0};
    ngx_str_t root = {strlen(argv[1]), (u_char *) argv[1]};
    const char *path = argv[2], *algorithm = argv[3], *mode = argv[4];
    int failed = atoi(argv[5]), fd = -1;
    if (!strcmp(mode, "fd")) { fd = open(path, O_RDONLY); assert(fd >= 0); }
    if (!strcmp(mode, "bad-fd")) { fd = -1; }
    int by_fd = strcmp(mode, "file") != 0;
    if (!strcmp(algorithm, "adler32") || !strcmp(algorithm, "crc32")) {
        uint32_t value;
        if (!strcmp(algorithm, "adler32")) {
            value = by_fd ? brix_query_adler32_fd(fd, path, &log)
                          : brix_query_adler32_file(&root, path, &log);
        } else {
            value = by_fd ? brix_query_crc32_fd(fd, path, &log)
                          : brix_query_crc32_file(&root, path, &log);
        }
        assert(!failed || value == UINT32_MAX);
        if (!failed) { printf("%08x\n", value); }
    } else {
        brix_checksum_alg_t alg = BRIX_CHECKSUM_SHA256;
        if (!strcmp(algorithm, "sha1")) { alg = BRIX_CHECKSUM_SHA1; }
        if (!strcmp(algorithm, "md5")) { alg = BRIX_CHECKSUM_MD5; }
        if (!strcmp(algorithm, "invalid")) { alg = (brix_checksum_alg_t) 999; }
        unsigned char value[EVP_MAX_MD_SIZE]; unsigned int length = 0;
        ngx_flag_t ok = by_fd ? brix_query_digest_fd(fd, path, alg, value, &length, &log)
                             : brix_query_digest_file(&root, path, alg, value, &length, &log);
        assert(ok == !failed);
        if (ok) {
            assert(length <= sizeof(value));
            for (unsigned int i = 0; i < length; i++) { printf("%02x", value[i]); }
            puts("");
        }
    }
    if (fd >= 0) {
        assert(fcntl(fd, F_GETFD) >= 0);
        assert(lseek(fd, 0, SEEK_CUR) == 0);
        close(fd);
    }
    return 0;
}

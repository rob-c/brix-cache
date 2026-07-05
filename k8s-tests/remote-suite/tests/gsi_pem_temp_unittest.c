/* Standalone unit test for brix_proxy_gsi_write_pem_temp — gcc, no nginx. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../src/net/proxy/gsi_upstream.h"

int main(void)
{
    const char *pem = "-----BEGIN CERT-----\nABC\n-----END CERT-----\n";
    char p1[256] = {0}, p2[256] = {0};

    /* writes a file, path returned */
    assert(brix_proxy_gsi_write_pem_temp((const unsigned char *) pem,
                                           strlen(pem), p1, sizeof(p1)) == 0);
    assert(p1[0] != '\0');

    /* perms are 0600, owner-only */
    struct stat st;
    assert(stat(p1, &st) == 0);
    assert((st.st_mode & 0777) == 0600);

    /* contents round-trip */
    char buf[256] = {0};
    int fd = open(p1, O_RDONLY);
    assert(fd >= 0);
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    assert(n == (ssize_t) strlen(pem));
    assert(memcmp(buf, pem, strlen(pem)) == 0);

    /* a second call yields a DISTINCT path */
    assert(brix_proxy_gsi_write_pem_temp((const unsigned char *) pem,
                                           strlen(pem), p2, sizeof(p2)) == 0);
    assert(strcmp(p1, p2) != 0);

    /* empty PEM rejected */
    assert(brix_proxy_gsi_write_pem_temp((const unsigned char *) pem,
                                           0, p1, sizeof(p1)) == -1);

    unlink(p1);
    unlink(p2);
    printf("gsi_pem_temp_unittest: all checks passed\n");
    return 0;
}

/* Black-box socket probe: no dependency on any reference-server internals. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
    struct sockaddr_storage address;
    socklen_t length = sizeof(struct sockaddr_in);
    int family = AF_INET;
    if (argc != 3) {
        return 2;
    }
    memset(&address, 0, sizeof(address));
    if (strchr(argv[1], ':') != NULL) {
        family = AF_INET6;
        length = sizeof(struct sockaddr_in6);
    }
    address.ss_family = family;
    struct sockaddr_in *v4 = (struct sockaddr_in *) &address;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *) &address;
    void *ip = family == AF_INET ? (void *) &v4->sin_addr : (void *) &v6->sin6_addr;
    if (inet_pton(family, argv[1], ip) != 1) {
        return 2;
    }
    unsigned long port = strtoul(argv[2], NULL, 10);
    if (port < 1024 || port > 65535) {
        return 2;
    }
    if (family == AF_INET) {
        v4->sin_port = htons((unsigned short) port);
    } else {
        v6->sin6_port = htons((unsigned short) port);
    }
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        return 3;
    }
    if (bind(fd, (struct sockaddr *) &address, length) != 0) {
        int error = errno;
        close(fd);
        return error == EACCES ? 13 : 3;
    }
    if (getsockname(fd, (struct sockaddr *) &address, &length) != 0) {
        close(fd);
        return 3;
    }
    char text[INET6_ADDRSTRLEN];
    if (inet_ntop(family, ip, text, sizeof(text)) == NULL) {
        close(fd);
        return 3;
    }
    puts(text);
    close(fd);
    return 0;
}

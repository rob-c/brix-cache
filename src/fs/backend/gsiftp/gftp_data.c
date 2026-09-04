/* Passive MODE-S GridFTP data transfers for the blocking storage driver. */

#include "gftp_client.h"
#include "gftp_reply.h"
#include "protocols/root/connection/netconnect.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define GFTP_DATA_CHUNK 65536
#define GFTP_SLURP_MAX  (16u * 1024u * 1024u)

static int
gftp_data_port(gftp_session_t *session, unsigned *port)
{
    unsigned char ignored[4];

    if (gftp_command(session, "EPSV") != 0) {
        return -1;
    }
    if (session->code == 229) {
        if (gftp_reply_parse_epsv(session->text, strlen(session->text), port)
            == 0) {
            return 0;
        }
        gftp_set_error(session, EPROTO, "GridFTP EPSV reply is malformed");
        return -1;
    }
    if (gftp_command(session, "PASV") != 0 || session->code != 227) {
        gftp_set_error(session, EPROTO, "GridFTP passive mode was refused");
        return -1;
    }
    if (gftp_reply_parse_pasv(session->text, strlen(session->text), ignored,
                              port) != 0) {
        gftp_set_error(session, EPROTO, "GridFTP PASV reply is malformed");
        return -1;
    }
    return 0;
}

static int
gftp_data_connect(gftp_session_t *session)
{
    struct addrinfo  hints;
    struct addrinfo *result = NULL;
    char             service[16];
    unsigned         port;
    int              fd;

    if (gftp_data_port(session, &port) != 0) {
        return -1;
    }
    if (port < 1024 || port > 65535 || session->peer_ip[0] == '\0') {
        gftp_set_error(session, EACCES,
            "refusing unsafe GridFTP passive data target");
        return -1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    (void) snprintf(service, sizeof(service), "%u", port);
    if (getaddrinfo(session->peer_ip, service, &hints, &result) != 0) {
        gftp_set_error(session, EHOSTUNREACH,
            "cannot resolve pinned GridFTP data peer");
        return -1;
    }
    fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd >= 0 && brix_connect_fd_deadline(fd, result->ai_addr,
            result->ai_addrlen, session->timeout_ms) != 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(result);
    if (fd < 0) {
        gftp_set_error(session, ECONNREFUSED,
            "cannot connect to pinned GridFTP data peer");
    }
    return fd;
}

static int
gftp_transfer_begin(gftp_session_t *session, const char *command, int *fd)
{
    *fd = gftp_data_connect(session);
    if (*fd < 0) {
        return -1;
    }
    if (gftp_command(session, "%s", command) != 0
        || session->code < 100 || session->code >= 200) {
        close(*fd);
        *fd = -1;
        gftp_set_error(session, session->code == 550 ? ENOENT : EIO,
            "GridFTP transfer was refused: %d", session->code);
        return -1;
    }
    return 0;
}

static int
gftp_transfer_finish(gftp_session_t *session)
{
    if (gftp_read_reply(session) != 0) {
        return -1;
    }
    if (session->code >= 200 && session->code < 300) {
        return 0;
    }
    gftp_set_error(session, EIO, "GridFTP transfer failed: %d %s",
        session->code, session->text);
    return -1;
}

int
gftp_retrieve(gftp_session_t *session, const char *path, off_t offset,
    size_t limit, gftp_sink_fn sink, void *ctx, size_t *received)
{
    uint8_t buffer[GFTP_DATA_CHUNK];
    char    command[GFTP_COMMAND_CAP];
    size_t  total = 0;
    int     fd;

    *received = 0;
    if (offset > 0
        && gftp_expect(session, 300, 399, "REST %lld",
                       (long long) offset) != 0) {
        return -1;
    }
    if (snprintf(command, sizeof(command), "RETR %s", path)
        >= (int) sizeof(command)) {
        gftp_set_error(session, EOVERFLOW, "GridFTP path exceeds limit");
        return -1;
    }
    if (gftp_transfer_begin(session, command, &fd) != 0) {
        return -1;
    }
    while (total < limit) {
        size_t  want = limit - total;
        ssize_t n;

        if (want > sizeof(buffer)) {
            want = sizeof(buffer);
        }
        n = gftp_socket_read(session, fd, buffer, want);
        if (n < 0 || (n > 0 && sink(ctx, buffer, (size_t) n) != 0)) {
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            *received = total;
            return gftp_transfer_finish(session);
        }
        total += (size_t) n;
    }
    close(fd);
    *received = total;
    return 0;
}

int
gftp_store(gftp_session_t *session, const char *path, gftp_source_fn source,
    void *ctx)
{
    uint8_t buffer[GFTP_DATA_CHUNK];
    char    command[GFTP_COMMAND_CAP];
    int     fd;

    if (snprintf(command, sizeof(command), "STOR %s", path)
        >= (int) sizeof(command)) {
        gftp_set_error(session, EOVERFLOW, "GridFTP path exceeds limit");
        return -1;
    }
    if (gftp_transfer_begin(session, command, &fd) != 0) {
        return -1;
    }
    for (;;) {
        ssize_t n = source(ctx, buffer, sizeof(buffer));

        if (n < 0 || (n > 0 && gftp_socket_write_all(session, fd, buffer,
                                                       (size_t) n) != 0)) {
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
    }
    (void) shutdown(fd, SHUT_WR);
    close(fd);
    return gftp_transfer_finish(session);
}

static int
gftp_slurp_append(gftp_session_t *session, char **data, size_t *used,
    const uint8_t *part, size_t len)
{
    char *larger;

    if (len > GFTP_SLURP_MAX - *used) {
        gftp_set_error(session, EOVERFLOW, "GridFTP listing exceeds limit");
        return -1;
    }
    larger = realloc(*data, *used + len + 1);
    if (larger == NULL) {
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP listing");
        return -1;
    }
    memcpy(larger + *used, part, len);
    *used += len;
    larger[*used] = '\0';
    *data = larger;
    return 0;
}

int
gftp_slurp(gftp_session_t *session, const char *command, char **out,
    size_t *out_len)
{
    uint8_t buffer[8192];
    char   *data = NULL;
    size_t  used = 0;
    int     fd;

    *out = NULL;
    *out_len = 0;
    if (gftp_transfer_begin(session, command, &fd) != 0) {
        return -1;
    }
    for (;;) {
        ssize_t n = gftp_socket_read(session, fd, buffer, sizeof(buffer));

        if (n < 0 || (n > 0 && gftp_slurp_append(session, &data, &used,
                                                  buffer, (size_t) n) != 0)) {
            free(data);
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
    }
    close(fd);
    if (gftp_transfer_finish(session) != 0) {
        free(data);
        return -1;
    }
    if (data == NULL) {
        data = calloc(1, 1);
        if (data == NULL) {
            gftp_set_error(session, ENOMEM, "cannot allocate GridFTP listing");
            return -1;
        }
    }
    *out = data;
    *out_len = used;
    return 0;
}

#ifndef BRIX_GFTP_CLIENT_H
#define BRIX_GFTP_CLIENT_H

/* Blocking GridFTP client kernel used only from VFS worker threads. */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define GFTP_CONTROL_CAP 65536
#define GFTP_TEXT_CAP    65536
#define GFTP_COMMAND_CAP 4096
#define GFTP_ADAT_LINE_CAP (128 * 1024)

typedef struct gftp_gsi_s gftp_gsi_t;

typedef struct {
    int         fd;
    int         timeout_ms;
    int         code;
    int         secure;
    size_t      buffered;
    char        input[GFTP_CONTROL_CAP];
    char        text[GFTP_TEXT_CAP];
    char        peer_ip[64];
    char        error[256];
    gftp_gsi_t *gsi;
} gftp_session_t;

typedef struct {
    const char *host;
    int         port;
    int         timeout_ms;
    int         require_gsi;
    const char *proxy_path;
    const char *ca_dir;
} gftp_session_cfg_t;

typedef int (*gftp_sink_fn)(void *ctx, const uint8_t *data, size_t len);
typedef ssize_t (*gftp_source_fn)(void *ctx, uint8_t *data, size_t cap);

int gftp_session_open(gftp_session_t *session,
    const gftp_session_cfg_t *cfg);
int gftp_authenticate(gftp_session_t *session,
    const gftp_session_cfg_t *cfg);
void gftp_session_close(gftp_session_t *session);
int gftp_read_reply(gftp_session_t *session);
int gftp_command(gftp_session_t *session, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
int gftp_expect(gftp_session_t *session, int low, int high,
    const char *fmt, ...) __attribute__((format(printf, 4, 5)));
void gftp_set_error(gftp_session_t *session, int err, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
ssize_t gftp_socket_read(gftp_session_t *session, int fd, void *buf,
    size_t cap);
int gftp_socket_write_all(gftp_session_t *session, int fd, const void *buf,
    size_t len);

int gftp_retrieve(gftp_session_t *session, const char *path, off_t offset,
    size_t limit, gftp_sink_fn sink, void *ctx, size_t *received);
int gftp_store(gftp_session_t *session, const char *path,
    gftp_source_fn source, void *ctx);
int gftp_slurp(gftp_session_t *session, const char *command,
    char **out, size_t *out_len);

#endif /* BRIX_GFTP_CLIENT_H */

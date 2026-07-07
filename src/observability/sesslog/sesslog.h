#ifndef BRIX_OBSERVABILITY_SESSLOG_H
#define BRIX_OBSERVABILITY_SESSLOG_H

#include <stddef.h>
#include <stdint.h>

#define BRIX_SESSLOG_ID_LEN              16
#define BRIX_SESSLOG_LINE_MAX            4096
#define BRIX_SESSLOG_PATH_MAX            1024
#define BRIX_SESSLOG_PENDING_PATH_MAX    256
#define BRIX_SESSLOG_USER_MAX            256
#define BRIX_SESSLOG_VO_MAX              128
#define BRIX_SESSLOG_PEER_MAX            80
#define BRIX_SESSLOG_ERR_MAX             32

typedef enum {
    BRIX_SESS_PROTO_ROOT = 0,
    BRIX_SESS_PROTO_WEBDAV,
    BRIX_SESS_PROTO_S3,
    BRIX_SESS_PROTO_CVMFS,
    BRIX_SESS_PROTO_CMS,
    BRIX_SESS_PROTO_TPC,
    BRIX_SESS_PROTO_FILL,
    BRIX_SESS_PROTO_MAX
} brix_sess_proto_t;

typedef enum {
    BRIX_SESS_DIR_IN = 0,
    BRIX_SESS_DIR_OUT
} brix_sess_dir_t;

typedef enum {
    BRIX_SESS_AM_GSI = 0,
    BRIX_SESS_AM_TOKEN,
    BRIX_SESS_AM_SSS,
    BRIX_SESS_AM_KRB5,
    BRIX_SESS_AM_PWD,
    BRIX_SESS_AM_UNIX,
    BRIX_SESS_AM_HOST,
    BRIX_SESS_AM_SIGV4,
    BRIX_SESS_AM_ANON,
    BRIX_SESS_AM_MAX
} brix_sess_am_t;

typedef enum {
    BRIX_SESS_MODE_READ = 0,
    BRIX_SESS_MODE_WRITE,
    BRIX_SESS_MODE_META,
    BRIX_SESS_MODE_DELETE,
    BRIX_SESS_MODE_LIST,
    BRIX_SESS_MODE_COPY,
    BRIX_SESS_MODE_MAX
} brix_sess_mode_t;

typedef enum {
    BRIX_SESS_XFER_COMPLETE = 0,
    BRIX_SESS_XFER_ABORTED,
    BRIX_SESS_XFER_SHUTDOWN
} brix_sess_xfer_status_t;

typedef enum {
    BRIX_SESS_END_CLIENT = 0,
    BRIX_SESS_END_SERVER,
    BRIX_SESS_END_TIMEOUT,
    BRIX_SESS_END_SHUTDOWN,
    BRIX_SESS_END_ERROR
} brix_sess_end_t;

typedef size_t (*brix_sess_sanitize_fn)(char *dst, size_t dst_size,
    const char *src, size_t src_len);

typedef struct brix_sess_xfer_s {
    struct brix_sess_xfer_s  *next;
    struct brix_sess_xfer_s **prevp;
    char                      path[BRIX_SESSLOG_PENDING_PATH_MAX];
    brix_sess_mode_t          mode;
    uint64_t                  bytes;
    int64_t                   expected;
    uint64_t                  start_msec;
    unsigned                  active:1;
} brix_sess_xfer_t;

typedef struct brix_sess_s {
    char                 id[BRIX_SESSLOG_ID_LEN + 1];
    brix_sess_proto_t    proto;
    brix_sess_dir_t      dir;
    brix_sess_am_t       authmethod;
    char                 peer[BRIX_SESSLOG_PEER_MAX];
    char                 parent[BRIX_SESSLOG_ID_LEN + 1];
    uint64_t             start_msec;
    int                  log_fd;

    char                 user[BRIX_SESSLOG_USER_MAX];
    brix_sess_am_t       auth_method_logged;
    unsigned             auth_logged:1;

    char                 pending_path[BRIX_SESSLOG_PENDING_PATH_MAX];
    brix_sess_mode_t     pending_mode;
    unsigned             pending_attempt:1;

    brix_sess_xfer_t    *xfers;
    int                  registry_next;

    unsigned             in_use:1;
    unsigned             end_logged:1;
} brix_sess_t;

/*
 * WHAT: Render one session-lifecycle event, excluding the timestamp prefix and
 * including the trailing newline.
 * WHY: Keeping the grammar in one ngx-free formatter prevents protocol hooks
 * from drifting in field order, quoting, or enum spellings.
 * HOW: Callers inject the sanitizer and clock values; the functions clamp
 * arbitrary strings before quoting and always return a single bounded line.
 */
size_t brix_sesslog_fmt_connect(char *line, size_t line_max,
    const brix_sess_t *s, brix_sess_sanitize_fn san);
size_t brix_sesslog_fmt_auth(char *line, size_t line_max,
    const brix_sess_t *s, int ok, brix_sess_am_t method,
    const char *user, const char *vo, const char *err,
    brix_sess_sanitize_fn san);
size_t brix_sesslog_fmt_attempt(char *line, size_t line_max,
    const brix_sess_t *s, const char *path, brix_sess_mode_t mode,
    brix_sess_sanitize_fn san);
size_t brix_sesslog_fmt_result(char *line, size_t line_max,
    const brix_sess_t *s, int ok, const char *path,
    brix_sess_mode_t mode, const char *err, brix_sess_sanitize_fn san);
size_t brix_sesslog_fmt_xfer(char *line, size_t line_max,
    const brix_sess_t *s, const brix_sess_xfer_t *x,
    brix_sess_xfer_status_t st, uint64_t now_msec,
    brix_sess_sanitize_fn san);
size_t brix_sesslog_fmt_end(char *line, size_t line_max,
    const brix_sess_t *s, brix_sess_end_t why, uint64_t now_msec,
    brix_sess_sanitize_fn san);

const char *brix_sesslog_proto_label(brix_sess_proto_t p);
const char *brix_sesslog_dir_label(brix_sess_dir_t d);
const char *brix_sesslog_am_label(brix_sess_am_t m);
const char *brix_sesslog_mode_label(brix_sess_mode_t m);
const char *brix_sesslog_xfer_label(brix_sess_xfer_status_t st);
const char *brix_sesslog_end_label(brix_sess_end_t e);

const char *brix_sesslog_err_from_errno(int err, char *scratch, size_t n);
const char *brix_sesslog_err_from_kxr(int kxr, char *scratch, size_t n);
const char *brix_sesslog_err_from_http(int status, char *scratch, size_t n);

#endif /* BRIX_OBSERVABILITY_SESSLOG_H */

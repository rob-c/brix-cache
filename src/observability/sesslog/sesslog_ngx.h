#ifndef BRIX_OBSERVABILITY_SESSLOG_NGX_H
#define BRIX_OBSERVABILITY_SESSLOG_NGX_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "observability/sesslog/sesslog.h"

#define BRIX_SESSLOG_REGISTRY_SLOTS 4096

/*
 * WHAT: nginx-facing lifecycle API for session audit logs.
 * WHY: Protocol planes should record events without knowing about the per-worker
 * registry, timestamp prefix, batched writer, or shutdown walk.
 * HOW: brix_sess_begin() claims a fixed registry slot and emits CONNECT; every
 * other call is NULL/end tolerant and emits at most one structured SESS line.
 */
brix_sess_t *brix_sess_begin(ngx_uint_t enabled, ngx_fd_t log_fd,
    brix_sess_proto_t proto, brix_sess_dir_t dir, const char *peer,
    size_t peer_len, brix_sess_am_t am, const brix_sess_t *parent);
void brix_sess_auth(brix_sess_t *s, int ok, brix_sess_am_t m,
    const char *user, const char *vo, const char *err);
void brix_sess_auth_once(brix_sess_t *s, brix_sess_am_t m, const char *user,
    const char *vo);
void brix_sess_attempt(brix_sess_t *s, const char *path,
    brix_sess_mode_t mode);
void brix_sess_result(brix_sess_t *s, int ok, const char *path,
    brix_sess_mode_t mode, const char *err);
void brix_sess_xfer_start(brix_sess_t *s, brix_sess_xfer_t *x,
    const char *path, brix_sess_mode_t mode, int64_t expected);
void brix_sess_xfer_add(brix_sess_xfer_t *x, uint64_t n);
void brix_sess_xfer_end(brix_sess_t *s, brix_sess_xfer_t *x,
    brix_sess_xfer_status_t st);
void brix_sess_end(brix_sess_t *s, brix_sess_end_t why);
void brix_sesslog_shutdown_flush(void);

brix_sess_am_t brix_sess_am_from_stream_auth(ngx_uint_t auth);
const char *brix_sess_id(const brix_sess_t *s);

#endif /* BRIX_OBSERVABILITY_SESSLOG_NGX_H */

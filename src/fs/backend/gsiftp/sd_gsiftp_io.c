/* Object and metadata operations for the outbound GridFTP driver. */

#include "sd_gsiftp_internal.h"
#include "gftp_mlsx.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *cursor;
} sd_gsiftp_sink;

static int
sd_gsiftp_sink_copy(void *ctx, const uint8_t *data, size_t len)
{
    sd_gsiftp_sink *sink = ctx;

    memcpy(sink->cursor, data, len);
    sink->cursor += len;
    return 0;
}

static int
sd_gsiftp_parse_size(const char *text, off_t *size)
{
    char               *end;
    unsigned long long  value;

    while (*text == ' ') {
        text++;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || value > (unsigned long long) INT64_MAX) {
        errno = EPROTO;
        return -1;
    }
    while (*end == ' ') {
        end++;
    }
    if (*end != '\0') {
        errno = EPROTO;
        return -1;
    }
    *size = (off_t) value;
    return 0;
}

static void
sd_gsiftp_parse_mtime(const char *text, brix_sd_stat_t *out)
{
    char             line[96];
    gftp_mlsx_ent_t  ent;
    const char      *start = text;
    size_t           len = 0;

    while (*start == ' ') {
        start++;
    }
    while (start[len] != '\0' && start[len] != ' ' && len < 32) {
        len++;
    }
    if (len < 14 || snprintf(line, sizeof(line), "modify=%.*s; x",
                              (int) len, start) >= (int) sizeof(line)) {
        return;
    }
    if (gftp_mlsx_parse(line, strlen(line), &ent) == 0 && ent.has_mtime) {
        out->mtime = ent.mtime;
        out->ctime = ent.mtime;
    }
}

static int
sd_gsiftp_stat_dir(gftp_session_t *session, const char *remote,
    brix_sd_stat_t *out)
{
    char   command[GFTP_COMMAND_CAP];
    char  *listing = NULL;
    size_t listing_len;

    if (snprintf(command, sizeof(command), "MLSD %s", remote)
        >= (int) sizeof(command)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (gftp_slurp(session, command, &listing, &listing_len) != 0) {
        free(listing);
        return -1;
    }
    free(listing);
    (void) listing_len;
    out->mode = S_IFDIR | 0755;
    out->is_dir = 1;
    return 0;
}

static int
sd_gsiftp_stat_file(gftp_session_t *session, const char *remote,
    brix_sd_stat_t *out)
{
    if (session->code != 213
        || sd_gsiftp_parse_size(session->text, &out->size) != 0) {
        return 0;
    }
    out->mode = S_IFREG | 0644;
    out->is_reg = 1;
    if (gftp_command(session, "MDTM %s", remote) == 0
        && session->code == 213) {
        sd_gsiftp_parse_mtime(session->text, out);
    }
    return 1;
}

static ngx_int_t
sd_gsiftp_stat_finish(gftp_session_t *session, const char *remote,
    brix_sd_stat_t *out, int command_rc)
{
    int rc = command_rc;

    if (rc == 0 && sd_gsiftp_stat_file(session, remote, out)) {
        return NGX_OK;
    }
    if (rc == 0 && session->code == 550) {
        rc = sd_gsiftp_stat_dir(session, remote, out);
    } else if (rc == 0) {
        errno = EPROTO;
        rc = -1;
    }
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_gsiftp_stat_impl(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    sd_gsiftp_state *state = inst->state;
    gftp_session_t   session;
    char             remote[GSIFTP_PATH_CAP];
    const char      *proxy;
    int              err = 0;
    int              rc;

    memset(out, 0, sizeof(*out));
    if (sd_gsiftp_select_proxy(state, cred, &proxy, &err) != 0) {
        return NGX_ERROR;
    }
    if (sd_gsiftp_path(state, path, remote) != 0
        || sd_gsiftp_session(&session, state, proxy) != 0) {
        return NGX_ERROR;
    }
    rc = gftp_command(&session, "SIZE %s", remote);
    rc = sd_gsiftp_stat_finish(&session, remote, out, rc);
    gftp_session_close(&session);
    return rc;
}

static void
sd_gsiftp_set_error(int *err_out, int error)
{
    errno = error;
    if (err_out != NULL) {
        *err_out = error;
    }
}

static int
sd_gsiftp_read_flags_ok(int flags, int *err_out)
{
    int forbidden = BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC
                    | BRIX_SD_O_APPEND | BRIX_SD_O_DIR;

    if ((flags & forbidden) == 0) {
        return 1;
    }
    sd_gsiftp_set_error(err_out, EROFS);
    return 0;
}

static brix_sd_obj_t *
sd_gsiftp_alloc_object(sd_gsiftp_obj_state **state_out, int *err_out)
{
    brix_sd_obj_t       *obj = calloc(1, sizeof(*obj));
    sd_gsiftp_obj_state *state = calloc(1, sizeof(*state));

    if (obj == NULL || state == NULL) {
        free(obj);
        free(state);
        sd_gsiftp_set_error(err_out, ENOMEM);
        return NULL;
    }
    *state_out = state;
    return obj;
}

static int
sd_gsiftp_prepare_object(sd_gsiftp_state *state,
    sd_gsiftp_obj_state *obj_state, const char *path, const char *proxy,
    int *err_out)
{
    if (sd_gsiftp_path(state, path, obj_state->path) != 0) {
        sd_gsiftp_set_error(err_out, errno);
        return -1;
    }
    if (proxy != NULL
        && sd_gsiftp_copy(obj_state->proxy, sizeof(obj_state->proxy), proxy)
           != 0) {
        sd_gsiftp_set_error(err_out, errno);
        return -1;
    }
    return 0;
}

static int
sd_gsiftp_object_snapshot(brix_sd_obj_t *obj, const char *path,
    const brix_sd_cred_t *cred, int *err_out)
{
    if (sd_gsiftp_stat_impl(obj->inst, path, &obj->snap, cred) == NGX_OK
        && obj->snap.is_reg) {
        return 0;
    }
    sd_gsiftp_set_error(err_out,
        obj->snap.is_dir ? EISDIR : (errno != 0 ? errno : EIO));
    return -1;
}

static brix_sd_obj_t *
sd_gsiftp_open_impl(brix_sd_instance_t *inst, const char *path, int flags,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_gsiftp_state     *state = inst->state;
    sd_gsiftp_obj_state *obj_state;
    brix_sd_obj_t       *obj;
    const char          *proxy;

    if (!sd_gsiftp_read_flags_ok(flags, err_out)) {
        return NULL;
    }
    if (sd_gsiftp_select_proxy(state, cred, &proxy, err_out) != 0) {
        return NULL;
    }
    obj = sd_gsiftp_alloc_object(&obj_state, err_out);
    if (obj == NULL) {
        return NULL;
    }
    obj->inst = inst;
    if (sd_gsiftp_prepare_object(state, obj_state, path, proxy, err_out) != 0
        || sd_gsiftp_object_snapshot(obj, path, cred, err_out) != 0) {
        free(obj_state);
        free(obj);
        return NULL;
    }
    obj->driver = inst->driver;
    obj->fd = NGX_INVALID_FILE;
    obj->state = obj_state;
    obj->heap_shell = 1;
    return obj;
}

brix_sd_obj_t *
sd_gsiftp_open(brix_sd_instance_t *inst, const char *path, int flags,
    mode_t mode, int *err_out)
{
    (void) mode;
    return sd_gsiftp_open_impl(inst, path, flags, NULL, err_out);
}

brix_sd_obj_t *
sd_gsiftp_open_cred(brix_sd_instance_t *inst, const char *path, int flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    (void) mode;
    return sd_gsiftp_open_impl(inst, path, flags, cred, err_out);
}

ngx_int_t
sd_gsiftp_close(brix_sd_obj_t *obj)
{
    if (obj != NULL) {
        free(obj->state);
        obj->state = NULL;
    }
    return NGX_OK;
}

ssize_t
sd_gsiftp_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_gsiftp_obj_state *obj_state = obj->state;
    sd_gsiftp_state     *state = obj->inst->state;
    sd_gsiftp_sink       sink = { .cursor = buf };
    gftp_session_t       session;
    size_t               received;

    if (off < 0) {
        errno = EINVAL;
        return -1;
    }
    if (off >= obj->snap.size || len == 0) {
        return 0;
    }
    if (len > (size_t) (obj->snap.size - off)) {
        len = (size_t) (obj->snap.size - off);
    }
    if (sd_gsiftp_session(&session, state,
            obj_state->proxy[0] != '\0' ? obj_state->proxy : NULL) != 0) {
        return -1;
    }
    if (gftp_retrieve(&session, obj_state->path, off, len,
                       sd_gsiftp_sink_copy, &sink, &received) != 0) {
        gftp_session_close(&session);
        return -1;
    }
    gftp_session_close(&session);
    return (ssize_t) received;
}

ssize_t
sd_gsiftp_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    uint8_t *buffer;
    size_t   total = 0;
    size_t   copied = 0;
    ssize_t  got;
    int      i;

    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > SIZE_MAX - total) {
            errno = EOVERFLOW;
            return -1;
        }
        total += iov[i].iov_len;
    }
    if (total == 0) {
        return 0;
    }
    buffer = malloc(total);
    if (buffer == NULL) {
        errno = ENOMEM;
        return -1;
    }
    got = sd_gsiftp_pread(obj, buffer, total, off);
    if (got < 0) {
        free(buffer);
        return -1;
    }
    for (i = 0; i < iovcnt && copied < (size_t) got; i++) {
        size_t take = iov[i].iov_len;

        if (take > (size_t) got - copied) {
            take = (size_t) got - copied;
        }
        memcpy(iov[i].iov_base, buffer + copied, take);
        copied += take;
    }
    free(buffer);
    return got;
}

ngx_int_t
sd_gsiftp_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

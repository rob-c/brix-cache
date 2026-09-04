/* Namespace and directory-listing operations for the GridFTP driver. */

#include "sd_gsiftp_internal.h"
#include "gftp_mlsx.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char   *listing;
    size_t  length;
    size_t  cursor;
} sd_gsiftp_dir_state;

ngx_int_t
sd_gsiftp_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    return sd_gsiftp_stat_impl(inst, path, out, NULL);
}

ngx_int_t
sd_gsiftp_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    return sd_gsiftp_stat_impl(inst, path, out, cred);
}

static ngx_int_t
sd_gsiftp_command_one(brix_sd_instance_t *inst, const char *verb,
    const char *path, const brix_sd_cred_t *cred)
{
    sd_gsiftp_state *state = inst->state;
    gftp_session_t   session;
    char             remote[GSIFTP_PATH_CAP];
    const char      *proxy;
    int              err = 0;
    int              rc;

    if (sd_gsiftp_select_proxy(state, cred, &proxy, &err) != 0) {
        return NGX_ERROR;
    }
    if (sd_gsiftp_path(state, path, remote) != 0
        || sd_gsiftp_session(&session, state, proxy) != 0) {
        return NGX_ERROR;
    }
    rc = gftp_command(&session, "%s %s", verb, remote);
    if (rc == 0 && (session.code < 200 || session.code >= 300)) {
        errno = session.code == 550 ? ENOENT : EIO;
        rc = -1;
    }
    gftp_session_close(&session);
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_gsiftp_unlink_impl(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    return sd_gsiftp_command_one(inst, is_dir ? "RMD" : "DELE", path, cred);
}

ngx_int_t
sd_gsiftp_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    return sd_gsiftp_unlink_impl(inst, path, is_dir, NULL);
}

ngx_int_t
sd_gsiftp_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    return sd_gsiftp_unlink_impl(inst, path, is_dir, cred);
}

static ngx_int_t
sd_gsiftp_mkdir_impl(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred)
{
    return sd_gsiftp_command_one(inst, "MKD", path, cred);
}

ngx_int_t
sd_gsiftp_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    (void) mode;
    return sd_gsiftp_mkdir_impl(inst, path, NULL);
}

ngx_int_t
sd_gsiftp_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    (void) mode;
    return sd_gsiftp_mkdir_impl(inst, path, cred);
}

static int
sd_gsiftp_destination_absent(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred)
{
    brix_sd_stat_t ignored;

    if (sd_gsiftp_stat_impl(inst, path, &ignored, cred) == NGX_OK) {
        errno = EEXIST;
        return 0;
    }
    return errno == ENOENT;
}

static ngx_int_t
sd_gsiftp_rename_impl(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    sd_gsiftp_state *state = inst->state;
    gftp_session_t   session;
    char             remote_src[GSIFTP_PATH_CAP];
    char             remote_dst[GSIFTP_PATH_CAP];
    const char      *proxy;
    int              err = 0;
    int              rc;

    if (noreplace && !sd_gsiftp_destination_absent(inst, dst, cred)) {
        return NGX_ERROR;
    }
    if (sd_gsiftp_select_proxy(state, cred, &proxy, &err) != 0) {
        return NGX_ERROR;
    }
    if (sd_gsiftp_path(state, src, remote_src) != 0
        || sd_gsiftp_path(state, dst, remote_dst) != 0
        || sd_gsiftp_session(&session, state, proxy) != 0) {
        return NGX_ERROR;
    }
    rc = gftp_expect(&session, 300, 399, "RNFR %s", remote_src);
    if (rc == 0) {
        rc = gftp_expect(&session, 200, 299, "RNTO %s", remote_dst);
    }
    gftp_session_close(&session);
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_gsiftp_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    return sd_gsiftp_rename_impl(inst, src, dst, noreplace, NULL);
}

ngx_int_t
sd_gsiftp_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    return sd_gsiftp_rename_impl(inst, src, dst, noreplace, cred);
}

static brix_sd_dir_t *
sd_gsiftp_dir_alloc(sd_gsiftp_dir_state **state_out, int *err_out)
{
    brix_sd_dir_t       *dir = calloc(1, sizeof(*dir));
    sd_gsiftp_dir_state *state = calloc(1, sizeof(*state));

    *state_out = NULL;
    if (dir == NULL || state == NULL) {
        free(dir);
        free(state);
        errno = ENOMEM;
        if (err_out != NULL) {
            *err_out = ENOMEM;
        }
        return NULL;
    }
    *state_out = state;
    return dir;
}

static void
sd_gsiftp_dir_free(brix_sd_dir_t *dir, sd_gsiftp_dir_state *state)
{
    if (state != NULL) {
        free(state->listing);
        free(state);
    }
    free(dir);
}

static brix_sd_dir_t *
sd_gsiftp_opendir_impl(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_gsiftp_state     *state = inst->state;
    sd_gsiftp_dir_state *dir_state;
    brix_sd_dir_t       *dir;
    gftp_session_t       session;
    char                 remote[GSIFTP_PATH_CAP];
    char                 command[GFTP_COMMAND_CAP];
    const char          *proxy;
    int                  err = 0;

    if (sd_gsiftp_select_proxy(state, cred, &proxy, &err) != 0) {
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        return NULL;
    }
    if (sd_gsiftp_path(state, path, remote) != 0
        || snprintf(command, sizeof(command), "MLSD %s", remote)
           >= (int) sizeof(command)
        || sd_gsiftp_session(&session, state, proxy) != 0) {
        if (err_out != NULL) {
            *err_out = errno != 0 ? errno : EIO;
        }
        return NULL;
    }
    dir = sd_gsiftp_dir_alloc(&dir_state, err_out);
    if (dir == NULL || gftp_slurp(&session, command, &dir_state->listing,
                                  &dir_state->length) != 0) {
        if (err_out != NULL) {
            *err_out = errno != 0 ? errno : ENOMEM;
        }
        sd_gsiftp_dir_free(dir, dir_state);
        gftp_session_close(&session);
        return NULL;
    }
    gftp_session_close(&session);
    dir->inst = inst;
    dir->state = dir_state;
    return dir;
}

brix_sd_dir_t *
sd_gsiftp_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    return sd_gsiftp_opendir_impl(inst, path, NULL, err_out);
}

brix_sd_dir_t *
sd_gsiftp_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred)
{
    return sd_gsiftp_opendir_impl(inst, path, cred, err_out);
}

static int
sd_gsiftp_next_line(sd_gsiftp_dir_state *state, const char **line,
    size_t *length)
{
    size_t start;

    while (state->cursor < state->length
           && (state->listing[state->cursor] == '\r'
               || state->listing[state->cursor] == '\n')) {
        state->cursor++;
    }
    if (state->cursor == state->length) {
        return 0;
    }
    start = state->cursor;
    while (state->cursor < state->length
           && state->listing[state->cursor] != '\r'
           && state->listing[state->cursor] != '\n') {
        state->cursor++;
    }
    *line = state->listing + start;
    *length = state->cursor - start;
    return 1;
}

ngx_int_t
sd_gsiftp_readdir(brix_sd_dir_t *dir, brix_sd_dirent_t *out)
{
    sd_gsiftp_dir_state *state = dir->state;
    const char          *line;
    size_t               length;

    while (sd_gsiftp_next_line(state, &line, &length)) {
        gftp_mlsx_ent_t entry;

        if (gftp_mlsx_parse(line, length, &entry) != 0
            || (entry.name_len == 1 && entry.name[0] == '.')
            || (entry.name_len == 2 && entry.name[0] == '.'
                && entry.name[1] == '.')) {
            continue;
        }
        if (entry.name_len >= sizeof(out->name)) {
            errno = ENAMETOOLONG;
            return NGX_ERROR;
        }
        memset(out, 0, sizeof(*out));
        memcpy(out->name, entry.name, entry.name_len);
        out->name[entry.name_len] = '\0';
        out->d_type = entry.is_dir ? DT_DIR : DT_REG;
        return NGX_OK;
    }
    return NGX_DONE;
}

ngx_int_t
sd_gsiftp_closedir(brix_sd_dir_t *dir)
{
    if (dir != NULL) {
        sd_gsiftp_dir_state *state = dir->state;

        if (state != NULL) {
            sd_gsiftp_dir_free(NULL, state);
        }
        free(dir);
    }
    return NGX_OK;
}

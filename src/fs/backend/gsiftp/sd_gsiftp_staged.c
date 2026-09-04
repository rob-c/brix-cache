/* Local scratch plus remote STOR-and-rename atomic publish. */

#include "sd_gsiftp_internal.h"

#include <errno.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    FILE *scratch;
    char  final_path[GSIFTP_PATH_CAP];
    char  proxy[PATH_MAX];
} sd_gsiftp_staged_state;

typedef struct {
    int   fd;
    off_t offset;
} sd_gsiftp_source;

static ssize_t
sd_gsiftp_source_read(void *ctx, uint8_t *data, size_t cap)
{
    sd_gsiftp_source *source = ctx;
    ssize_t           n;

    do {
        n = pread(source->fd, data, cap, source->offset);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        source->offset += n;
    }
    return n;
}

static void
sd_gsiftp_staged_free(brix_sd_staged_t *handle)
{
    if (handle != NULL) {
        sd_gsiftp_staged_state *state = handle->state;

        if (state != NULL) {
            if (state->scratch != NULL) {
                fclose(state->scratch);
            }
            free(state);
        }
        free(handle);
    }
}

static void
sd_gsiftp_staged_error(int *err_out, int error)
{
    errno = error;
    if (err_out != NULL) {
        *err_out = error;
    }
}

static brix_sd_staged_t *
sd_gsiftp_staged_alloc(sd_gsiftp_staged_state **state_out, int *err_out)
{
    sd_gsiftp_staged_state *state = calloc(1, sizeof(*state));
    brix_sd_staged_t       *handle = calloc(1, sizeof(*handle));

    if (state == NULL || handle == NULL) {
        free(state);
        free(handle);
        sd_gsiftp_staged_error(err_out, ENOMEM);
        return NULL;
    }
    *state_out = state;
    return handle;
}

static int
sd_gsiftp_staged_prepare(sd_gsiftp_state *inst_state,
    sd_gsiftp_staged_state *state, const char *path, const char *proxy,
    int *err_out)
{
    if (sd_gsiftp_path(inst_state, path, state->final_path) != 0) {
        sd_gsiftp_staged_error(err_out, errno);
        return -1;
    }
    if (proxy != NULL
        && sd_gsiftp_copy(state->proxy, sizeof(state->proxy), proxy) != 0) {
        sd_gsiftp_staged_error(err_out, errno);
        return -1;
    }
    state->scratch = tmpfile();
    if (state->scratch == NULL) {
        sd_gsiftp_staged_error(err_out, errno);
        return -1;
    }
    return 0;
}

static brix_sd_staged_t *
sd_gsiftp_staged_open_impl(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_gsiftp_state        *inst_state = inst->state;
    sd_gsiftp_staged_state *state;
    brix_sd_staged_t       *handle;
    const char             *proxy;

    if (sd_gsiftp_select_proxy(inst_state, cred, &proxy, err_out) != 0) {
        return NULL;
    }
    handle = sd_gsiftp_staged_alloc(&state, err_out);
    if (handle == NULL) {
        return NULL;
    }
    if (sd_gsiftp_staged_prepare(inst_state, state, path, proxy, err_out)
        != 0) {
        free(state);
        free(handle);
        return NULL;
    }
    handle->inst = inst;
    handle->state = state;
    return handle;
}

brix_sd_staged_t *
sd_gsiftp_staged_open(brix_sd_instance_t *inst, const char *path,
    mode_t mode, off_t size, int *err_out)
{
    (void) mode;
    (void) size;
    return sd_gsiftp_staged_open_impl(inst, path, NULL, err_out);
}

brix_sd_staged_t *
sd_gsiftp_staged_open_cred(brix_sd_instance_t *inst, const char *path,
    mode_t mode, off_t size, const brix_sd_cred_t *cred, int *err_out)
{
    (void) mode;
    (void) size;
    return sd_gsiftp_staged_open_impl(inst, path, cred, err_out);
}

ssize_t
sd_gsiftp_staged_write(brix_sd_staged_t *handle, const void *buf, size_t len,
    off_t off)
{
    sd_gsiftp_staged_state *state = handle->state;
    size_t                  done = 0;
    int                     fd = fileno(state->scratch);

    if (off < 0) {
        errno = EINVAL;
        return -1;
    }
    while (done < len) {
        ssize_t n = pwrite(fd, (const uint8_t *) buf + done, len - done,
                           off + (off_t) done);

        if (n > 0) {
            done += (size_t) n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n == 0) {
            errno = EIO;
        }
        return -1;
    }
    return (ssize_t) done;
}

static int
sd_gsiftp_temp_path(const char *final_path, char out[GSIFTP_PATH_CAP])
{
    unsigned char random[12];
    char          suffix[25];
    size_t        i;
    int           n;

    if (RAND_bytes(random, sizeof(random)) != 1) {
        errno = EIO;
        return -1;
    }
    for (i = 0; i < sizeof(random); i++) {
        (void) snprintf(suffix + i * 2, 3, "%02x", random[i]);
    }
    n = snprintf(out, GSIFTP_PATH_CAP, "%s.brix-tmp-%s", final_path, suffix);
    if (n < 0 || n >= GSIFTP_PATH_CAP) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int
sd_gsiftp_precondition(brix_sd_staged_t *handle, brix_sd_precond_t *pre)
{
    sd_gsiftp_staged_state *state = handle->state;
    sd_gsiftp_state        *inst_state = handle->inst->state;
    brix_sd_cred_t          cred;
    brix_sd_stat_t          ignored;
    const char             *logical;

    if (pre == NULL || pre->kind == BRIX_SD_PRECOND_NONE) {
        return 0;
    }
    if (pre->kind != BRIX_SD_PRECOND_ABSENT) {
        errno = ENOTSUP;
        return -1;
    }
    logical = state->final_path;
    if (inst_state->base_path[0] != '\0'
        && strcmp(inst_state->base_path, "/") != 0) {
        logical += strlen(inst_state->base_path);
    }
    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy = state->proxy[0] != '\0' ? state->proxy : NULL;
    if (sd_gsiftp_stat_impl(handle->inst, logical, &ignored, &cred) == NGX_OK) {
        errno = EEXIST;
        return -1;
    }
    return errno == ENOENT ? 0 : -1;
}

static void
sd_gsiftp_delete_temp(gftp_session_t *session, const char *path)
{
    (void) gftp_command(session, "DELE %s", path);
}

ngx_int_t
sd_gsiftp_staged_commit(brix_sd_staged_t *handle, brix_sd_precond_t *pre)
{
    sd_gsiftp_staged_state *state = handle->state;
    sd_gsiftp_state        *inst_state = handle->inst->state;
    sd_gsiftp_source        source;
    gftp_session_t          session;
    char                    temp_path[GSIFTP_PATH_CAP];
    int                     rc;

    if (sd_gsiftp_precondition(handle, pre) != 0
        || sd_gsiftp_temp_path(state->final_path, temp_path) != 0
        || fflush(state->scratch) != 0
        || sd_gsiftp_session(&session, inst_state,
            state->proxy[0] != '\0' ? state->proxy : NULL) != 0) {
        return NGX_ERROR;
    }
    source.fd = fileno(state->scratch);
    source.offset = 0;
    rc = gftp_store(&session, temp_path, sd_gsiftp_source_read, &source);
    if (rc == 0) {
        rc = gftp_expect(&session, 300, 399, "RNFR %s", temp_path);
    }
    if (rc == 0) {
        rc = gftp_expect(&session, 200, 299, "RNTO %s", state->final_path);
    }
    if (rc != 0) {
        sd_gsiftp_delete_temp(&session, temp_path);
        gftp_session_close(&session);
        return NGX_ERROR;
    }
    gftp_session_close(&session);
    sd_gsiftp_staged_free(handle);
    return NGX_OK;
}

void
sd_gsiftp_staged_abort(brix_sd_staged_t *handle)
{
    sd_gsiftp_staged_free(handle);
}

/* Driver descriptor, instance factory, confinement and session helpers. */

#include "sd_gsiftp_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
sd_gsiftp_copy(char *dst, size_t cap, const char *src)
{
    size_t len = src != NULL ? strlen(src) : 0;

    if (len >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (len != 0) {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
    return 0;
}

static int
sd_gsiftp_component_safe(const char *start, size_t len)
{
    if ((len == 1 && start[0] == '.')
        || (len == 2 && start[0] == '.' && start[1] == '.')) {
        return 0;
    }
    while (len-- != 0) {
        unsigned char ch = (unsigned char) *start++;

        if (ch < 0x20 || ch == 0x7f || ch == '\\') {
            return 0;
        }
    }
    return 1;
}

static int
sd_gsiftp_logical_safe(const char *path)
{
    const char *part;
    const char *cursor;

    if (path == NULL || path[0] != '/') {
        return 0;
    }
    part = path + 1;
    for (cursor = part;; cursor++) {
        if (*cursor != '/' && *cursor != '\0') {
            continue;
        }
        if (!sd_gsiftp_component_safe(part, (size_t) (cursor - part))) {
            return 0;
        }
        if (*cursor == '\0') {
            return 1;
        }
        part = cursor + 1;
    }
}

int
sd_gsiftp_path(const sd_gsiftp_state *state, const char *logical,
    char out[GSIFTP_PATH_CAP])
{
    const char *base = state->base_path;
    int         n;

    if (!sd_gsiftp_logical_safe(logical)) {
        errno = EACCES;
        return -1;
    }
    if (base[0] == '\0' || strcmp(base, "/") == 0) {
        n = snprintf(out, GSIFTP_PATH_CAP, "%s", logical);
    } else {
        n = snprintf(out, GSIFTP_PATH_CAP, "%s%s", base, logical);
    }
    if (n < 0 || n >= GSIFTP_PATH_CAP) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

const char *
sd_gsiftp_proxy(const sd_gsiftp_state *state, const brix_sd_cred_t *cred,
    int *err_out)
{
    if (cred != NULL && cred->x509_proxy != NULL
        && cred->x509_proxy[0] != '\0') {
        return cred->x509_proxy;
    }
    if (cred != NULL && cred->fallback_deny) {
        errno = EACCES;
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        return NULL;
    }
    if (state->require_gsi && state->x509_proxy[0] == '\0') {
        errno = EACCES;
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        return NULL;
    }
    return state->x509_proxy[0] != '\0' ? state->x509_proxy : NULL;
}

int
sd_gsiftp_select_proxy(const sd_gsiftp_state *state,
    const brix_sd_cred_t *cred, const char **proxy, int *err_out)
{
    *proxy = sd_gsiftp_proxy(state, cred, err_out);
    if ((state->require_gsi || (cred != NULL && cred->fallback_deny))
        && *proxy == NULL) {
        return -1;
    }
    return 0;
}

int
sd_gsiftp_session(gftp_session_t *session, const sd_gsiftp_state *state,
    const char *proxy)
{
    gftp_session_cfg_t cfg = {
        .host = state->host,
        .port = state->port,
        .timeout_ms = state->timeout_ms,
        .require_gsi = state->require_gsi,
        .proxy_path = proxy,
        .ca_dir = state->ca_dir[0] != '\0' ? state->ca_dir : NULL,
    };

    return gftp_session_open(session, &cfg);
}

static const brix_sd_driver_t *
sd_gsiftp_driver(void)
{
    static const brix_sd_driver_t brix_sd_gsiftp_driver = {
        .name = "gsiftp",
        .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_MEMFILE
                | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_DIRS_WRITE
                | BRIX_SD_CAP_HARD_RENAME,
        .cred_accept = BRIX_SD_CRED_PROXY_PEM,
        .open = sd_gsiftp_open,
        .close = sd_gsiftp_close,
        .pread = sd_gsiftp_pread,
        .preadv = sd_gsiftp_preadv,
        .fstat = sd_gsiftp_fstat,
        .stat = sd_gsiftp_stat,
        .unlink = sd_gsiftp_unlink,
        .mkdir = sd_gsiftp_mkdir,
        .rename = sd_gsiftp_rename,
        .opendir = sd_gsiftp_opendir,
        .readdir = sd_gsiftp_readdir,
        .closedir = sd_gsiftp_closedir,
        .staged_open = sd_gsiftp_staged_open,
        .staged_write = sd_gsiftp_staged_write,
        .staged_commit = sd_gsiftp_staged_commit,
        .staged_abort = sd_gsiftp_staged_abort,
        .open_cred = sd_gsiftp_open_cred,
        .staged_open_cred = sd_gsiftp_staged_open_cred,
        .stat_cred = sd_gsiftp_stat_cred,
        .unlink_cred = sd_gsiftp_unlink_cred,
        .mkdir_cred = sd_gsiftp_mkdir_cred,
        .rename_cred = sd_gsiftp_rename_cred,
        .opendir_cred = sd_gsiftp_opendir_cred,
    };

    return &brix_sd_gsiftp_driver;
}

static int
sd_gsiftp_cfg_valid(const brix_sd_gsiftp_cfg_t *cfg)
{
    return cfg != NULL && cfg->host != NULL && cfg->host[0] != '\0'
           && cfg->port >= 1 && cfg->port <= 65535;
}

static int
sd_gsiftp_fill_state(sd_gsiftp_state *state,
    const brix_sd_gsiftp_cfg_t *cfg)
{
    if (sd_gsiftp_copy(state->host, sizeof(state->host), cfg->host) != 0
        || sd_gsiftp_copy(state->base_path, sizeof(state->base_path),
                          cfg->base_path != NULL ? cfg->base_path : "") != 0
        || sd_gsiftp_copy(state->x509_proxy, sizeof(state->x509_proxy),
                          cfg->x509_proxy) != 0
        || sd_gsiftp_copy(state->ca_dir, sizeof(state->ca_dir),
                          cfg->ca_dir) != 0) {
        return -1;
    }
    if (state->base_path[0] != '\0'
        && !sd_gsiftp_logical_safe(state->base_path)) {
        errno = EINVAL;
        return -1;
    }
    while (state->base_path[1] != '\0'
           && state->base_path[strlen(state->base_path) - 1] == '/') {
        state->base_path[strlen(state->base_path) - 1] = '\0';
    }
    state->port = cfg->port;
    state->require_gsi = cfg->require_gsi != 0;
    state->timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : 30000;
    return 0;
}

static brix_sd_instance_t *
sd_gsiftp_alloc_instance(sd_gsiftp_state **state_out)
{
    brix_sd_instance_t *inst = calloc(1, sizeof(*inst));
    sd_gsiftp_state    *state = calloc(1, sizeof(*state));

    if (inst == NULL || state == NULL) {
        free(inst);
        free(state);
        errno = ENOMEM;
        return NULL;
    }
    *state_out = state;
    return inst;
}

brix_sd_instance_t *
brix_sd_gsiftp_create(const brix_sd_gsiftp_cfg_t *cfg, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    sd_gsiftp_state    *state;

    if (!sd_gsiftp_cfg_valid(cfg)) {
        errno = EINVAL;
        return NULL;
    }
    inst = sd_gsiftp_alloc_instance(&state);
    if (inst == NULL) {
        return NULL;
    }
    if (sd_gsiftp_fill_state(state, cfg) != 0) {
        free(state);
        free(inst);
        return NULL;
    }
    inst->driver = sd_gsiftp_driver();
    inst->log = log;
    inst->state = state;
    inst->caps = inst->driver->caps;
    inst->domain = BRIX_VFS_DOMAIN_EXPORT;
    return inst;
}

void
brix_sd_gsiftp_destroy(brix_sd_instance_t *inst)
{
    if (inst != NULL) {
        free(inst->state);
        free(inst);
    }
}

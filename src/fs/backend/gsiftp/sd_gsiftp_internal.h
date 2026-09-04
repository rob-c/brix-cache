#ifndef BRIX_SD_GSIFTP_INTERNAL_H
#define BRIX_SD_GSIFTP_INTERNAL_H

#include "sd_gsiftp.h"
#include "gftp_client.h"

#include <limits.h>

#define GSIFTP_PATH_CAP 2048

typedef struct {
    char host[256];
    int  port;
    char base_path[1024];
    int  require_gsi;
    char x509_proxy[PATH_MAX];
    char ca_dir[PATH_MAX];
    int  timeout_ms;
} sd_gsiftp_state;

typedef struct {
    char path[GSIFTP_PATH_CAP];
    char proxy[PATH_MAX];
} sd_gsiftp_obj_state;

int sd_gsiftp_copy(char *dst, size_t cap, const char *src);
int sd_gsiftp_path(const sd_gsiftp_state *state, const char *logical,
    char out[GSIFTP_PATH_CAP]);
const char *sd_gsiftp_proxy(const sd_gsiftp_state *state,
    const brix_sd_cred_t *cred, int *err_out);
int sd_gsiftp_select_proxy(const sd_gsiftp_state *state,
    const brix_sd_cred_t *cred, const char **proxy, int *err_out);
int sd_gsiftp_session(gftp_session_t *session, const sd_gsiftp_state *state,
    const char *proxy);
ngx_int_t sd_gsiftp_stat_impl(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);

brix_sd_obj_t *sd_gsiftp_open(brix_sd_instance_t *inst, const char *path,
    int flags, mode_t mode, int *err_out);
brix_sd_obj_t *sd_gsiftp_open_cred(brix_sd_instance_t *inst, const char *path,
    int flags, mode_t mode, const brix_sd_cred_t *cred, int *err_out);
ngx_int_t sd_gsiftp_close(brix_sd_obj_t *obj);
ssize_t sd_gsiftp_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ssize_t sd_gsiftp_preadv(brix_sd_obj_t *obj, const struct iovec *iov,
    int iovcnt, off_t off);
ngx_int_t sd_gsiftp_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);

ngx_int_t sd_gsiftp_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_gsiftp_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);
ngx_int_t sd_gsiftp_unlink(brix_sd_instance_t *inst, const char *path,
    int is_dir);
ngx_int_t sd_gsiftp_unlink_cred(brix_sd_instance_t *inst, const char *path,
    int is_dir, const brix_sd_cred_t *cred);
ngx_int_t sd_gsiftp_mkdir(brix_sd_instance_t *inst, const char *path,
    mode_t mode);
ngx_int_t sd_gsiftp_mkdir_cred(brix_sd_instance_t *inst, const char *path,
    mode_t mode, const brix_sd_cred_t *cred);
ngx_int_t sd_gsiftp_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace);
ngx_int_t sd_gsiftp_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred);
brix_sd_dir_t *sd_gsiftp_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
brix_sd_dir_t *sd_gsiftp_opendir_cred(brix_sd_instance_t *inst,
    const char *path, int *err_out, const brix_sd_cred_t *cred);
ngx_int_t sd_gsiftp_readdir(brix_sd_dir_t *dir, brix_sd_dirent_t *out);
ngx_int_t sd_gsiftp_closedir(brix_sd_dir_t *dir);

brix_sd_staged_t *sd_gsiftp_staged_open(brix_sd_instance_t *inst,
    const char *path, mode_t mode, off_t size, int *err_out);
brix_sd_staged_t *sd_gsiftp_staged_open_cred(brix_sd_instance_t *inst,
    const char *path, mode_t mode, off_t size, const brix_sd_cred_t *cred,
    int *err_out);
ssize_t sd_gsiftp_staged_write(brix_sd_staged_t *st, const void *buf,
    size_t len, off_t off);
ngx_int_t sd_gsiftp_staged_commit(brix_sd_staged_t *st,
    brix_sd_precond_t *pre);
void sd_gsiftp_staged_abort(brix_sd_staged_t *st);

#endif /* BRIX_SD_GSIFTP_INTERNAL_H */

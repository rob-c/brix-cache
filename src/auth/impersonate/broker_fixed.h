/* Fixed-identity helper pool: private broker lifecycle/dispatch contract.
 * Requires: broker_internal.h (credential and operation context types).
 * Each entry owns a process descriptor and private channel; no helper retains
 * a saved privileged identity or can switch to another mapped account.
 */
#pragma once

#define BRIX_IMP_FIXED_MAX 256u

typedef struct {
    struct {
        brix_idmap_creds_t creds;
        int channel;
        int process_fd;
    } entries[BRIX_IMP_FIXED_MAX];
    size_t count;
} brix_imp_fixed_pool_t;

brix_imp_fixed_pool_t *brix_imp_fixed_pool_start(int listenfd, int rootfd,
                                               ngx_log_t *log);
void brix_imp_fixed_pool_close(brix_imp_fixed_pool_t *pool);
int brix_imp_fixed_pool_dispatch(brix_imp_fixed_pool_t *pool,
    const brix_idmap_creds_t *creds, imp_op_ctx_t *operation);
int brix_imp_fixed_drop(const brix_idmap_creds_t *creds);
int brix_imp_fixed_creds_equal(const brix_idmap_creds_t *left,
                              const brix_idmap_creds_t *right);
int brix_imp_fixed_spawn(int rootfd, const brix_idmap_creds_t *creds,
    int *channel, int *process_fd, ngx_log_t *log);
void brix_imp_fixed_serve(int channel, int rootfd,
    const brix_idmap_creds_t *creds, ngx_log_t *log);

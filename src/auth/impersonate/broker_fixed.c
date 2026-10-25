/* Bounded fixed-identity helpers and an irreversibly non-root supervisor.
 * The initial account catalogue is frozen before privilege loss. Unknown/new
 * credentials fail closed until a broker restart; requests never fork as root.
 * Linux retains its capability broker. This optional native model is selected
 * by the PAL feature contract, not OS tests in authentication code.
 */
#include "broker_internal.h"
#include "broker_fixed.h"
#include "client_internal.h"
#include "idmap_internal.h"
#include <pwd.h>

/* WHAT: Compare complete credentials, independent of group enumeration order.
 * WHY: A uid match alone could retain removed or foreign supplementary grants.
 * HOW: Require equal uid/gid/count and membership for every bounded group. */
int
brix_imp_fixed_creds_equal(const brix_idmap_creds_t *left,
                           const brix_idmap_creds_t *right)
{
    uint64_t matched = 0;

    if (left->uid != right->uid || left->gid != right->gid
        || left->ngroups != right->ngroups || left->ngroups < 0
        || left->ngroups > BRIX_IDMAP_MAXGROUPS)
    {
        return 0;
    }
    for (int index = 0; index < left->ngroups; index++) {
        int present = 0;
        for (int other = 0; other < right->ngroups; other++) {
            uint64_t bit = UINT64_C(1) << other;
            if (!(matched & bit) && left->groups[index] == right->groups[other]) {
                matched |= bit;
                present = 1;
                break;
            }
        }
        if (!present) { return 0; }
    }
    return 1;
}

#if BRIX_HAS_FIXED_ID_BROKER

/* WHAT: Release only this pool's descriptors and their kernel-owned children.
 * WHY: Supervisor failure must not strand helpers or kill reused numeric pids.
 * HOW: Close each channel and process descriptor, then free the pool. */
void
brix_imp_fixed_pool_close(brix_imp_fixed_pool_t *pool)
{
    if (pool == NULL) { return; }
    for (size_t index = 0; index < pool->count; index++) {
        if (pool->entries[index].channel >= 0) {
            close(pool->entries[index].channel);
        }
        close(pool->entries[index].process_fd);
    }
    ngx_free(pool);
}

/* WHAT: Snapshot potentially eligible account names without nesting NSS scans.
 * WHY: getpwnam/getgrouplist can invalidate getpwent's shared iteration state.
 * HOW: Copy bounded names, excluding obvious reserved/service identities;
 * membership/deny-list resolution happens only after endpwent. */
static int
fixed_account_names(char (*names)[IMP_PRINC_MAX], size_t *count)
{
    struct passwd *account;

    *count = 0;
    setpwent();
    for (;;) {
        errno = 0;
        account = getpwent();
        if (account == NULL) { break; }
        if (account->pw_uid < brix_idmap_get_min_uid()
            || account->pw_uid == brix_imp_get_broker_user_uid()
            || account->pw_uid == brix_imp_get_broker_allow_uid())
        {
            continue;
        }
        size_t length = strlen(account->pw_name);
        if (*count == BRIX_IMP_FIXED_MAX || length >= IMP_PRINC_MAX) {
            endpwent();
            errno = E2BIG;
            return -1;
        }
        ngx_memcpy(names[(*count)++], account->pw_name, length + 1);
    }
    int status = errno == 0 ? 0 : -1;
    endpwent();
    return status;
}

/* WHAT: Add one permitted complete identity, deduplicating true aliases.
 * WHY: Both mapping policy and the syscall-edge hard floor remain authoritative.
 * HOW: Resolve via the existing mapper, reject forbidden credentials, then
 * spawn a bounded helper only when no exact identity already exists. */
static int
fixed_add_account(brix_imp_fixed_pool_t *pool, const char *name, int rootfd,
                  ngx_log_t *log)
{
    brix_idmap_creds_t creds;
    size_t index = pool->count;

    ngx_memzero(&creds, sizeof(creds));
    if (idmap_resolve_user(name, &creds) != 0 || !idmap_creds_allowed(&creds)
        || brix_imp_creds_privileged(&creds, BRIX_IMP_HARD_MIN_ID, NULL, NULL))
    {
        return 0;
    }
    for (size_t prior = 0; prior < index; prior++) {
        if (brix_imp_fixed_creds_equal(&creds, &pool->entries[prior].creds)) {
            return 0;
        }
    }
    if (index == BRIX_IMP_FIXED_MAX) { errno = E2BIG; return -1; }
    if (brix_imp_fixed_spawn(rootfd, &creds, &pool->entries[index].channel,
                            &pool->entries[index].process_fd, log) != 0)
    {
        return -1;
    }
    pool->entries[index].creds = creds;
    pool->count++;
    return 0;
}

/* WHAT: Build all helper identities from a bounded, frozen account snapshot.
 * WHY: No runtime request may require the supervisor to regain root or fork it.
 * HOW: Own the name scratch allocation, enumerate first, then resolve/spawn. */
static int
fixed_populate(brix_imp_fixed_pool_t *pool, int rootfd, ngx_log_t *log)
{
    char (*names)[IMP_PRINC_MAX];
    size_t count = 0;
    int status;

    names = ngx_alloc(BRIX_IMP_FIXED_MAX * IMP_PRINC_MAX, log);
    if (names == NULL) { return -1; }
    status = fixed_account_names(names, &count);
    for (size_t index = 0; status == 0 && index < count; index++) {
        status = fixed_add_account(pool, names[index], rootfd, log);
    }
    ngx_free(names);
    return status;
}

/* WHAT: Start fixed helpers then irreversibly drop the supervising broker.
 * WHY: Neither the supervisor nor any serving helper may retain saved root.
 * HOW: Require a dedicated service account, populate helpers, drop all service
 * uid/gid slots, close the supervisor's export root and report its identity. */
brix_imp_fixed_pool_t *
brix_imp_fixed_pool_start(int listenfd, int rootfd, ngx_log_t *log)
{
    brix_imp_fixed_pool_t *pool;
    brix_idmap_creds_t service;

    (void) listenfd;
    ngx_memzero(&service, sizeof(service));
    service.uid = brix_imp_get_broker_user_uid();
    service.gid = brix_imp_get_broker_user_gid();
    service.ngroups = 1;
    service.groups[0] = service.gid;
    if (getuid() != 0 || service.uid == (uid_t) -1 || service.uid == 0
        || service.gid == (gid_t) -1 || service.gid == 0)
    {
        BRIX_LOG(NGX_LOG_EMERG, log, 0,
            "impersonate: fixed-identity broker requires a dedicated non-root "
            "brix_idmap_broker_user; refusing a root-equivalent fallback");
        errno = EPERM;
        return NULL;
    }
    pool = ngx_alloc(sizeof(*pool), log);
    if (pool == NULL) { return NULL; }
    ngx_memzero(pool, sizeof(*pool));
    if (fixed_populate(pool, rootfd, log) != 0
        || brix_imp_fixed_drop(&service) != 0)
    {
        BRIX_LOG(NGX_LOG_EMERG, log, ngx_errno,
            "impersonate: fixed-identity helper setup failed; refusing to serve");
        brix_imp_fixed_pool_close(pool);
        return NULL;
    }
    close(rootfd);
    BRIX_LOG(NGX_LOG_NOTICE, log, 0,
        "impersonate: non-root fixed-identity supervisor uid=%d helpers=%uz; "
        "all serving identities permanently dropped root",
        (int) service.uid, pool->count);
    return pool;
}

/* WHAT: Forward an authorized operation to its exact fixed-identity helper.
 * WHY: New/group-changed identities or dead helpers must never fall back to
 * service/root I/O, and mutations must not be replayed after transport failure.
 * HOW: Match complete credentials, exchange once through the shared codec;
 * permanently close a broken channel and return an explicit I/O error. */
int
brix_imp_fixed_pool_dispatch(brix_imp_fixed_pool_t *pool,
    const brix_idmap_creds_t *creds, imp_op_ctx_t *operation)
{
    for (size_t index = 0; index < pool->count; index++) {
        if (!brix_imp_fixed_creds_equal(creds, &pool->entries[index].creds)) {
            continue;
        }
        int channel = pool->entries[index].channel;
        if (channel < 0) { return -EIO; }
        if (imp_write_full(channel, operation->req, sizeof(*operation->req)) == 0
            && (operation->data_in_len == 0
                || imp_write_full(channel, operation->data_in,
                                  operation->data_in_len) == 0)
            && imp_recv_reply(channel, operation->rep, operation->out_fd,
                operation->data_out, operation->data_max) == 0)
        {
            return operation->rep->status;
        }
        close(channel);
        pool->entries[index].channel = -1;
        return -EIO;
    }
    return -EACCES;
}
#endif

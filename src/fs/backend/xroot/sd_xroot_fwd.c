/*
 * sd_xroot_fwd.c — forwarding root:// proxy driver: lifecycle, key→child
 *                  resolution, and the open / opendir / staged_open family.
 *
 * See sd_xroot_fwd.h for the WHAT/WHY/HOW.  The object-keyed relays live in
 * sd_xroot_fwd_obj.c and the namespace relays in sd_xroot_fwd_ns.c; this file
 * owns the driver table that binds all three.
 */
#include "sd_xroot_fwd_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const brix_sd_driver_t  brix_sd_xroot_fwd_driver;

/* ---- template + state -------------------------------------------------- */

/* Copy one optional template string into instance storage; the template
 * pointer is then re-aimed at the copy (NULL when unset). */
static const char *
sd_xroot_fwd_copy_opt(char *dst, size_t cap, const char *src)
{
    if (src == NULL || src[0] == '\0') {
        dst[0] = '\0';
        return NULL;
    }
    ngx_cpystrn((u_char *) dst, (u_char *) src, cap);
    return dst;
}

static void
sd_xroot_fwd_state_init(sd_xroot_fwd_inst_state *st,
    const brix_sd_xroot_fwd_cfg_t *cfg)
{
    const brix_sd_xroot_origin_cfg_t *o = &cfg->origin;

    st->tmpl.af_policy    = o->af_policy;
    st->tmpl.verify_pages = o->verify_pages;
    st->tmpl.nearline     = o->nearline;
    st->tmpl.dns          = o->dns;
    st->tmpl.bearer     = sd_xroot_fwd_copy_opt(st->bearer,
                                                sizeof(st->bearer), o->bearer);
    st->tmpl.x509_proxy = sd_xroot_fwd_copy_opt(st->x509_proxy,
                                                sizeof(st->x509_proxy),
                                                o->x509_proxy);
    st->tmpl.x509_key   = sd_xroot_fwd_copy_opt(st->x509_key,
                                                sizeof(st->x509_key),
                                                o->x509_key);
    st->tmpl.ca_dir     = sd_xroot_fwd_copy_opt(st->ca_dir, sizeof(st->ca_dir),
                                                o->ca_dir);
    st->tmpl.sss_keytab = sd_xroot_fwd_copy_opt(st->sss_keytab,
                                                sizeof(st->sss_keytab),
                                                o->sss_keytab);
    ngx_cpystrn((u_char *) st->permit, (u_char *) cfg->permit,
                sizeof(st->permit));
    st->allow_root  = cfg->allow_root ? 1 : 0;
    st->allow_roots = cfg->allow_roots ? 1 : 0;
}

brix_sd_instance_t *
brix_sd_xroot_fwd_create(const brix_sd_xroot_fwd_cfg_t *cfg, ngx_log_t *log)
{
    brix_sd_instance_t      *inst;
    sd_xroot_fwd_inst_state  *st;

    if (cfg == NULL || cfg->permit == NULL || cfg->permit[0] == '\0'
        || (!cfg->allow_root && !cfg->allow_roots))
    {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    st   = calloc(1, sizeof(*st));
    if (inst == NULL || st == NULL) {
        free(inst);
        free(st);
        errno = ENOMEM;
        return NULL;
    }
    sd_xroot_fwd_state_init(st, cfg);
    if (pthread_mutex_init(&st->mtx, NULL) != 0) {
        free(inst);
        free(st);
        errno = ENOMEM;
        return NULL;
    }
    inst->driver = &brix_sd_xroot_fwd_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = st;
    /* Same caps as one origin — the operator's `nearline` arms recall on
     * every child exactly as it does on a fixed root+tape:// origin. */
    inst->caps   = brix_sd_xroot_fwd_driver.caps;
    if (cfg->origin.nearline) {
        inst->caps |= BRIX_SD_CAP_NEARLINE;
    }
    inst->domain = BRIX_VFS_DOMAIN_EXPORT;
    return inst;
}

void
brix_sd_xroot_fwd_destroy(brix_sd_instance_t *inst)
{
    sd_xroot_fwd_inst_state  *st;
    sd_xroot_fwd_child_t     *c, *next;

    if (inst == NULL) {
        return;
    }
    st = inst->state;
    if (st != NULL) {
        for (c = st->children; c != NULL; c = next) {
            next = c->next;
            brix_sd_xroot_destroy(c->inst);
            free(c);
        }
        pthread_mutex_destroy(&st->mtx);
        free(st);
    }
    free(inst);
}

int
brix_sd_xroot_serves(const brix_sd_instance_t *inst)
{
    const char *name = brix_sd_backend_name(inst);

    return ngx_strcmp(name, "xroot") == 0
           || ngx_strcmp(name, brix_sd_xroot_fwd_driver.name) == 0;
}

const brix_sd_driver_t *
sd_xroot_fwd_relay_driver(const brix_sd_driver_t *d)
{
    return (d == NULL || d == &brix_sd_xroot_fwd_driver) ? NULL : d;
}

/* ---- key → child ------------------------------------------------------- */

static sd_xroot_fwd_child_t *
sd_xroot_fwd_child_find(const sd_xroot_fwd_inst_state *st,
    const brix_sd_xroot_fwd_target_t *t)
{
    sd_xroot_fwd_child_t *c;

    for (c = st->children; c != NULL; c = c->next) {
        if (c->port == t->port && c->tls == t->tls
            && strcasecmp(c->host, t->host) == 0)
        {
            return c;
        }
    }
    return NULL;
}

/* Create the sd_xroot child for `t` from the template and link it.  Caller
 * holds st->mtx.  NULL with errno on the cap or the factory's failure. */
static sd_xroot_fwd_child_t *
sd_xroot_fwd_child_new(brix_sd_instance_t *inst, sd_xroot_fwd_inst_state *st,
    const brix_sd_xroot_fwd_target_t *t)
{
    brix_sd_xroot_origin_cfg_t  cfg = st->tmpl;
    sd_xroot_fwd_child_t       *c;

    if (st->nchildren >= SD_XROOT_FWD_MAX_CHILDREN) {
        ngx_log_error(NGX_LOG_ERR, inst->log, 0,
            "brix: forward: origin table full (%ud distinct origins), "
            "refusing %s:%d", st->nchildren, t->host, t->port);
        errno = EMFILE;
        return NULL;
    }
    c = calloc(1, sizeof(*c));
    if (c == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    cfg.host = t->host;
    cfg.port = t->port;
    cfg.tls  = t->tls;
    c->inst = brix_sd_xroot_create_origin(&cfg, inst->log);
    if (c->inst == NULL) {
        int saved = errno;

        free(c);
        errno = saved;
        return NULL;
    }
    c->inst->domain = inst->domain;
    ngx_cpystrn((u_char *) c->host, (u_char *) t->host, sizeof(c->host));
    c->port = t->port;
    c->tls  = t->tls;
    c->next = st->children;
    st->children = c;
    st->nchildren++;
    ngx_log_error(NGX_LOG_INFO, inst->log, 0,
        "brix: forward: origin %s://%s:%d admitted (%ud of %d)",
        t->tls ? "roots" : "root", t->host, t->port, st->nchildren,
        SD_XROOT_FWD_MAX_CHILDREN);
    return c;
}

/* The two admission verdicts, in the order a refusal should be reported: a
 * scheme outside the protocol list is a client error (kXR_Unsupported); a
 * host outside the permit list is the security refusal (kXR_NotAuthorized)
 * and is logged as such. */
static int
sd_xroot_fwd_admit(brix_sd_instance_t *inst, const sd_xroot_fwd_inst_state *st,
    const brix_sd_xroot_fwd_target_t *t)
{
    if ((t->tls && !st->allow_roots) || (!t->tls && !st->allow_root)) {
        return ENOTSUP;
    }
    if (!brix_sd_xroot_fwd_host_permitted(st->permit, t->host)) {
        ngx_log_error(NGX_LOG_NOTICE, inst->log, 0,
            "brix: forward: origin \"%s\" is not in the permit list — refused",
            t->host);
        return EACCES;
    }
    return 0;
}

int
brix_sd_xroot_fwd_admit_key(brix_sd_instance_t *inst, const char *key)
{
    brix_sd_xroot_fwd_target_t  t;
    int                          rc;

    if (inst == NULL || inst->driver != &brix_sd_xroot_fwd_driver) {
        return 0;
    }
    rc = brix_sd_xroot_fwd_parse_key(key, &t);
    if (rc != 0) {
        return rc;
    }
    return sd_xroot_fwd_admit(inst, inst->state, &t);
}

brix_sd_instance_t *
sd_xroot_fwd_resolve(brix_sd_instance_t *inst, const char *key,
    brix_sd_xroot_fwd_target_t *t)
{
    sd_xroot_fwd_inst_state  *st = inst->state;
    sd_xroot_fwd_child_t     *c;
    int                       rc;

    rc = brix_sd_xroot_fwd_parse_key(key, t);
    if (rc == 0) {
        rc = sd_xroot_fwd_admit(inst, st, t);
    }
    if (rc != 0) {
        errno = rc;
        return NULL;
    }
    pthread_mutex_lock(&st->mtx);
    c = sd_xroot_fwd_child_find(st, t);
    if (c == NULL) {
        c = sd_xroot_fwd_child_new(inst, st, t);
    }
    pthread_mutex_unlock(&st->mtx);
    return (c != NULL) ? c->inst : NULL;
}

/* Every handle-returning slot reports its failure through *err_out AND errno
 * (the sd_xroot convention); the resolver only sets errno. */
static void
sd_xroot_fwd_fail_open(int *err_out)
{
    if (err_out != NULL) {
        *err_out = errno;
    }
}

/* ---- open / opendir / staged_open ------------------------------------ */

static brix_sd_obj_t *
sd_xroot_fwd_open_cred(brix_sd_instance_t *inst, const char *path,
    int sd_flags, mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    brix_sd_xroot_fwd_target_t  t;
    brix_sd_instance_t        *child = sd_xroot_fwd_resolve(inst, path, &t);

    if (child == NULL) {
        sd_xroot_fwd_fail_open(err_out);
        return NULL;
    }
    return brix_sd_open_maybe_cred(child, t.path, sd_flags, mode, cred,
                                   err_out);
}

static brix_sd_obj_t *
sd_xroot_fwd_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    return sd_xroot_fwd_open_cred(inst, path, sd_flags, mode, NULL, err_out);
}

static brix_sd_obj_t *
sd_xroot_fwd_open_hinted(brix_sd_instance_t *inst, const char *path,
    int sd_flags, mode_t mode, const brix_sd_cred_t *cred,
    const brix_sd_open_hints_t *hints, int *err_out)
{
    brix_sd_xroot_fwd_target_t  t;
    brix_sd_instance_t        *child = sd_xroot_fwd_resolve(inst, path, &t);

    if (child == NULL) {
        sd_xroot_fwd_fail_open(err_out);
        return NULL;
    }
    return brix_sd_open_hinted_maybe_cred(child, t.path, sd_flags, mode, cred,
                                          hints, err_out);
}

static brix_sd_dir_t *
sd_xroot_fwd_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred)
{
    brix_sd_xroot_fwd_target_t  t;
    brix_sd_instance_t        *child = sd_xroot_fwd_resolve(inst, path, &t);

    if (child == NULL) {
        sd_xroot_fwd_fail_open(err_out);
        return NULL;
    }
    return brix_sd_opendir_maybe_cred(child, t.path, err_out, cred);
}

static brix_sd_dir_t *
sd_xroot_fwd_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    return sd_xroot_fwd_opendir_cred(inst, path, err_out, NULL);
}

static brix_sd_staged_t *
sd_xroot_fwd_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, const brix_sd_cred_t *cred,
    int *err_out)
{
    brix_sd_xroot_fwd_target_t  t;
    brix_sd_instance_t        *child = sd_xroot_fwd_resolve(inst, final_path,
                                                            &t);

    if (child == NULL) {
        sd_xroot_fwd_fail_open(err_out);
        return NULL;
    }
    return brix_sd_staged_open_maybe_cred(child, t.path, mode, declared_size,
                                          cred, err_out);
}

static brix_sd_staged_t *
sd_xroot_fwd_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, int *err_out)
{
    return sd_xroot_fwd_staged_open_cred(inst, final_path, mode, declared_size,
                                         NULL, err_out);
}

/* ---- driver table ------------------------------------------------------ */

/* The slot set is sd_xroot's minus `space`: a forwarding export has no single
 * origin whose free space could be reported.  Caps and cred_accept are
 * sd_xroot's — every object here IS an sd_xroot object. */
static const brix_sd_driver_t brix_sd_xroot_fwd_driver = {
    .name          = "xroot_fwd",
    .caps      = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
                 | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
                 | BRIX_SD_CAP_XATTR_WRITE
                 | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_SERVER_COPY
                 | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_DIRS_WRITE
                 | BRIX_SD_CAP_MEMFILE | BRIX_SD_CAP_BLOCKING_WIRE,
    .cred_accept = BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM
                 | BRIX_SD_CRED_SSS | BRIX_SD_CRED_GSS_KRB5,
    .open          = sd_xroot_fwd_open,
    .open_cred     = sd_xroot_fwd_open_cred,
    .open_hinted   = sd_xroot_fwd_open_hinted,
    .close         = sd_xroot_fwd_close,
    .pread         = sd_xroot_fwd_pread,
    .preadv        = sd_xroot_fwd_preadv,
    .pwrite        = sd_xroot_fwd_pwrite,
    .fstat         = sd_xroot_fwd_fstat,
    .ftruncate     = sd_xroot_fwd_ftruncate,
    .fsync         = sd_xroot_fwd_fsync,
    .query_checksum = sd_xroot_fwd_query_checksum,
    .stat          = sd_xroot_fwd_stat,
    .stat_cred     = sd_xroot_fwd_stat_cred,
    .unlink        = sd_xroot_fwd_unlink,
    .unlink_cred   = sd_xroot_fwd_unlink_cred,
    .mkdir         = sd_xroot_fwd_mkdir,
    .mkdir_cred    = sd_xroot_fwd_mkdir_cred,
    .rename        = sd_xroot_fwd_rename,
    .rename_cred   = sd_xroot_fwd_rename_cred,
    .server_copy   = sd_xroot_fwd_server_copy,
    .server_copy_cred = sd_xroot_fwd_server_copy_cred,
    .setattr       = sd_xroot_fwd_setattr,
    .setattr_cred  = sd_xroot_fwd_setattr_cred,
    .truncate_path = sd_xroot_fwd_truncate_path,
    .truncate_path_cred = sd_xroot_fwd_truncate_path_cred,
    .getxattr      = sd_xroot_fwd_getxattr,
    .getxattr_cred = sd_xroot_fwd_getxattr_cred,
    .listxattr     = sd_xroot_fwd_listxattr,
    .listxattr_cred = sd_xroot_fwd_listxattr_cred,
    .setxattr      = sd_xroot_fwd_setxattr,
    .setxattr_cred = sd_xroot_fwd_setxattr_cred,
    .removexattr   = sd_xroot_fwd_removexattr,
    .removexattr_cred = sd_xroot_fwd_removexattr_cred,
    .opendir       = sd_xroot_fwd_opendir,
    .opendir_cred  = sd_xroot_fwd_opendir_cred,
    .readdir       = sd_xroot_fwd_readdir,
    .closedir      = sd_xroot_fwd_closedir,
    .staged_open   = sd_xroot_fwd_staged_open,
    .staged_open_cred = sd_xroot_fwd_staged_open_cred,
    .staged_write  = sd_xroot_fwd_staged_write,
    .staged_commit = sd_xroot_fwd_staged_commit,
    .staged_abort  = sd_xroot_fwd_staged_abort,
    /* Nearline pair: reached only when the template arms CAP_NEARLINE. */
    .recall        = sd_xroot_fwd_recall,
    .recall_cred   = sd_xroot_fwd_recall_cred,
    .residency     = sd_xroot_fwd_residency,
    .evict         = sd_xroot_fwd_evict,
    .evict_cred    = sd_xroot_fwd_evict_cred,
};

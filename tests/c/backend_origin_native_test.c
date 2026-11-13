/* Origin configuration must retain its declared namespace and reject bad syntax. */
#include "fs/vfs/vfs_backend_config_internal.h"
#include <assert.h>

/* WHAT: Dispatch one public origin grammar without resolving an endpoint.
 * WHY: Parsing must work for unavailable origins and never broaden a protocol set.
 * HOW: Link the configured production parsers and inspect their registry output. */
static ngx_int_t parse(ngx_conf_t *cf, const char *family, const char *root,
    const ngx_str_t *value)
{
    if (!strcmp(family, "ceph")) { return vfs_parse_ceph_origin(cf, root, value); }
    if (!strcmp(family, "rados")) { return vfs_parse_rados_origin(cf, root, value); }
    if (!strcmp(family, "cephfs")) { return vfs_parse_cephfsro_origin(cf, root, value); }
    if (!strcmp(family, "tape")) { return vfs_parse_tape_origin(cf, root, value); }
    if (!strcmp(family, "s3")) { return vfs_parse_s3_origin(cf, root, value); }
    if (!strcmp(family, "ftp")) { return vfs_parse_gsiftp_origin(cf, root, value); }
    if (!strcmp(family, "forward")) { return vfs_parse_forward_origin(cf, root, value, 0); }
    assert(!strcmp(family, "root"));
    return vfs_parse_xroot_or_driver_origin(cf, root, value, 4096, 0);
}

/* WHAT: Observe configuration as stored for later worker initialization.
 * WHY: A successful return is insufficient if a path, identity or TLS bit changes.
 * HOW: Emit a bounded key/value view of the real registry entry. */
static void describe(const brix_vfs_backend_entry_t *e)
{
    if (!e) { puts("registered=0"); return; }
    printf("registered=1\nbackend=%s\nhost=%s\nport=%d\ntls=%d\npath=%s\n",
        e->backend, e->origin_host, e->origin_port, e->origin_tls, e->origin_path);
    printf("pool=%s\nconf=%s\nprefix=%s\ndata_pool=%s\nquiesced=%d\nlive=%d\n",
        e->ceph_pool, e->ceph_conf, e->ceph_key_prefix, e->ceph_data_pool,
        e->cephfs_quiesced, e->cephfs_live);
    printf("arc=%u\nnearline=%d\nrestore_days=%d\nchecksum=%d\nroot=%u\nroots=%u\n",
        e->tape_arc_depth, e->origin_nearline, e->origin_restore_days,
        e->origin_put_checksum, e->origin_fwd_allow_root, e->origin_fwd_allow_roots);
    assert(e->inst == NULL);
}

/* WHAT: Exercise full-registry refusal without changing an existing export.
 * WHY: Capacity pressure must never replace a different export's configuration.
 * HOW: Fill every real slot with a unique root, then parse a new root. */
static void saturate(void)
{
    for (unsigned i = 0; i < BRIX_VFS_BACKEND_MAX; i++) {
        char path[64]; snprintf(path, sizeof(path), "/reserved/%u", i);
        brix_vfs_backend_entry_t *e = brix_vfs_backend_entry_claim(path, "posix");
        assert(e && !strcmp(e->root_canon, path));
    }
    assert(!brix_vfs_backend_entry_get_or_create("/overflow"));
}

int main(int argc, char **argv)
{
    assert(argc == 5);
    ngx_log_t log = {0}; ngx_open_file_t output = {.fd = STDERR_FILENO};
    log.file = &output; log.log_level = NGX_LOG_EMERG;
    ngx_time_init();
    assert(ngx_strerror_init() == NGX_OK);
    ngx_cycle_t cycle = {.log = &log}; ngx_cycle = &cycle;
    ngx_conf_file_t file = {0}; ngx_str_set(&file.file.name, "origin-fixture.conf");
    ngx_conf_t cf = {.cycle = &cycle, .log = &log, .conf_file = &file};
    ngx_str_t value = {.len = strlen(argv[2]), .data = (u_char *) argv[2]};
    const char *root = !strcmp(argv[3], "empty") ? "" : "/origin-fixture";
    if (!strcmp(argv[3], "full")) { saturate(); }
    ngx_int_t rc = parse(&cf, argv[1], root, &value);
    assert(rc == atol(argv[4]));
    brix_vfs_backend_entry_t *entry = brix_vfs_backend_entry_find(root);
    if (rc != NGX_OK) { assert(entry == NULL); }
    describe(entry);
    return 0;
}

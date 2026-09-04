/*
 * vfs_backend_config_internal.h — cross-file glue for the backend-config
 * scheme-parser split (phase-79 file-size cap).
 *
 * WHAT: The shared origin-segment parse record (vfs_origin_parse_t) plus the
 *       extern declarations for the per-scheme origin parsers that the
 *       brix_vfs_backend_config_str dispatcher (vfs_backend_config.c) calls
 *       across translation units:
 *         - ceph / rados / cephfsro / tape → vfs_backend_config_ceph.c
 *         - http origin list              → vfs_backend_config_http.c
 *         - s3 / root(s):// driver        → vfs_backend_config_s3.c
 * WHY:  vfs_backend_config.c grew past the 500-line cap. Splitting the scheme
 *       parsers into three cohesive files needs one place to publish the parse
 *       record shared by the http and s3 parsers and the dispatcher entry
 *       points; keeping it here (not the public vfs_backend_registry.h) keeps
 *       these purely internal to the registry's config half.
 * HOW:  Every config-half translation unit includes vfs_backend_internal.h then
 *       this header. The seven dispatcher entry points are non-static and
 *       declared below; each per-driver entry builder stays static in the file
 *       that owns its scheme.
 */
#ifndef BRIX_VFS_BACKEND_CONFIG_INTERNAL_H
#define BRIX_VFS_BACKEND_CONFIG_INTERNAL_H

#include "vfs_backend_internal.h"

/*
 * vfs_origin_parse_t — the shared output record for the http:// and s3://
 * origin-segment parsers.
 *
 * WHAT: One caller-owned bundle carrying an origin segment's parse result —
 *       the host and base/bucket destination buffers (with their capacities),
 *       the resolved port and TLS flag, plus a `host_len` scratch slot the
 *       host/port splitter writes and the scheme stripper's `rest`/`rest_len`
 *       intermediates.
 * WHY:  The parse pipeline (strip scheme → split host:port → copy out) threaded
 *       the same host/port/tls/base four-tuple through every stage as separate
 *       by-value + out-pointer arguments, pushing each helper past the 5-param
 *       readability gate. Passing one pointer keeps the data flow explicit while
 *       collapsing the argument lists; behaviour is byte-for-byte identical
 *       (same buffers, same caps, same fields written).
 * HOW:  The caller stack-allocates and zero-inits one of these, sets `host`/
 *       `host_cap`/`base`/`base_cap` to its own char buffers, and passes its
 *       address down the pipeline. Each stage fills the fields it owns; the
 *       final stage copies the host and base into the caller's buffers.
 */
typedef struct {
    char    *host;       /* caller buffer for the NUL-terminated host          */
    size_t   host_cap;   /* capacity of `host` (incl. the NUL)                 */
    char    *base;       /* caller buffer for the base path (http) / bucket(s3)*/
    size_t   base_cap;   /* capacity of `base`                                 */
    int      port;       /* resolved port                                      */
    int      tls;        /* 1 iff https (http parser); 0 for s3                */
    size_t   host_len;   /* scratch: host length within the authority segment  */
    u_char  *rest;       /* scratch: segment remainder after the scheme        */
    size_t   rest_len;   /* scratch: length of `rest`                          */
} vfs_origin_parse_t;

/* Per-scheme origin parsers (dispatched by brix_vfs_backend_config_str). Each
 * returns NGX_OK on a handled+valid segment, NGX_ERROR after an [emerg] for a
 * malformed one, or NGX_DECLINED when the scheme is not theirs. */

/* ceph / rados / cephfsro / tape → vfs_backend_config_ceph.c */
ngx_int_t vfs_parse_cephfsro_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb);
ngx_int_t vfs_parse_ceph_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb);
ngx_int_t vfs_parse_rados_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb);
ngx_int_t vfs_parse_tape_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb);

/* http origin list → vfs_backend_config_http.c */
ngx_int_t vfs_parse_http_origin_list(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb);

/* ftp / gsiftp origin → vfs_backend_config_gsiftp.c */
ngx_int_t vfs_parse_gsiftp_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb);

/* s3 / root(s):// or local driver → vfs_backend_config_s3.c */
ngx_int_t vfs_parse_s3_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb);
ngx_int_t vfs_parse_xroot_or_driver_origin(ngx_conf_t *cf,
    const char *root_canon, const ngx_str_t *sb, size_t block_size, int family);

/* The shared head of every per-driver entry builder: get-or-create the export's
 * registry entry and stamp its backend name. NULL ⇒ registry full (the builder
 * gives up, matching get_or_create's contract). Defined in vfs_backend_config.c. */
brix_vfs_backend_entry_t *brix_vfs_backend_entry_claim(const char *root_canon,
    const char *backend);

/* Stamp one NUL-terminated string field of an entry (capacity-clamped). */
#define VFS_BE_STR(e, field, src) \
    ngx_cpystrn((u_char *) (e)->field, (u_char *) (src), sizeof((e)->field))

/* Read one "key=value" declaration out of an origin URL's query suffix into
 * out[cap] (always NUL-terminated; "" when the key is absent). `key` carries its
 * own '=' ("tape_api="). The value ends at '&', '|' (the T11 endpoint
 * separator) or end-of-string. Shared because the http and s3 origin grammars
 * carry the same query suffix and must read it identically — one place to get
 * the terminators right. Defined in vfs_backend_config.c. */
void brix_vfs_origin_opt_str(const u_char *spec, const char *key, char *out,
    size_t cap);

/* The integer form of the same read: the value parsed as a non-negative
 * decimal, or `dflt` when the key is absent or malformed. */
int brix_vfs_origin_opt_int(const u_char *spec, const char *key, int dflt);

/* Stamp the libcurl-origin endpoint fields shared by the http and s3 builders
 * (host/port/tls, origin_path = base path or bucket, the #12 PUT-checksum flag)
 * and invalidate the built instance. Defined in vfs_backend_config.c. */
void brix_vfs_backend_set_origin(brix_vfs_backend_entry_t *e, const char *host,
    int port, int tls, const char *path, int put_checksum);

#endif /* BRIX_VFS_BACKEND_CONFIG_INTERNAL_H */

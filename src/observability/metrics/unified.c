#include "unified_internal.h"
#include "core/types/identity.h"

#include <errno.h>

/*
 * unified.c — cross-protocol metric label tables and classification helpers.
 *
 * WHAT: Owns the shared label vocabulary for the unified metrics API declared in
 *       unified.h — the static name tables (proto/op/err/auth/tpc-direction) and
 *       the latency-bucket bound table — plus the name-lookup and classification
 *       helpers: brix_metric_proto_name / _op_name / _err_name, the auth-slot
 *       mapper (brix_metric_auth_slot) and its name form, and the errno→err /
 *       http-status→err classifiers. The record-side mutators live in
 *       unified_record.c and the Prometheus exporter in unified_export*.c.
 * WHY:  One vocabulary behind one exporter keeps every protocol plane's dashboard
 *       directly comparable and keeps labels low-cardinality (INVARIANT #8).
 *       Concentrating the tables and the pure classifiers here — separate from
 *       the SHM mutators and the exporter — keeps every file single-concern and
 *       under the file-size budget (coding-standards §1).
 * HOW:  Static name tables map each enum to its label string; three of them
 *       (auth names, tpc-direction names, latency bounds) are shared with the
 *       exporter/record files and so carry external linkage via
 *       unified_internal.h. The classification helpers are pure functions —
 *       table lookups and small switch/if ladders — with no SHM or I/O side
 *       effects, so they are trivially reusable across protocols.
 */

/* Generated from the central protocol declaration (core/types/proto_list.h). */
static const char *brix_unified_proto_names[BRIX_PROTO_COUNT] = {
#define X(ID, metric_label, dash_name, http_plane) metric_label,
    BRIX_PROTO_LIST(X)
#undef X
};

static const char *brix_unified_op_names[BRIX_METRIC_OP_COUNT] = {
    "read",
    "write",
    "stat",
    "delete",
    "mkdir",
    "rename",
    "dirlist",
    "tpc",
    "xattr",
    "copy",
};

static const char *brix_unified_err_names[BRIX_ERR_COUNT] = {
    "ok",
    "not_found",
    "forbidden",
    "io_error",
    "other",
};

/* Shared with the auth exporter (unified_export.c); declared in
 * unified_internal.h, so external linkage. */
const char *brix_unified_auth_names[BRIX_METRIC_AUTH_COUNT] = {
    "none",
    "gsi",
    "token",
    "sss",
    "s3key",
    "unix",
    "krb5",
    "host",
    "pwd",
};

/* Shared with the tpc exporter (unified_export.c); external linkage. */
const char *brix_unified_tpc_direction_names[
    BRIX_METRIC_TPC_DIRECTION_COUNT] =
{
    "pull",
    "push",
};

/* Shared with the tpc-delegation exporter (unified_export.c); external linkage.
 * Order matches brix_tpc_deleg_result_t. */
const char *brix_unified_tpc_deleg_result_names[
    BRIX_TPC_DELEG_RESULT_COUNT] =
{
    "ok",
    "expired",
    "absent",
};

/* Shared with the record hot path (unified_record.c) and the latency exporter
 * (unified_export_io.c); external linkage via unified_internal.h. */
const ngx_msec_t brix_latency_bounds[BRIX_IO_LATENCY_BUCKETS - 1] = {
    1000,
    5000,
    10000,
    50000,
    100000,
    500000,
    1000000,
    5000000,
};

const char *
brix_metric_proto_name(brix_proto_t proto)
{
    return proto < BRIX_PROTO_COUNT ? brix_unified_proto_names[proto]
                                      : "unknown";
}

const char *
brix_metric_op_name(brix_metric_op_t op)
{
    return op < BRIX_METRIC_OP_COUNT ? brix_unified_op_names[op]
                                       : "unknown";
}

const char *
brix_metric_err_name(brix_err_class_t err)
{
    return err < BRIX_ERR_COUNT ? brix_unified_err_names[err] : "other";
}

/* phase-110 W1: the ONE cache-disposition vocabulary. Every surface (both
 * planes' $brix_cache_status, the JSON access log's "cache_status", the
 * brix_cache_requests_total{cache_status} label) renders through this table, so
 * a grep, a `map` and a PromQL selector share a string by construction. */
static const char *brix_unified_cache_status_names[BRIX_CACHE_STATUS_COUNT] = {
    "-", "HIT", "MISS", "BYPASS", "NEGHIT"
};

const char *
brix_metric_cache_status_name(brix_cache_status_e status)
{
    return (ngx_uint_t) status < BRIX_CACHE_STATUS_COUNT
           ? brix_unified_cache_status_names[status] : "-";
}

/* Phase-70 delegation-gate label vocabularies (P90-70.6). Mode names mirror
 * the brix_backend_delegation directive enum; the fail names are the closed
 * reason set from unified.h. Out-of-range renders "unknown" so future enum
 * growth can never emit unbounded label values (INVARIANT #8). */
static const char *brix_unified_cred_mode_names[BRIX_CRED_MODE_METRIC_COUNT] =
{
    "select",
    "passthrough",
    "exchange",
    "delegate",
    "mint",
    "auto",
};

static const char *brix_unified_cred_fail_names[BRIX_CRED_FAIL_COUNT] =
{
    "missing",
    "kind",
    "pem",
    "chain",
    "materialise",
    "exchange",
};

const char *
brix_metric_cred_mode_name(ngx_uint_t mode)
{
    return mode < BRIX_CRED_MODE_METRIC_COUNT
        ? brix_unified_cred_mode_names[mode] : "unknown";
}

const char *
brix_metric_cred_fail_name(brix_cred_fail_t reason)
{
    return (ngx_uint_t) reason < BRIX_CRED_FAIL_COUNT
        ? brix_unified_cred_fail_names[reason] : "unknown";
}

/* Phase-105 bounded mutation-operation labels. Mirrors brix_vfs_mutation_op_t
 * (fs/vfs/vfs_policy.h) so the exporter needs no fs-layer include; vfs_policy.c
 * asserts the two stay the same length. */
static const char *brix_unified_vfs_mutate_op_names
    [BRIX_VFS_MUTATE_OP_METRIC_COUNT] =
{
    "open",
    "write",
    "truncate",
    "sync",
    "mkdir",
    "remove",
    "rename",
    "copy",
    "setattr",
    "xattr",
    "publish",
    "stage",
    "evict",
    "lock",
    "dedup",
    "credential",
};

const char *
brix_metric_vfs_mutate_op_name(ngx_uint_t op)
{
    return op < BRIX_VFS_MUTATE_OP_METRIC_COUNT
        ? brix_unified_vfs_mutate_op_names[op] : "unknown";
}

/* Phase-107 §7.5 bounded storage-domain labels. Mirrors brix_vfs_domain_t
 * (fs/backend/sd_domain.h) so the exporter needs no fs-layer include;
 * vfs_policy_domain.c asserts the two stay the same length. */
static const char *brix_unified_vfs_domain_names
    [BRIX_VFS_DOMAIN_METRIC_COUNT] =
{
    "export",
    "cache",
    "stage",
    "registry",
    "credential",
    "config",
    "journal",
};

const char *
brix_metric_vfs_domain_name(ngx_uint_t domain)
{
    return domain < BRIX_VFS_DOMAIN_METRIC_COUNT
        ? brix_unified_vfs_domain_names[domain] : "unknown";
}

/* Phase-108 C12 bounded authorization-backstop result labels. Mirrors
 * brix_authz_backstop_result_t (fs/vfs/vfs_authz.h) so the exporter needs no
 * fs-layer include; vfs_authz.c asserts the two stay the same length. */
static const char *brix_unified_vfs_authz_backstop_names
    [BRIX_AUTHZ_BACKSTOP_RESULT_COUNT] =
{
    "agree",
    "edge_missing",
    "no_rules",
    "unbound",
};

const char *
brix_metric_vfs_authz_backstop_result_name(ngx_uint_t result)
{
    return result < BRIX_AUTHZ_BACKSTOP_RESULT_COUNT
        ? brix_unified_vfs_authz_backstop_names[result] : "unknown";
}

/*
 * brix_metric_auth_slot — map an identity auth_method bitmask to one
 * BRIX_METRIC_AUTH_* slot. Tested in priority order (GSI, TOKEN, SSS, S3KEY,
 * UNIX, KRB5); returns BRIX_METRIC_AUTH_NONE when no known bit is set.
 */
ngx_uint_t
brix_metric_auth_slot(ngx_uint_t auth_method)
{
    if (auth_method & BRIX_AUTHN_GSI) {
        return BRIX_METRIC_AUTH_GSI;
    }
    if (auth_method & BRIX_AUTHN_TOKEN) {
        return BRIX_METRIC_AUTH_TOKEN;
    }
    if (auth_method & BRIX_AUTHN_SSS) {
        return BRIX_METRIC_AUTH_SSS;
    }
    if (auth_method & BRIX_AUTHN_S3KEY) {
        return BRIX_METRIC_AUTH_S3KEY;
    }
    if (auth_method & BRIX_AUTHN_UNIX) {
        return BRIX_METRIC_AUTH_UNIX;
    }
    if (auth_method & BRIX_AUTHN_KRB5) {
        return BRIX_METRIC_AUTH_KRB5;
    }
    if (auth_method & BRIX_AUTHN_HOST) {
        return BRIX_METRIC_AUTH_HOST;
    }
    if (auth_method & BRIX_AUTHN_PWD) {
        return BRIX_METRIC_AUTH_PWD;
    }

    return BRIX_METRIC_AUTH_NONE;
}

const char *
brix_metric_auth_method_name(ngx_uint_t auth_method)
{
    return brix_unified_auth_names[brix_metric_auth_slot(auth_method)];
}

/*
 * brix_metric_err_from_errno — classify a POSIX errno into an
 * brix_err_class_t bucket (0→NONE, ENOENT/ENOTDIR→NOT_FOUND,
 * EACCES/EPERM→FORBIDDEN, EIO/ENOMEM/ENOSPC→IO, else OTHER).
 */
brix_err_class_t
brix_metric_err_from_errno(int sys_errno)
{
    switch (sys_errno) {
    case 0:
        return BRIX_ERR_NONE;
    case ENOENT:
    case ENOTDIR:
        return BRIX_ERR_NOT_FOUND;
    case EACCES:
    case EPERM:
    case EROFS:
        /* phase-110 W4: a read-only-export refusal (the phase-105 typed
         * mutation gate's EROFS) is a permission-class outcome, not "other":
         * one $brix_status / JSON "status" / io_ops{status} word for it on
         * every plane. */
        return BRIX_ERR_FORBIDDEN;
    case EIO:
    case ENOMEM:
    case ENOSPC:
        return BRIX_ERR_IO;
    default:
        return BRIX_ERR_OTHER;
    }
}

/*
 * brix_metric_err_from_http_status — classify an HTTP status code into an
 * brix_err_class_t bucket (2xx/3xx→NONE, 404→NOT_FOUND, 401/403→FORBIDDEN,
 * 5xx→IO, else OTHER), so WebDAV/S3 outcomes share the unified error vocabulary.
 */
brix_err_class_t
brix_metric_err_from_http_status(ngx_uint_t status)
{
    if (status >= 200 && status < 400) {
        return BRIX_ERR_NONE;
    }
    if (status == NGX_HTTP_NOT_FOUND) {
        return BRIX_ERR_NOT_FOUND;
    }
    if (status == NGX_HTTP_FORBIDDEN || status == NGX_HTTP_UNAUTHORIZED) {
        return BRIX_ERR_FORBIDDEN;
    }
    if (status >= 500 && status < 600) {
        return BRIX_ERR_IO;
    }

    return BRIX_ERR_OTHER;
}

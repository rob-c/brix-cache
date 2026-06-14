#ifndef XROOTD_TPC_COMMON_TRANSFER_H
#define XROOTD_TPC_COMMON_TRANSFER_H

/* ---- Module: TPC Transfer Vocabulary ----
 *
 * WHAT: The shared vocabulary for third-party copies — protocol tags
 *       (STREAM / WEBDAV), direction tags (PULL / PUSH), lifecycle states
 *       (PENDING / ACTIVE / DONE / ERROR), the registry sizing constants
 *       (slot count and max URL/path lengths), and the protocol-neutral
 *       xrootd_tpc_transfer_t describing one in-flight copy.
 *
 * WHY: Every other file in tpc/common builds on these definitions, so they live
 *      in one leaf header with no dependencies beyond nginx core. Keeping the
 *      state machine and size limits centralised guarantees the stream and
 *      WebDAV transports, the registry, and the metrics/dashboard readers all
 *      agree on the same enum values and buffer bounds.
 *
 * HOW: Plain #define tags and a POD struct. The xrootd_tpc_transfer_t ngx_str_t
 *      members (src_url, dst_path) point at storage owned by the registry slot
 *      that holds the transfer; callers may pass stack/request-pool strings to
 *      xrootd_tpc_registry_add(), which copies them before publishing.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>

#define XROOTD_TPC_PROTO_STREAM  1
#define XROOTD_TPC_PROTO_WEBDAV  2

#define XROOTD_TPC_DIR_PULL      1
#define XROOTD_TPC_DIR_PUSH      2

#define XROOTD_TPC_STATE_PENDING 1
#define XROOTD_TPC_STATE_ACTIVE  2
#define XROOTD_TPC_STATE_DONE    3
#define XROOTD_TPC_STATE_ERROR   4

#define XROOTD_TPC_REGISTRY_SLOTS 1024
#define XROOTD_TPC_SRC_URL_MAX    1024
#define XROOTD_TPC_DST_PATH_MAX   1024

/*
 * Protocol-neutral state for an in-flight third-party copy.
 *
 * The ngx_str_t members point at storage owned by the registry slot that
 * contains this transfer.  Callers may pass stack/request-pool strings to
 * xrootd_tpc_registry_add(); the registry copies them before publishing.
 */
typedef struct {
    uint64_t       id;
    ngx_uint_t     protocol;
    ngx_uint_t     direction;
    ngx_str_t      src_url;
    ngx_str_t      dst_path;
    off_t          bytes_total;
    off_t          bytes_done;
    time_t         started_at;
    time_t         updated_at;
    ngx_uint_t     state;
} xrootd_tpc_transfer_t;

#endif /* XROOTD_TPC_COMMON_TRANSFER_H */

#ifndef BRIX_SERVICE_PUBLISH_H
#define BRIX_SERVICE_PUBLISH_H

/*
 * service_publish.h — the domain-gated staged-publish verb for SERVICE
 * storage (phase-108 C10).
 *
 * WHAT: brix_service_publish_bytes()/_fd() — the one form every service-storage
 *       site (the OCI registry today; the FRM journal tomorrow) calls to make a
 *       byte string or an already-written staged file appear atomically at a
 *       final path, with the durability class its storage domain demands (§3.3).
 *
 * WHY:  The OCI registry privately rebuilt staged publish, atomic swap and CAS
 *       presence over raw syscalls with no fsync anywhere — in the one domain
 *       phase 107 marks durable. This verb consolidates that onto the phase-107
 *       staging primitives (staged_file.c) behind the typed domain claim, so a
 *       manifest, tag or blob the client was told was 201 Created is on stable
 *       storage before the answer, the rename is confined, and the durable
 *       publish barrier (C3) actually runs. It sits BESIDE staged_file.c rather
 *       than inside it: staged_file.c stages EXPORT uploads under the phase-105
 *       gate; the domain-aware service arm is a different concern and would
 *       push the file past its 600-line budget.
 *
 * HOW:  Claim the domain (brix_vfs_domain_claim — EXPORT routes to the phase-105
 *       kernel and answers EROFS, so no export mutation can be laundered through
 *       a service verb), stage beneath req->root_canon with staged_open's
 *       O_EXCL/O_NOFOLLOW/random-suffix/confinement for free, run the EINTR
 *       write loop, fsync the data before the rename when the domain is durable,
 *       then commit through brix_staged_commit{,_excl} — which carries any live
 *       lock record, renames confined, and runs the C3 parent-dir barrier. No
 *       file is left behind on any failure path.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd_domain.h"   /* brix_vfs_domain_t — precedent: core/types/file.h */

typedef struct {
    ngx_log_t         *log;
    brix_vfs_domain_t  domain;       /* REGISTRY / STAGE / CACHE / CONFIG / JOURNAL */
    const char        *root_canon;   /* confinement root (the store root, never "/") */
    const char        *final_path;   /* absolute, canonical, under root_canon */
    mode_t             mode;         /* published mode; 0 keeps the staged temp's */
    unsigned           excl:1;       /* publish only if absent (RENAME_NOREPLACE) */
} brix_service_publish_req_t;

/*
 * brix_service_publish_bytes — stage `len` bytes and publish them at
 * req->final_path atomically, with the durability class of req->domain (§3.3).
 * The parent directory of final_path must already exist (the caller owns the
 * store layout). NGX_OK, or NGX_ERROR with errno:
 *   EROFS      — the domain claim refused (an EXPORT-domain publish)
 *   EINVAL     — req NULL, domain out of range, or final_path outside root_canon
 *   EEXIST     — req->excl and the final path already exists (map to 409/412)
 *   ENOSPC/EIO/EDQUOT — surfaced verbatim from the write, close or fsync
 * No file is left behind on any failure path.
 */
ngx_int_t brix_service_publish_bytes(const brix_service_publish_req_t *req,
    const void *bytes, size_t len);

/*
 * brix_service_publish_fd — publish an ALREADY-written staged file at
 * stage_path (the caller finished writing it) onto req->final_path. Same
 * contract as _bytes. `fd`, when not NGX_INVALID_FILE, is the still-open write
 * fd and is fsynced before the rename on a durable domain; pass
 * NGX_INVALID_FILE when the caller holds no fd — a durable domain then reopens
 * stage_path read-only, confined beneath root_canon, and fsyncs it, so the
 * data is stable before the name is. stage_path must be absolute and under
 * root_canon.
 */
ngx_int_t brix_service_publish_fd(const brix_service_publish_req_t *req,
    ngx_fd_t fd, const char *stage_path);

#endif /* BRIX_SERVICE_PUBLISH_H */

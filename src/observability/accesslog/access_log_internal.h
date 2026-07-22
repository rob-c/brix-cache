#ifndef BRIX_OBSERVABILITY_ACCESS_LOG_INTERNAL_H
#define BRIX_OBSERVABILITY_ACCESS_LOG_INTERNAL_H

/*
 * WHAT: Internal seam shared between access_log.c and access_log_sesslog.c.
 * WHY: The sesslog-mirror concept was split into its own translation unit
 * (file-size governance), but brix_log_access still needs to feed it one raw
 * request event; this header carries the event struct plus the single
 * de-static'd entry point across that seam.
 * HOW: access_log.c populates a brix_access_event_t and calls
 * brix_access_maybe_sesslog(); access_log_sesslog.c owns the implementation and
 * all of its file-local helpers.
 */

#include "core/ngx_brix_module.h"

/*
 * WHAT: File-local descriptor of one access-log event to be mirrored into the
 * sesslog lifecycle.
 * WHY: The mirror entry point needs the raw (un-sanitized) request fields;
 * grouping them into one struct keeps brix_access_maybe_sesslog under the
 * parameter gate without altering what it consumes.
 * HOW: Populated once in brix_log_access from its own arguments and passed by
 * const pointer to the mirror helper and its AUTH/namespace sub-helpers.
 */
typedef struct {
    const char  *verb;
    const char  *path;
    const char  *detail;
    ngx_uint_t   xrd_ok;
    uint16_t     errcode;
    const char  *errmsg;
} brix_access_event_t;

/*
 * WHAT: Mirror selected legacy access-log calls into the sesslog lifecycle.
 * WHY: Root handlers already have well-audited success/error exits; using this
 * chokepoint gives root:// ATTEMPT/RESULT and AUTH coverage with minimal risk.
 * HOW: AUTH emits auth events; namespace verbs emit immediate ATTEMPT followed
 * by RESULT; pure data I/O is intentionally ignored and summarized by XFER.
 */
void brix_access_maybe_sesslog(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    const brix_access_event_t *ev);

#endif /* BRIX_OBSERVABILITY_ACCESS_LOG_INTERNAL_H */

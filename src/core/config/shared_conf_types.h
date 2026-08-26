/*
 * shared_conf_types.h — ngx_http_brix_shared_conf_t definition.
 *
 * The shared config preamble struct, split out of shared_conf.h so both files
 * stay under the per-file line ceiling. Included at the exact original position
 * of the struct by shared_conf.h; every consumer sees the type transitively.
 */

#ifndef NGX_HTTP_BRIX_SHARED_CONF_TYPES_H
#define NGX_HTTP_BRIX_SHARED_CONF_TYPES_H

#include <ngx_thread_pool.h>

#include <regex.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "observability/pmark/pmark.h"
#include "auth/authz/acc/acc.h"   /* brix_acc_http_t (phase-101 W2: in the preamble) */
#include "core/shm/rate_limit.h"  /* brix_rate_limit_conf_t + brix_kv_t (phase-105 W1) */
#include "net/mirror/mirror.h"    /* brix_mirror_conf_t (phase-105 W2) */

/*
 * ngx_http_brix_shared_conf_t — Common fields embedded at the top of every
 * protocol location/server config struct (stream, WebDAV, S3).
 *
 * WHAT: A shared preamble that holds enable flags, root path, write permission,
 * and thread pool name — fields present in all three protocol configs. Each
 * protocol struct embeds this struct as its first member so offsetof() offsets
 * into the protocol-specific tail remain valid after merge.
 *
 * WHY: Stream, WebDAV, and S3 each duplicate enable + root + allow_write in
 * their own structs and their create/merge functions (~90 total ngx_conf_merge_*
 * calls). Consolidating these shared fields into one struct reduces merge
 * boilerplate to ~30 protocol-specific calls plus a single preamble merge.
 *
 * HOW: Protocol structs declare this as their first member (no padding needed
 * because it starts with ngx_flag_t which aligns naturally). The create function
 * sets all shared fields to NGX_CONF_UNSET; the merge function uses standard
 * nginx merge macros on each field before calling protocol-specific merge logic.
 */

typedef struct {
#include "shared_conf_fields.h"
} ngx_http_brix_shared_conf_t;

/* phase-105 W8: the preamble is plane-neutral (embedded by the stream srv
 * conf, stream_common, and gridftp as well as every HTTP protocol conf) —
 * new code should use this alias; existing uses are NOT swept (a rename
 * sweep is deliberately out of scope, same call phase-101 made). */
typedef ngx_http_brix_shared_conf_t  brix_shared_conf_t;

#endif /* NGX_HTTP_BRIX_SHARED_CONF_TYPES_H */

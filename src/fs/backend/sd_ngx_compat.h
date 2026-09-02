#ifndef BRIX_SD_NGX_COMPAT_H
#define BRIX_SD_NGX_COMPAT_H

/*
 * sd_ngx_compat.h — sd.h's nginx-or-shim include seam (split from sd.h for
 * the 600-line budget; the text is verbatim, see sd.h's WHAT/WHY).
 * Under XRDPROTO_NO_NGX it supplies the minimal nginx type/macro surface the
 * driver contract names (typedefs and macros only — no runtime symbol, so the
 * built libxrdproto stays ngx-free); otherwise it pulls the real ngx_core.h.
 */

#ifdef XRDPROTO_NO_NGX
/* ngx-free consumers (the native client via shared libxrdproto) include this
 * header ONLY for the worker-safe POSIX raw-fd surface — brix_sd_posix_wrap()
 * + the driver's pread/pwrite/... slots — which touch no nginx runtime. Supply
 * the minimal nginx type/macro surface this header *names* so it compiles
 * without ngx_core.h. Each is a typedef or macro (no runtime symbol), so the
 * built libxrdproto stays ngx-free (check-ngx-free.sh inspects the archive for
 * ngx_* symbols). The ngx-coupled namespace/instance/registry slots are simply
 * absent (NULL) in the ngx-free POSIX driver (see sd_posix.c). */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>   /* free() for brix_sd_obj_release */
#include <string.h>
#include <time.h>     /* struct timespec for brix_sd_setattr_t */
typedef intptr_t          ngx_int_t;
typedef uintptr_t         ngx_uint_t;
typedef int               ngx_fd_t;
typedef struct ngx_log_s  ngx_log_t;   /* opaque: only ever a pointer field */
typedef struct ngx_pool_s ngx_pool_t;  /* opaque: only ever a pointer field */
#ifndef NGX_INVALID_FILE
#define NGX_INVALID_FILE  (-1)
#endif
#ifndef NGX_OK
#define NGX_OK            0
#endif
#ifndef NGX_ERROR
#define NGX_ERROR         (-1)
#endif
#ifndef NGX_AGAIN
#define NGX_AGAIN         (-2)
#endif
#ifndef NGX_DONE
#define NGX_DONE          (-4)
#endif
/* Part of the slot contract, not a convenience: query_checksum returns
 * NGX_DECLINED to mean "I hold no such digest" and recall returns NGX_AGAIN to
 * mean "queued". A driver TU built for the ngx-free plane (client tools, the
 * live-cluster tests) implements those slots too, so the values must be here as
 * well as in ngx_core.h — and must be nginx's, since the same object files link
 * against the module. */
#ifndef NGX_DECLINED
#define NGX_DECLINED      (-5)
#endif
#ifndef ngx_inline
#define ngx_inline        inline
#endif
#ifndef ngx_memzero
#define ngx_memzero(buf, n) memset(buf, 0, (n))
#endif
#else
#include <ngx_config.h>
#include <ngx_core.h>
#endif

#endif /* BRIX_SD_NGX_COMPAT_H */

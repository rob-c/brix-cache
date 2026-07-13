#ifndef BRIX_OPEN_INTERNAL_H
#define BRIX_OPEN_INTERNAL_H

/*
 * open_internal.h — helpers split out of the kXR_open handler (open_request.c)
 * to keep that god-function decomposed and each file under the size cap.  The
 * two heaviest, self-contained phases moved to their own files:
 *   - open_tpc.c      TPC (third-party-copy) context detection + destination/
 *                     source handling, which must act BEFORE normal resolution.
 *   - open_manager.c  manager-mode CMS/registry redirect + static manager_map.
 *
 * Both follow the same control contract as the in-file open phases: return
 * NGX_DECLINED to mean "not handled, proceed with the normal open"; any other
 * value is the response rc the caller must return verbatim (a redirect, an
 * error, NGX_AGAIN for a parked CMS/TPC wait, or a deferred TPC pull).
 */

#include "open.h"

/* Opaque extraction helper — defined in open_overview.c. */
extern int open_extract_opaque(const u_char *payload, size_t payload_len,
    char *out, size_t out_size);

/*
 * TPC context detection.  Parses the kXR_open opaque; a write open carrying
 * tpc.src acts as the TPC destination (redirect in manager mode, else authorize
 * + prepare the outbound pull); a read open carrying tpc.key/dst/org registers
 * or consumes the rendezvous key.  NGX_DECLINED when no TPC context applies.
 */
ngx_int_t brix_open_handle_tpc(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int is_write, uint16_t options,
    uint16_t mode_bits);

/*
 * Manager-mode redirect: dynamic CMS/registry selection (with the tried-
 * exhausted and collapse-redir caches) and the static manager_map prefix
 * redirect.  NGX_DECLINED to resolve locally; NGX_AGAIN when parked on a CMS
 * locate; otherwise a redirect/error rc.  clean_path is the CGI-stripped path.
 */
ngx_int_t brix_open_manager_redirect(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int is_write, const char *clean_path);

#endif /* BRIX_OPEN_INTERNAL_H */

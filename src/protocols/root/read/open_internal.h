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

/*
 * Opaque CGI negotiation helpers (open_request_opaque.c).
 *
 * open_negotiate_compress_codec — phase-42 W4/W5 inline-compression codec
 *   selection from the kXR_open "?xrootd.compress=" opaque; returns the codec
 *   ordinal or BRIX_CODEC_IDENTITY (0) when disabled/absent/unknown.
 * open_extract_zip_member — phase-57 W2 validated ZIP member name from the
 *   "?xrdcl.unzip=" opaque; 1 with out[] filled, 0 when absent, -1 on an invalid
 *   (empty/too-long/traversal) value.
 */
uint8_t open_negotiate_compress_codec(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf, ngx_flag_t is_write);
int open_extract_zip_member(brix_ctx_t *ctx, char *out, size_t outsz);

/*
 * Path-resolution phases (open_request_resolve.c).  Same NGX_DECLINED-to-proceed
 * contract as the in-file open phases.  Each builds full_path from clean_path and
 * runs the auth gate (read: before any existence probe; write: create/update op).
 */
ngx_int_t brix_open_read_resolve(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    char *full_path, uint16_t options, uint16_t mode_bits);
ngx_int_t brix_open_write_resolve(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    char *full_path, uint16_t options);

#endif /* BRIX_OPEN_INTERNAL_H */

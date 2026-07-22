#include "open.h"
#include "open_internal.h"
#include "core/compat/codec_core.h"

#include <string.h>

/* open_extract_opaque() is declared in open_internal.h. */

/*
 * Locate a CGI opaque key on a token boundary (start / '&' / '?') and return its
 * value span [*val, *val+*vlen).  Shared by the compression and ZIP-member
 * negotiations, which both scan the same path?opaque carrier.  Returns 1 when the
 * key is present on a boundary, 0 otherwise.
 */
static int
open_cgi_find_value(const char *opaque, const char *key,
    const char **val, size_t *vlen)
{
    const char *p = strstr(opaque, key);
    const char *v, *end;

    if (p == NULL) {
        return 0;
    }
    if (p != opaque && p[-1] != '&' && p[-1] != '?') {
        return 0;   /* not on a key boundary */
    }

    v = p + strlen(key);
    end = v;
    while (*end != '\0' && *end != '&') {
        end++;
    }
    *val = v;
    *vlen = (size_t) (end - v);
    return 1;
}

/*
 *
 * WHAT: Phase-42 W4/W5 — negotiate an inline-compression codec from the kXR_open
 *       opaque.  Returns the codec ordinal (brix_codec_id_t) to use for this
 *       handle, or BRIX_CODEC_IDENTITY (0) when compression is disabled for the
 *       direction, no "?xrootd.compress=" opaque is present, or the requested
 *       codec is unknown/unavailable.  Direction is chosen by is_write: a READ
 *       open gates on brix_read_compress (W4, compress kXR_read responses); a
 *       WRITE open gates on brix_write_compress (W5, decompress kXR_write
 *       payloads on ingest).
 *
 * WHY:  Inline compression must be strictly opt-in and invisible to stock peers.
 *       The negotiation rides the existing path?opaque carrier (stock servers
 *       ignore unknown CGI keys; stock clients never send them), gated behind the
 *       direction's directive (both off by default).  Fail-soft: an unknown or
 *       unbuilt codec degrades to plaintext rather than failing the open.
 *
 * HOW:  Extract the opaque, scan the '&'-separated CGI list for the
 *       "xrootd.compress=" key on a token boundary, look the value up by
 *       canonical name (then HTTP token, so "br" works) and require it built in.
 */
uint8_t
open_negotiate_compress_codec(brix_ctx_t *ctx,
                              ngx_stream_brix_srv_conf_t *conf,
                              ngx_flag_t is_write)
{
	char                       opaque[BRIX_MAX_PATH + 1];
	const char                *val;
	size_t                     vlen;
	ngx_flag_t                 enabled;
	const brix_codec_desc_t *d;

	enabled = is_write ? conf->write_compress : conf->read_compress;
	if (!enabled || ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0)
	{
		return BRIX_CODEC_IDENTITY;
	}

	if (!open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen,
	                         opaque, sizeof(opaque)))
	{
		return BRIX_CODEC_IDENTITY;
	}

	if (!open_cgi_find_value(opaque, "xrootd.compress=", &val, &vlen)
	    || vlen == 0) {
		return BRIX_CODEC_IDENTITY;
	}

	d = brix_codec_by_name(val, vlen);
	if (d == NULL) {
		d = brix_codec_by_http_token(val, vlen);
	}
	if (d == NULL || !d->available || d->id == BRIX_CODEC_IDENTITY) {
		return BRIX_CODEC_IDENTITY;
	}
	return (uint8_t) d->id;
}

/*
 *
 * WHAT: Phase-57 W2 — pull a validated ZIP member name out of the kXR_open opaque
 *       "?xrdcl.unzip=<member>".  Returns 1 with out[] filled (NUL-terminated)
 *       for a usable member, 0 when no "xrdcl.unzip=" key is present (open the
 *       archive normally), or -1 when the key IS present but its value is invalid
 *       (empty / too long / traversal) — the caller rejects with kXR_ArgInvalid.
 * WHY:  ZIP member access serves one file inside an archive.  The member name is
 *       intra-archive, but a hostile name must never be trusted, so reject empty,
 *       absolute ("/..."), and any ".." path component here, before it reaches the
 *       central-directory lookup.
 * HOW:  Extract the opaque (same carrier as the compression negotiation), scan for
 *       the "xrdcl.unzip=" key on a token boundary (start / '&' / '?'), copy the
 *       value up to the next '&', then reject leading '/', a bare "..", a leading
 *       "../", any embedded "/../", or a trailing "/..".
 */
/* Intra-archive traversal / absolute-path guard for a ZIP member name: reject a
 * leading '/', a bare "..", a leading "../", any embedded "/../", or a trailing
 * "/..".  Returns 1 (unsafe → caller rejects with kXR_ArgInvalid), else 0. */
static int
open_zip_member_path_unsafe(const char *out, size_t vlen)
{
	if (out[0] == '/') {
		return 1;
	}
	if (ngx_strcmp(out, "..") == 0) {
		return 1;
	}
	if (vlen >= 3 && out[0] == '.' && out[1] == '.' && out[2] == '/') {
		return 1;   /* leading "../" */
	}
	if (strstr(out, "/../") != NULL) {
		return 1;
	}
	if (vlen >= 3 && ngx_strcmp(out + vlen - 3, "/..") == 0) {
		return 1;   /* trailing "/.." */
	}
	return 0;
}

int
open_extract_zip_member(brix_ctx_t *ctx, char *out, size_t outsz)
{
	char        opaque[BRIX_MAX_PATH + 1];
	const char *val;
	size_t      vlen;

	if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
		return 0;
	}
	if (!open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen, opaque, sizeof(opaque))) {
		return 0;
	}

	if (!open_cgi_find_value(opaque, "xrdcl.unzip=", &val, &vlen)) {
		return 0;   /* key absent — open the whole archive normally */
	}

	/* From here the "xrdcl.unzip=" key IS present: a bad value is an explicit
	 * error (return -1, caller rejects with kXR_ArgInvalid), NOT a fall-through
	 * to opening the whole archive — so a traversal attempt is surfaced, not
	 * silently ignored. */
	if (vlen == 0 || vlen >= outsz) {
		return -1;
	}

	ngx_memcpy(out, val, vlen);
	out[vlen] = '\0';

	if (open_zip_member_path_unsafe(out, vlen)) {
		return -1;
	}

	return 1;
}

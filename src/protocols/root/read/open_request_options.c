/*
 * Pure kXR_open mode and opaque hint interpretation.
 * Keeps attacker-controlled option classification independent of path, policy
 * and storage effects; open_request.c retains ordering of every security gate.
 */
#include "open_internal.h"
#include "protocols/root/path/opaque_validate.h"

/* ---- Interpret the declared final size after opaque validation ----
 * WHAT: Return oss.asize for a write-open caller, or zero without a declaration.
 * WHY: Reservation intent must be parsed independently of storage effects.
 * HOW: 1. Extract bounded opaque bytes. 2. Delegate to the common value parser.
 */
off_t
brix_open_declared_asize(brix_ctx_t *ctx)
{
	char opq[BRIX_MAX_PATH + 1];

	if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0
	    || !open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen,
	                            opq, sizeof(opq)))
	{
		return 0;
	}
	return (off_t) brix_opaque_asize(opq);
}


/*
 * WHAT: Detect mutually exclusive kXR_open access-mode bits.
 * WHY:  Treating an all-bits or multi-mode request as an ordered set of hints
 *       partially honours attacker-chosen semantics (for example truncate plus
 *       append) instead of rejecting the contradictory request atomically.
 * HOW:  Normalize the stock-compatible wrto|apnd spelling to append, then count
 *       the effective access modes; zero/one is defined and two or more fails
 *       before TPC, path, or VFS work.
 */
int
brix_open_options_conflict(uint16_t options)
{
	uint16_t access = options
	    & (kXR_open_read | kXR_open_updt | kXR_open_apnd | kXR_open_wrto);
	unsigned count = 0;

	/* Stock clients send wrto|apnd for a write-only append open.  In that
	 * shape wrto declares the access direction and apnd refines its placement;
	 * they are one effective mode, not two contradictory modes. */
	if ((access & (kXR_open_wrto | kXR_open_apnd))
	    == (kXR_open_wrto | kXR_open_apnd))
	{
		access &= (uint16_t) ~kXR_open_wrto;
	}

	while (access != 0) {
		count += access & 1U;
		access >>= 1;
	}
	return count > 1;
}


/* ---- Interpret read-only cache hints after opaque validation ----
 * WHAT: Return pfc.blocksize/prefetch hints, all zero for writes or absent CGI.
 * WHY: Hints describe slicing and speculation, never mutation authority; the
 *      cache still decides whether brix_cache_urlcgi admits them. Strict mode
 *      has already rejected bad types; lenient mode drops them here.
 * HOW: 1. Exclude writes. 2. Extract bounded opaque. 3. Parse common uint keys.
 */
brix_sd_open_hints_t
brix_open_cache_hints(brix_ctx_t *ctx, ngx_flag_t is_write)
{
	brix_sd_open_hints_t h = { 0, 0, 0 };
	char                 opq[BRIX_MAX_PATH + 1];
	long long            v;

	if (is_write || ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0
	    || !open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen,
	                            opq, sizeof(opq)))
	{
		return h;
	}
	if (brix_opaque_uint(opq, "pfc.blocksize", &v) && v > 0) {
		h.block_size = (size_t) v;
	}
	if (brix_opaque_uint(opq, "pfc.prefetch", &v)) {
		h.prefetch_blocks = (size_t) v;
		h.prefetch_set    = 1;
	}
	return h;
}

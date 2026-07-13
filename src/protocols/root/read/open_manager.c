#include "open_internal.h"
#include "net/manager/registry.h"
#include "net/manager/redir_cache.h"
#include "net/manager/pending.h"
#include "net/cms/cms_internal.h"

/*
 * open_manager.c — kXR_open manager-mode redirection, split from open_request.c.
 * A manager (redirector) never serves bytes: it points the client at a data
 * server via the dynamic registry / CMS parent (with the tried-exhausted and
 * collapse-redir caches short-circuiting the common cases), or via the static
 * manager_map prefix table.  Bodies are moved verbatim; the early-returns are
 * unchanged.  Returns NGX_DECLINED to resolve locally instead.
 */
/*
 * Registry miss — ask the CMS parent via kYR_locate.  Parks the open in
 * XRD_ST_WAITING_CMS and returns NGX_AGAIN when the locate was sent; NGX_DECLINED
 * to fall through to the static map / local resolve / error.
 */
static ngx_int_t
brix_open_cms_locate(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path)
{
	uint32_t streamid;

	if (conf->cms.ctx == NULL) {
		return NGX_DECLINED;
	}

	streamid = ngx_brix_cms_next_streamid(conf->cms.ctx);
	if (brix_pending_insert(streamid, ngx_pid, c->fd, c->number,
	                          ctx->recv.cur_streamid,
	                          conf->cms.locate_timeout) == NGX_OK)
	{
		ctx->cms_wait_streamid = streamid;
		ctx->state = XRD_ST_WAITING_CMS;
		ngx_add_timer(c->read, conf->cms.locate_timeout);
		if (ngx_brix_cms_send_locate(conf->cms.ctx, streamid,
		                               clean_path) == NGX_OK)
		{
			return NGX_AGAIN;
		}
		ngx_del_timer(c->read);
		ctx->state = XRD_ST_REQ_HEADER;
		brix_pending_remove(streamid, ngx_pid);
	}
	return NGX_DECLINED;
}

ngx_int_t
brix_open_manager_redirect(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int is_write, const char *clean_path)
{
	int op = is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD;

	/* Dynamic manager mode: redirect to best registered server. */
	if (conf->manager_mode) {
		char     redir_host[256];
		uint16_t redir_port;

		/* tried/triedrc: a read whose client has already visited every server
		 * holding this path (all returned enoent) must get not-found, not yet
		 * another redirect — otherwise it loops to the client redirect limit.
		 * Writes are excluded: they create the file on the selected server. */
		if (!is_write
		    && brix_manager_tried_exhausted(ctx->recv.payload, ctx->recv.cur_dlen,
		                                      clean_path)) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", clean_path,
			                  "rd", kXR_NotFound,
			                  "file not found on any data server");
		}

		/* Collapse-redir cache: serve reads from cache to skip CMS. */
		if (!is_write && conf->caps.collapse_redir
		    && brix_redir_cache_lookup(clean_path, redir_host,
		                                 sizeof(redir_host), &redir_port)) {
			BRIX_RETURN_REDIR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
			                    clean_path, "redir-cache",
			                    redir_host, redir_port);
		}

		/* Open may redirect to a server whose CMS heartbeat just dropped (a
		 * transient blip under load blacklists it for 30 s though its data plane
		 * is still serving) — better than a false NotFound for a file that
		 * exists.  kXR_locate stays strict.  A truly dead target just makes the
		 * client's connect fail and the tried/triedrc retry converges to
		 * NotFound. */
		if (brix_srv_select_or_blacklisted(clean_path, is_write, redir_host,
		                      sizeof(redir_host), &redir_port)) {
			if (!is_write && conf->caps.collapse_redir) {
				brix_redir_cache_insert(clean_path, redir_host, redir_port,
				                          conf->caps.collapse_redir_ttl);
			}
			BRIX_RETURN_REDIR(ctx, c, op,
			                    "OPEN", clean_path, "registry",
			                    redir_host, redir_port);
		}

		/* Registry miss — ask the CMS parent via kYR_locate. */
		{
			ngx_int_t crc = brix_open_cms_locate(ctx, c, conf, clean_path);
			if (crc != NGX_DECLINED) {
				return crc;   /* parked on the CMS locate (NGX_AGAIN) */
			}
			/* NGX_DECLINED: fall through to static-map / local resolve. */
		}
	}

	/* Manager-mode mapping: redirect opens for configured prefixes. */
	if (conf->manager_map != NULL) {
		const brix_manager_map_t *m = brix_find_manager_map(clean_path,
																conf->manager_map);
		if (m != NULL) {
			BRIX_RETURN_REDIR(ctx, c,
							  op,
							  "OPEN", clean_path, "redirect",
							  (const char *) m->host.data, m->port);
		}
	}

	return NGX_DECLINED;
}

#include "open_internal.h"
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"
#include "fs/vfs/vfs_secgate.h"   /* brix_tls_require tpc capability gate */
#include "tpc/common/identity_matrix.h"  /* 2.0 F18 ofs.tpc identity matrix */
#include "auth/protbind/protbind.h"      /* peer hostname for `allow ... host` */

#include <string.h>

/*
 * open_tpc.c — kXR_open TPC (third-party-copy) context detection, split from
 * open_request.c.  The XRootD TPC protocol embeds transfer-context parameters in
 * the open path as CGI-style opaque strings:
 *
 *   TPC destination (we pull FROM source): write open + tpc.src=root://host//path
 *     + tpc.key=<token>.  Connect outbound to the source, stream the file
 *     locally, and return the fhandle only after the pull completes.
 *
 *   TPC source (destination connects TO us): read open with tpc.key=<token>
 *     (+ optional tpc.dst=/tpc.org= for the two-step rendezvous).  Register the
 *     first form and consume the second before serving bytes.
 *
 *   F16 push (tpc.stage=push, a BriX dialect stock xrootd has no equivalent of;
 *   both legs carry the stage so a stock peer never mistakes one for a pull):
 *     push SOURCE — read open + tpc.key + tpc.dst=<destination host[:port]> +
 *       tpc.dlfn=<remote path>.  We will DIAL that destination and write to it,
 *       so this leg carries the egress posture; the role is only parked here
 *       (brix_tpc_prepare_push) and the ordinary read-open then resolves,
 *       authorizes and opens the local file exactly as any other read.
 *     push TARGET — write open + tpc.key, no tpc.src.  Leg 1 (from the client,
 *       no tpc.org) registers the key and creates the file; leg 3 (from the
 *       pushing source, tpc.org set) consumes the key.  Both fall through to
 *       the ordinary write-open.
 *
 * Must act BEFORE the normal path-resolution/open logic, so it runs first from
 * brix_handle_open.  Bodies are moved verbatim; the early-returns are unchanged.
 */

/*
 * TPC destination role: pull the file from tpc->src and write it to our local
 * storage.  The open response (fhandle or error) is deferred until the pull
 * completes in the thread pool.  Always returns a response rc (redirect, error,
 * or the deferred prepare-pull).
 */
static ngx_int_t
tpc_handle_dest(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    uint16_t options, uint16_t mode_bits)
{
	char tpc_full_path[PATH_MAX];
	char tpc_clean[PATH_MAX];

	if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
	                         tpc_clean, sizeof(tpc_clean), 1)) {
		brix_log_access(ctx, c, "OPEN", "-", "tpc-pull",
		                  0, kXR_ArgInvalid,
		                  "invalid TPC dst path", 0);
		BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
		return brix_send_error(ctx, c, kXR_ArgInvalid,
		                         "invalid TPC destination path");
	}
	if (brix_count_path_depth(tpc_clean) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
		                  tpc_clean, "tpc-pull", kXR_ArgInvalid,
		                  "path exceeds maximum depth");
	}

	/* Manager mode: generate TPC key and redirect to a data server. */
	if (conf->manager_mode) {
		char     redir_host[256];
		uint16_t redir_port;

		if (brix_srv_select(tpc_clean, 1, redir_host,
		                      sizeof(redir_host), &redir_port)) {
			char tpc_key[BRIX_TPC_KEY_LEN];

			brix_tpc_generate_key(tpc_key, sizeof(tpc_key));
			brix_tpc_key_register(tpc_key, conf->tpc_key_ttl_ms);
			brix_log_access(ctx, c, "OPEN", tpc_clean, "tpc-redirect",
			                  1, 0, NULL, 0);
			BRIX_OP_OK(ctx, BRIX_OP_OPEN_WR);
			return brix_send_redirect_tpc(ctx, c, redir_host,
			                                redir_port, tpc_key);
		}
			brix_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
			                  0, kXR_Overloaded,
			                  "no data server for TPC", 0);
			BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
			return brix_send_error(ctx, c, kXR_Overloaded,
			                         "no data server available for TPC");
	}

	if (!conf->common.allow_write) {
		brix_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
		                  0, kXR_fsReadOnly,
		                  "read-only server", 0);
		BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
		return brix_send_error(ctx, c, kXR_fsReadOnly,
		                         "this is a read-only server");
	}

	{
		ngx_str_t tpc_src_scope;
		ngx_str_t tpc_dst_scope;

		tpc_src_scope.data = (u_char *) tpc->src_path;
		tpc_src_scope.len = ngx_strlen(tpc->src_path);
		tpc_dst_scope.data = (u_char *) tpc_clean;
		tpc_dst_scope.len = ngx_strlen(tpc_clean);

		if (brix_tpc_check_authz(ctx->identity, &tpc_src_scope,
		                           &tpc_dst_scope, c->log)
		    != NGX_OK)
		{
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
			                  tpc_clean, "tpc-pull",
			                  kXR_NotAuthorized,
			                  "TPC authorization denied");
		}
	}

	brix_beneath_full_path(conf->common.root_canon, tpc_clean,
	                          tpc_full_path, sizeof(tpc_full_path));

	/* Format-aware authz (xrdacc engine or native authdb); the TPC pull creates
	 * the dest file (AOP_Create). */
	if (brix_authz_check(ctx, c, conf, tpc_clean, tpc_full_path,
	                       "OPEN", BRIX_AUTH_UPDATE,
	                       BRIX_AOP_CREATE) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
		                  tpc_clean, "tpc-pull", kXR_NotAuthorized,
		                  "authdb denied");
	}

	if (brix_check_vo_acl_identity(c->log, tpc_full_path,
	                                 conf->common.vo_rules,
	                                 ctx->identity) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
		                  tpc_clean, "tpc-pull", kXR_NotAuthorized,
		                  "VO not authorized");
	}

	if (options & kXR_mkpath) {
		char  parent[PATH_MAX];
		char *slash;
		ngx_cpystrn((u_char *) parent, (u_char *) tpc_full_path,
		            sizeof(parent));
		slash = strrchr(parent, '/');
		if (slash && slash > parent) {
			*slash = '\0';
			brix_mkdir_recursive_policy(parent, 0755, c->log,
			                              conf->group_rules);
		}
	}

	return brix_tpc_prepare_pull(ctx, c, conf, tpc,
	                               tpc_full_path, options, mode_bits);
}

/*
 * TPC source role.  XrdCl drives full native TPC as a two-step source
 * rendezvous: first the initiating client opens the source with tpc.dst and the
 * shared key, then the destination server opens the same source with tpc.org and
 * that key.  Register the first form and consume the second before serving
 * bytes.  NGX_DECLINED to serve the file normally; an error rc on a bad consume.
 */
static ngx_int_t
tpc_handle_source(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc)
{
	ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
	               "brix: TPC source open key=%s dst=%s org=%s",
	               tpc->has_key ? tpc->key : "-",
	               tpc->has_dst ? tpc->dst : "-",
	               tpc->has_org ? tpc->org : "-");

	if (tpc->has_key && tpc->key[0] != '\0' && tpc->has_dst
	    && !tpc->has_org) {
		brix_tpc_key_register(tpc->key, conf->tpc_key_ttl_ms);
		ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
		               "brix: TPC source key=%s registered",
		               tpc->key);

	} else if (tpc->has_key && tpc->key[0] != '\0'
	           && tpc->has_org) {
		if (brix_tpc_key_consume(tpc->key)) {
			ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
			               "brix: TPC source key=%s consumed",
			               tpc->key);
		} else {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
			                  ctx->recv.payload ? (char *) ctx->recv.payload : "-",
			                  "tpc-source", kXR_NotAuthorized,
			                  "TPC authorization missing or expired");
		}
	}

	return NGX_DECLINED;
}

/*
 * F16 push TARGET role (write open, tpc.stage=push, a key and no tpc.src): the
 * mirror of tpc_handle_source for the other direction.  Leg 1 arrives from the
 * initiating client with no tpc.org and REGISTERS the key; leg 3 arrives from
 * the pushing source with tpc.org and CONSUMES it (single-use — a replayed key
 * is refused).  Neither leg dials anything, so both return NGX_DECLINED and the
 * ordinary write-open creates (leg 1) or reopens (leg 3) the file.
 */
static ngx_int_t
tpc_handle_push_target(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc)
{
	ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
	               "brix: TPC push target open key=%s org=%s",
	               tpc->key, tpc->has_org ? tpc->org : "-");

	if (!conf->tpc_push) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN", "-",
		                  "tpc-push", kXR_Unsupported,
		                  "native TPC push is disabled (brix_tpc_push off)");
	}

	if (!tpc->has_org) {
		brix_tpc_key_register(tpc->key, conf->tpc_key_ttl_ms);
		return NGX_DECLINED;
	}

	if (!brix_tpc_key_consume(tpc->key)) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN", "-",
		                  "tpc-push", kXR_NotAuthorized,
		                  "TPC authorization missing or expired");
	}

	return NGX_DECLINED;
}

/*
 * tpc_open_roles_t — which of the four native-TPC roles this open is playing.
 * At most one is ever set; the struct exists so the classification, the TLS
 * gate and the dispatch can be three flat steps instead of one branchy
 * function (CCN contract, coding-standards §2).
 */
typedef struct {
	int dest;       /* destination of a PULL: creates the file, dials the source */
	int source;     /* source of a PULL: registers/consumes the rendezvous key  */
	int push_src;   /* source of a PUSH: dials the destination and writes (F16) */
	int push_dst;   /* destination of a PUSH: leg 1 registers, leg 3 consumes   */
} tpc_open_roles_t;

/*
 * WHAT: hand the open to the one handler its role names.
 * WHY: the order is a security order, not a stylistic one — the destination
 * roles are decided before the source roles so an open that somehow carried
 * both key-consuming and key-presenting opaque can only ever consume, and the
 * push roles are decided before the pull's generic source test (which
 * tpc_open_is_source already excludes a push from) so a stage=push read-open
 * can never fall through to the pull's key registration.
 * HOW: first match wins; NGX_DECLINED means "not a TPC open after all", which
 * the caller treats as an ordinary open.
 */
static ngx_int_t
tpc_open_dispatch_role(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const tpc_open_roles_t *roles, uint16_t options, uint16_t mode_bits)
{
	if (roles->dest) {
		return tpc_handle_dest(ctx, c, conf, tpc, options, mode_bits);
	}
	if (roles->push_dst) {
		return tpc_handle_push_target(ctx, c, conf, tpc);
	}
	if (roles->push_src) {
		return brix_tpc_prepare_push(ctx, c, conf, tpc);
	}
	if (roles->source) {
		return tpc_handle_source(ctx, c, conf, tpc);
	}
	return NGX_DECLINED;
}

/*
 * 2.0 F18 — the ofs.tpc identity matrix, evaluated at this one choke point.
 *
 * WHY HERE: brix_open_handle_tpc() is the only place that has parsed the tpc.*
 * opaque and knows the role, and it runs before tpc_open_dispatch_role() —
 * therefore before brix_tpc_prepare_pull()/_prepare_push() ever dial.  Like
 * F5's `permit=`, the whole verdict precedes any outbound connection.
 *
 * WHY IT CAN ONLY NARROW: the host plane (brix_tpc_source_guard/_allow,
 * brix_tpc_allow_local/_private) remains the OUTER gate and is untouched; this
 * matrix is an inner one that runs in addition to it.  A rule here can refuse
 * a transfer the host plane would have allowed; it can never admit one the
 * host plane denies, because the host plane's own checks still run afterwards
 * inside the role handlers.
 */

/*
 * Which party's credential is on this leg.  A native TPC leg carrying tpc.org
 * was opened by the peer SERVER and therefore presents the SERVER's
 * credential — that is the destination party.  A leg without tpc.org was
 * opened by the initiating CLIENT.  This is the wire fact that makes
 * `brix_tpc_require dest <auth>` unsatisfiable by a client credential.
 */
static int
tpc_matrix_party(const brix_tpc_params_t *tpc)
{
	return tpc->has_org ? BRIX_TPC_PARTY_DEST : BRIX_TPC_PARTY_CLIENT;
}

/*
 * Fill `mc` from the server conf.  Kept separate so the gate below reads as
 * the security order it is (subject, path, verdict) with no conf plumbing.
 */
static void
tpc_matrix_conf_from(const ngx_stream_brix_srv_conf_t *conf,
    brix_tpc_matrix_conf_t *mc)
{
	mc->allow         = conf->common.tpc_allow_identity;
	mc->require_rules = conf->common.tpc_require;
	mc->paths         = conf->common.tpc_restrict;
	mc->oids          = conf->common.tpc_oids;
}

/*
 * The logical path this open names, as the matrix must see it.
 *
 * INVARIANT 4: `brix_tpc_restrict` is specified against the resolved path.
 * brix_extract_path() strips the CGI opaque but does NOT clean traversal, so a
 * raw "." or ".." component would let /export/../etc slip past a
 * `restrict /export` rule and then be resolved elsewhere.  Rather than
 * duplicate the resolver here, we reject exactly what the resolver rejects
 * (brix_op_path_forbidden_component, which brix_path_resolve_beneath also
 * calls) — after which the extracted string is byte-identical to what the
 * resolver will produce, and prefix-matching it is sound.
 *
 * Returns 0 when no usable path could be produced; the caller then denies.
 */
static int
tpc_matrix_path(brix_ctx_t *ctx, ngx_connection_t *c, char *buf, size_t buflen)
{
	if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
	                       buf, buflen, 1)) {
		return 0;
	}
	return !brix_op_path_forbidden_component(buf);
}

/*
 * The gate.  NGX_DECLINED means "not configured, or permitted" — carry on to
 * the role dispatch; anything else is a response already sent and must be
 * returned to the client untouched.  The polarity is deliberate: every refusal
 * here leaves through BRIX_RETURN_ERR, whose last act is
 * `return brix_send_error(...)` = NGX_OK, so NGX_OK cannot also mean permitted
 * without making the two indistinguishable at the call site.
 *
 * Refusal texts come from brix_tpc_matrix_verdict_text() and are FIXED strings
 * naming the directive that refused — never the DN, VO, host or path that did
 * not match (INVARIANT 8: these reach the access log and the error path, and a
 * subject-derived string is unbounded cardinality).
 */
static ngx_int_t
tpc_matrix_gate(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    int is_write)
{
	brix_tpc_matrix_conf_t     mc;
	brix_tpc_subject_t         subj;
	brix_tpc_matrix_verdict_t  v;
	char                       path[PATH_MAX];
	const char                *peer_host;
	int                        op;

	tpc_matrix_conf_from(conf, &mc);
	if (!brix_tpc_matrix_configured(&mc)) {
		/* a no-op for every operator who never adopts it */
		return NGX_DECLINED;
	}

	op = is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD;

	if (!tpc_matrix_path(ctx, c, path, sizeof(path))) {
		BRIX_RETURN_ERR(ctx, c, op, "OPEN", "-", "tpc-matrix",
		                kXR_ArgInvalid, "invalid TPC path");
	}

	peer_host = brix_protbind_peer_host_cached(ctx, c);
	brix_tpc_matrix_subject_from_identity(ctx->identity, peer_host, &subj);

	v = brix_tpc_matrix_check(&mc, tpc_matrix_party(tpc), &subj, path);
	if (v != BRIX_TPC_MATRIX_OK) {
		BRIX_RETURN_ERR(ctx, c, op, "OPEN", "-", "tpc-matrix",
		                kXR_NotAuthorized,
		                brix_tpc_matrix_verdict_text(v));
	}
	return NGX_DECLINED;
}

/* Role predicates over the parsed tpc.* opaque keys: a WRITE open naming a
 * source host is the destination leg; a READ open carrying any of key/dst/org
 * is the source leg (registration or consume — tpc_handle_source splits them).
 * The two F16 push roles are recognised by tpc.stage=push and take precedence:
 * a push read-open would otherwise read as an ordinary source registration, and
 * a push write-open (no tpc.src) matches no pull role at all.
 * A non-TPC open matches none of them and falls through to the normal path. */
static int
tpc_open_is_dest(int is_write, const brix_tpc_params_t *tpc)
{
	return is_write && tpc->has_src && tpc->src_host[0] != '\0';
}

static int
tpc_open_is_push_source(int is_write, const brix_tpc_params_t *tpc)
{
	return !is_write && brix_tpc_stage_is_push(tpc)
	       && tpc->has_dst && tpc->dst_host[0] != '\0';
}

static int
tpc_open_is_push_target(int is_write, const brix_tpc_params_t *tpc)
{
	return is_write && brix_tpc_stage_is_push(tpc)
	       && tpc->has_key && tpc->key[0] != '\0' && !tpc->has_src;
}

static int
tpc_open_is_source(int is_write, const brix_tpc_params_t *tpc)
{
	return !is_write && !tpc_open_is_push_source(is_write, tpc)
	       && (tpc->has_key || tpc->has_dst || tpc->has_org);
}

ngx_int_t
brix_open_handle_tpc(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int is_write, uint16_t options,
    uint16_t mode_bits)
{
	char                 opaque[BRIX_MAX_PATH + 1];
	brix_tpc_params_t  tpc;
	tpc_open_roles_t     roles;
	ngx_int_t            rc;

	if (!(ctx->recv.payload != NULL && ctx->recv.cur_dlen > 0
	      && open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen,
	                             opaque, sizeof(opaque))
	      && brix_tpc_parse_opaque(opaque, &tpc) == 0))
	{
		return NGX_DECLINED;
	}

	roles.dest     = tpc_open_is_dest(is_write, &tpc);
	roles.push_src = tpc_open_is_push_source(is_write, &tpc);
	roles.push_dst = tpc_open_is_push_target(is_write, &tpc);
	roles.source   = tpc_open_is_source(is_write, &tpc);

	if (!(roles.dest || roles.source || roles.push_src || roles.push_dst)) {
		return NGX_DECLINED;
	}

	/* Per-capability TLS gate (brix_tls_require tpc): a TPC-role open —
	 * any role, any leg, pull or push — on a cleartext connection is
	 * refused at this single choke point, where the tpc.* opaque keys are
	 * parsed. */
	if (brix_tls_gate_refused(conf->common.tls_require, BRIX_TLSREQ_TPC,
	                          c->ssl != NULL && c->ssl->connection != NULL))
	{
		BRIX_RETURN_ERR(ctx, c,
		                  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
		                  "OPEN", "-", "tpc", kXR_TLSRequired,
		                  "server security policy requires TLS for TPC");
	}

	/* 2.0 F18 identity matrix — inner gate, before any dial.
	 *
	 * NGX_DECLINED, not NGX_OK, is this gate's "carry on": BRIX_RETURN_ERR
	 * ends in `return brix_send_error(...)`, which answers NGX_OK once the
	 * refusal is on the wire.  A gate that reported permission as NGX_OK
	 * would therefore be indistinguishable from one that had just refused
	 * — the refusal would be logged and sent, and the pull would run
	 * anyway.  It did, until the security negative caught it. */
	rc = tpc_matrix_gate(ctx, c, conf, &tpc, is_write);
	if (rc != NGX_DECLINED) {
		return rc;
	}

	return tpc_open_dispatch_role(ctx, c, conf, &tpc, &roles,
	                              options, mode_bits);
}

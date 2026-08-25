/*
 * server_conf_merge_cluster.c — server-block merge for the third-party-copy and
 * cluster/session configuration areas.
 *
 * WHAT: Owns brix_merge_srv_tpc() (TPC allowances, key TTL, transfer caps +
 *       reaper age, SSI/CNS, outbound credentials) and brix_merge_srv_cluster()
 *       (manager/redirector mode, staged uploads, pipeline/registry/session
 *       sizing, health checks, traffic mirror, CMS client, listen port,
 *       checksum-scan limits, VO/group/manager-map rule arrays + redirector
 *       inheritance), together with the file-local per-concern helpers.
 * WHY:  Split (phase-79 file-size cap) out of the former 1249-line
 *       server_conf.c. Both entry points are non-static (declared in
 *       server_conf_internal.h) because the top-level orchestrator in
 *       server_conf.c calls them in linear order; every sub-helper stays
 *       file-local.
 * HOW:  Standard nginx parent->child inheritance via ngx_conf_merge_* and the
 *       BRIX_MERGE_* macros, one helper per concern group, invoked in the
 *       original order so cross-group derivations (pipeline-depth clamp, CMS
 *       read-timeout from the heartbeat interval) still observe their
 *       already-merged inputs. Config-time side effects (CNS collect flag, TPC
 *       registry reaper age) run once inputs settle, exactly as before. No
 *       behaviour change from the split.
 */

#include "config.h"
#include "server_conf_internal.h"
#include "net/cms/cns.h"               /* §6 CNS mode enum */
#include "tpc/engine/key_registry.h"
#include "tpc/common/registry.h"   /* Phase 39 (WS5): registry reaper max-age */
#include "protocols/root/session/registry.h"   /* BRIX_SESSION_REGISTRY_SLOTS default */
#include "net/manager/health_check.h" /* BRIX_HC_TYPE_PING default */
#include "net/manager/registry.h"     /* Phase 89 (W4): load-weight setter */
#include "net/manager/loc_cache.h"    /* §2.6: fxhold / emptylife TTL setters */

/* Third-party copy (TPC): local/private allowances, key TTL, transfer caps and
 * the abandoned-slot reaper age, and the outbound OAuth2/bearer credentials. */
void
brix_merge_srv_tpc(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_value(conf->tpc_allow_local,   prev->tpc_allow_local,   0);
    ngx_conf_merge_value(conf->tpc_allow_private, prev->tpc_allow_private, 1);
    ngx_conf_merge_value(conf->tpc_source_guard,  prev->tpc_source_guard,  0);
    ngx_conf_merge_ptr_value(conf->tpc_source_allow, prev->tpc_source_allow, NULL);
    ngx_conf_merge_value(conf->ssi_enable,        prev->ssi_enable,        0);
    ngx_conf_merge_value(conf->ssi_cta_enable,    prev->ssi_cta_enable,    0);
    /* defaults mirror BRIX_SSI_MAX_INFLIGHT (8) and the 1 MiB req/resp caps. */
    ngx_conf_merge_uint_value(conf->ssi_max_inflight, prev->ssi_max_inflight, 8);
    ngx_conf_merge_size_value(conf->ssi_request_max,  prev->ssi_request_max,  1u << 20);
    ngx_conf_merge_size_value(conf->ssi_response_max, prev->ssi_response_max, 1u << 20);
    ngx_conf_merge_str_value(conf->ssi_cta_journal,   prev->ssi_cta_journal,  "");
    ngx_conf_merge_uint_value(conf->ssi_cta_executor, prev->ssi_cta_executor, 0);
    ngx_conf_merge_uint_value(conf->cns_mode,     prev->cns_mode,          BRIX_CNS_OFF);
    if (conf->cns_mode == BRIX_CNS_COLLECT) {
        brix_cns_set_collect(1);   /* §6: this node maintains the CNS inventory */
    }
    ngx_conf_merge_value(conf->tpc_outbound_tls,  prev->tpc_outbound_tls,  0);
    ngx_conf_merge_value(conf->tpc_delegate,      prev->tpc_delegate,      0);
    /* Phase-70/opportunistic: passthrough of the client's own inbound bearer JWT
     * to the TPC source is ON by default so token-authenticated pulls forward the
     * end-user identity without any per-server opt-in. The default path is
     * OPPORTUNISTIC (token_mode "passthrough-opt", set in tpc_init_dst_file): an
     * inbound token is used when present, but its ABSENCE falls back to GSI proxy
     * delegation / static bearer file / anonymous exactly as before this default
     * flip — never a new denial. Only an explicit client tpc.token_mode=passthrough
     * stays STRICT/fail-closed. Operators can still set the directive to `off`. */
    ngx_conf_merge_value(conf->tpc_outbound_passthrough,
                         prev->tpc_outbound_passthrough, 1);
    ngx_conf_merge_msec_value(conf->tpc_key_ttl_ms, prev->tpc_key_ttl_ms,
                              BRIX_TPC_KEY_TTL_MS);
    /* Phase 51 (B2): default native-TPC absolute wall-clock cap to a generous
     * 24h so a wedged transfer cannot pin a thread-pool worker forever; 0 still
     * means unlimited (back-compat).  Progress-based stall detection (the curl
     * low-speed bounds, webdav/tpc_config.c) is the primary guard — this is only
     * the absolute backstop, large enough never to clip a real transfer. */
    ngx_conf_merge_uint_value(conf->tpc_max_transfer_secs,
                              prev->tpc_max_transfer_secs, 86400);
    /* Hostile-network completion/integrity gates for the native TPC pull, both
     * default off (a size mismatch always fails regardless; these only govern the
     * "no size" and "verify content checksum" postures). */
    ngx_conf_merge_value(conf->tpc_require_source_size,
                         prev->tpc_require_source_size, 0);
    /* tpc_verify_checksum merge -> ngx_http_brix_shared_merge
     * (common.tpc_verify_checksum, str "" = off) — phase-101 W4. */
    ngx_conf_merge_value(conf->tpc_transfer_max_age,
                         prev->tpc_transfer_max_age, 0);
    /* Phase 39 (WS5): publish the abandoned-slot reaper age to the shared TPC
     * registry (config-time, before fork).  Guarded so a 0-default block does not
     * disable a sibling block that enabled it. */
    if (conf->tpc_transfer_max_age > 0) {
        brix_tpc_registry_set_max_age((time_t) conf->tpc_transfer_max_age);
    }
    ngx_conf_merge_str_value(conf->tpc_outbound_bearer_file,
                             prev->tpc_outbound_bearer_file, "");
    ngx_conf_merge_str_value(conf->tpc_outbound_token_endpoint,
                             prev->tpc_outbound_token_endpoint, "");
    ngx_conf_merge_str_value(conf->tpc_outbound_client_id,
                             prev->tpc_outbound_client_id, "");
    ngx_conf_merge_str_value(conf->tpc_outbound_client_secret,
                             prev->tpc_outbound_client_secret, "");
    ngx_conf_merge_str_value(conf->tpc_outbound_scope,
                             prev->tpc_outbound_scope, "storage.read");
}

/*
 * WHAT: merge the node sizing group — manager mode, staged/resumable uploads,
 *       and the pipeline/registry/session/redirector-cache slot counts.
 * WHY:  the pipeline-window clamp is its own decision; isolating it keeps the
 *       cluster orchestrator flat.
 * HOW:  standard child<-parent inheritance, then clamp pipeline_depth into
 *       [MIN, MAX] (the recv-loop ring arithmetic needs a positive bounded
 *       modulus).
 */
static void
brix_merge_srv_cluster_sizing(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_value(conf->manager_mode,         prev->manager_mode,         0);
    brix_node_caps_conf_merge(&conf->caps, &prev->caps);
    /* Uploads are staged + resumable by DEFAULT (atomic commit-on-close, resume
     * across a restart).  Set brix_upload_resume off to opt out. */
    ngx_conf_merge_value(conf->upload_resume,        prev->upload_resume,        1);
    ngx_conf_merge_str_value(conf->upload_stage_dir, prev->upload_stage_dir,     "");
    ngx_conf_merge_uint_value(conf->pipeline_depth,  prev->pipeline_depth,
                              BRIX_PIPELINE_DEPTH_DEFAULT);
    /* Clamp the in-flight pipeline window to a sane range: >=1 (the recv loop and
     * ring arithmetic require a positive modulus) and <=MAX (bounds per-connection
     * out_ring/rd_pool memory). */
    if (conf->pipeline_depth < BRIX_PIPELINE_DEPTH_MIN) {
        conf->pipeline_depth = BRIX_PIPELINE_DEPTH_MIN;
    } else if (conf->pipeline_depth > BRIX_PIPELINE_DEPTH_MAX) {
        conf->pipeline_depth = BRIX_PIPELINE_DEPTH_MAX;
    }
    ngx_conf_merge_uint_value(conf->registry_slots,  prev->registry_slots,  128);
    ngx_conf_merge_uint_value(conf->session_slots,   prev->session_slots,
                              BRIX_SESSION_REGISTRY_SLOTS);
    /* Left UNSET when unconfigured; postconfiguration treats UNSET as
     * "use the compile-time default" (BRIX_REDIR_CACHE_SLOTS). */
    ngx_conf_merge_uint_value(conf->redir_cache_slots, prev->redir_cache_slots,
                              NGX_CONF_UNSET_UINT);
}

/*
 * WHAT: merge the active-health-check group (Phase 22) — enable, interval,
 *       timeout, failure threshold, blacklist duration, and probe type.
 * WHY:  a self-contained directive family; a dedicated helper keeps it out of
 *       the orchestrator's flow.
 * HOW:  plain child<-parent inheritance; disabled by default (non-breaking).
 */
static void
brix_merge_srv_healthcheck(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_value(conf->hc.enabled,       prev->hc.enabled,       0);
    ngx_conf_merge_msec_value(conf->hc.interval_ms,  prev->hc.interval_ms,  30000);
    ngx_conf_merge_msec_value(conf->hc.timeout_ms,   prev->hc.timeout_ms,    5000);
    ngx_conf_merge_uint_value(conf->hc.threshold,    prev->hc.threshold,        3);
    ngx_conf_merge_msec_value(conf->hc.blacklist_ms, prev->hc.blacklist_ms, 60000);
    ngx_conf_merge_uint_value(conf->hc.type, prev->hc.type, BRIX_HC_TYPE_PING);
}

/*
 * WHAT: merge the traffic-mirror group (Phase 24) — targets, sample rate, the
 *       opcode/method include+exclude masks, auth-strip, divergence logging,
 *       timeout, and write-mirroring; then derive the `enabled` flag.
 * WHY:  the derived `enabled` (targets present ⇒ on) is a distinct rule worth
 *       isolating.
 * HOW:  inherit parent targets when unset, merge the tunables, then set
 *       `enabled` from the presence of at least one target.
 */
static void
brix_merge_srv_mirror(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    /* Phase 24: traffic mirror — stream-surface extras, then the shared knob
     * merge (mirror.h), which inherits targets and derives `enabled`.
     * Opcode default: mirror ALL ops; the operator de-selects with
     * brix_mirror_exclude_opcodes (or restricts with brix_mirror_opcodes). */
    ngx_conf_merge_uint_value(conf->mirror.opcode_mask, prev->mirror.opcode_mask,
                              BRIX_MIRROR_OP_ALL);
    ngx_conf_merge_uint_value(conf->mirror.opcode_exclude_mask,
                              prev->mirror.opcode_exclude_mask, 0);
    brix_mirror_conf_merge_common(&conf->mirror, &prev->mirror);
}

/*
 * WHAT: merge the CMS selection knobs — load weight, path affinity, rm/rmdir
 *       fan-out, cluster role, state relay, the delay-server floor and the
 *       scheduler weight vector.
 * WHY:  several of these are process-wide set-once installs (one registry, one
 *       weight vector), so they must all be resolved in the same pass, before
 *       fork — grouping them makes that shared property visible.
 * HOW:  merge each directive, clamp the ones that are hints rather than
 *       contracts, then install the process-wide values.
 */
static void
brix_merge_srv_cms_selection(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    /* Phase-89 W4: load-weighted selection knob (0 = legacy scoring).  Values
     * are clamped, not rejected — the weight is a balancing hint.  Applied
     * process-wide like brix_manager_stale_after (set once before fork). */
    ngx_conf_merge_value(conf->cms.load_weight, prev->cms.load_weight, 0);
    if (conf->cms.load_weight < 0) {
        conf->cms.load_weight = 0;
    }
    if (conf->cms.load_weight > 100) {
        conf->cms.load_weight = 100;
    }
    if (conf->cms.load_weight > 0) {
        brix_srv_set_load_weight((ngx_uint_t) conf->cms.load_weight);
    }

    /* Phase-89 W5: path-affinity sticky selection (process-wide, like the
     * load weight — set once before fork) + multi-source locate replies. */
    ngx_conf_merge_value(conf->cms.affinity,     prev->cms.affinity,     0);
    ngx_conf_merge_value(conf->cms.locate_multi, prev->cms.locate_multi, 0);
    if (conf->cms.affinity) {
        brix_srv_set_affinity(1);
    }

    /* Phase-89 W8: rm/rmdir fan-out to all holder nodes + its reply window.
     * The window is the success deadline (node executor is silent on success),
     * so it must be short enough to sit inside any client request timeout. */
    ngx_conf_merge_value(conf->cms.fanout, prev->cms.fanout, 0);
    ngx_conf_merge_msec_value(conf->cms.fanout_window,
                                prev->cms.fanout_window, 500);

    /* Phase-61 W7: explicit upward-leg cluster role (auto = legacy mode
     * derivation + permissive inbound dispatch). */
    ngx_conf_merge_uint_value(conf->cms.role, prev->cms.role,
                              BRIX_CMS_ROLE_AUTO);

    /* Phase-61 W7: multi-tier kYR_state recursion (off = registry-only). */
    ngx_conf_merge_value(conf->cms.state_relay, prev->cms.state_relay, 0);

    /* §2.2 (cms.delay servers): SUPCount floor + hold seconds.  Process-wide
     * set-once like the load weight — the registry is one table. */
    ngx_conf_merge_value(conf->cms.delay_servers, prev->cms.delay_servers, 0);
    ngx_conf_merge_value(conf->cms.delay_hold,    prev->cms.delay_hold,    5);
    if (conf->cms.delay_servers > 0) {
        brix_srv_set_delay_servers((ngx_uint_t) conf->cms.delay_servers);
    }
    if (conf->cms.delay_hold < 1) {
        conf->cms.delay_hold = 1;      /* kXR_wait 0 would busy-loop clients */
    }

    /* §2.3 (cms.sched): component weights + fuzz + maxload; any weight set
     * installs the process-wide vector (all-zero = legacy scoring). */
    ngx_conf_merge_value(conf->cms.sched_cpu,     prev->cms.sched_cpu,     0);
    ngx_conf_merge_value(conf->cms.sched_io,      prev->cms.sched_io,      0);
    ngx_conf_merge_value(conf->cms.sched_runq,    prev->cms.sched_runq,    0);
    ngx_conf_merge_value(conf->cms.sched_mem,     prev->cms.sched_mem,     0);
    ngx_conf_merge_value(conf->cms.sched_pag,     prev->cms.sched_pag,     0);
    ngx_conf_merge_value(conf->cms.sched_space,   prev->cms.sched_space,   0);
    ngx_conf_merge_value(conf->cms.sched_fuzz,    prev->cms.sched_fuzz,    0);
    ngx_conf_merge_value(conf->cms.sched_maxload, prev->cms.sched_maxload, 0);
    if (conf->cms.sched_cpu | conf->cms.sched_io | conf->cms.sched_runq
        | conf->cms.sched_mem | conf->cms.sched_pag | conf->cms.sched_space
        | conf->cms.sched_fuzz | conf->cms.sched_maxload)
    {
        brix_srv_sched_t sched;
        sched.cpu     = (ngx_uint_t) conf->cms.sched_cpu;
        sched.io      = (ngx_uint_t) conf->cms.sched_io;
        sched.runq    = (ngx_uint_t) conf->cms.sched_runq;
        sched.mem     = (ngx_uint_t) conf->cms.sched_mem;
        sched.pag     = (ngx_uint_t) conf->cms.sched_pag;
        sched.space   = (ngx_uint_t) conf->cms.sched_space;
        sched.fuzz    = (ngx_uint_t) conf->cms.sched_fuzz;
        sched.maxload = (ngx_uint_t) conf->cms.sched_maxload;
        brix_srv_set_sched(&sched);
    }

    /* §2.5: stage-aware selection (off = legacy least-utilised pick). */
    ngx_conf_merge_value(conf->cms.stage_select, prev->cms.stage_select, 0);
}


/*
 * WHAT: merge the CMS data-plane feeds — loc-cache TTL policy, shared-filesystem
 *       mode, the external perf program and the advertised alternate data server.
 * WHY:  these describe where the cluster's load and location facts come from,
 *       independent of how a server is then chosen from them.
 * HOW:  merge each directive, install the two loc-cache TTLs process-wide when
 *       configured, and inherit an unset altds string from the parent.
 */
static void
brix_merge_srv_cms_feeds(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    /* §2.6: loc-cache TTL policy (process-wide set-once).  fxhold keeps the
     * legacy 30s default unless configured; emptylife 0 = negatives off. */
    ngx_conf_merge_msec_value(conf->cms.fxhold,    prev->cms.fxhold,    0);
    ngx_conf_merge_msec_value(conf->cms.emptylife, prev->cms.emptylife, 0);
    if (conf->cms.fxhold > 0) {
        brix_loc_cache_set_ttl(conf->cms.fxhold);
    }
    if (conf->cms.emptylife > 0) {
        brix_loc_cache_set_emptylife(conf->cms.emptylife);
    }

    /* §2.8: shared-filesystem mode (off = per-file discovery). */
    ngx_conf_merge_value(conf->cms.dfs, prev->cms.dfs, 0);

    /* §2.11 (cms.perf pgm): external load feed + freshness window. */
    ngx_conf_merge_str_value(conf->cms.perf_pgm, prev->cms.perf_pgm, "");
    ngx_conf_merge_msec_value(conf->cms.perf_int, prev->cms.perf_int, 30000);

    /* §2.12 (cms.altds): advertised foreign data port + liveness monitor. */
    ngx_conf_merge_value(conf->cms.altds_port,      prev->cms.altds_port,   0);
    ngx_conf_merge_value(conf->cms.altds_monitor, prev->cms.altds_monitor, 0);
    ngx_conf_merge_msec_value(conf->cms.altds_interval,
                              prev->cms.altds_interval, 10000);
    /* §2.4 mSpace policy floor (MB) advertised in kYR_login; default 100,
     * byte-identical to the prior NGX_BRIX_CMS_MIN_FREE_MB constant. */
    ngx_conf_merge_value(conf->cms.min_free_mb, prev->cms.min_free_mb, 100);
    if (conf->cms.altds.len == 0 && prev->cms.altds.len > 0) {
        conf->cms.altds = prev->cms.altds;
    }
}


/*
 * WHAT: merge the heartbeat interval and the resilience deadlines that derive
 *       from it (read/send/keepalive/tcp_user + the connect-backoff pair left
 *       UNSET for worker-time choice).
 * WHY:  the read-timeout auto-derivation depends on the just-merged interval;
 *       isolating it keeps that ordering explicit and unbreakable — no directive
 *       merged after this point can change what the deadlines derived from.
 * HOW:  merge the interval (floored at 1s to avoid a busy-loop heartbeat), then
 *       derive read_timeout = max(3×interval, 90s) when unset, and default
 *       tcp_user_timeout to the read timeout.
 */
static void
brix_merge_srv_cms_deadlines(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_value(conf->cms.interval,        prev->cms.interval,    30);
    if (conf->cms.interval < 1) {
        /* 0 would arm a 0ms heartbeat timer AND zero the reconnect backoff
         * (connect.c) — both busy-loops. Floor the heartbeat at 1s. */
        conf->cms.interval = 1;
    }

    /*
     * Phase 50: CMS client resilience deadlines.  Resolve here (after
     * cms_interval is merged) so an unset directive auto-derives a generous
     * ON-by-default value from the heartbeat interval; an explicit 0 disables.
     *   - read timeout: max(3 x interval, 90s) — a healthy real cmsd pings well
     *     within its interval, so this never trips a conformant manager.
     *   - send timeout: 10s — bounds a manager that stops draining our writes.
     *   - tcp_user_timeout: defaults to the read-timeout as a kernel backstop.
     */
    if (conf->cms.read_timeout == NGX_CONF_UNSET_MSEC) {
        if (prev->cms.read_timeout != NGX_CONF_UNSET_MSEC) {
            conf->cms.read_timeout = prev->cms.read_timeout;
        } else {
            ngx_msec_t d = (ngx_msec_t) conf->cms.interval * 3 * 1000;
            conf->cms.read_timeout = (d > 90000) ? d : 90000;
        }
    }
    ngx_conf_merge_msec_value(conf->cms.send_timeout, prev->cms.send_timeout,
                              10000);
    ngx_conf_merge_value(conf->cms.tcp_keepalive, prev->cms.tcp_keepalive, 1);
    if (conf->cms.tcp_user_timeout == NGX_CONF_UNSET_MSEC) {
        conf->cms.tcp_user_timeout =
            (prev->cms.tcp_user_timeout != NGX_CONF_UNSET_MSEC)
                ? prev->cms.tcp_user_timeout
                : conf->cms.read_timeout;
    }

    /* Leave these UNSET through the merge so connect.c can pick the manager-locality
     * (loopback vs remote) profile default at worker start; an explicit directive
     * still wins and is inherited child<-parent. */
    ngx_conf_merge_msec_value(conf->cms.initial_delay, prev->cms.initial_delay,
                              NGX_CONF_UNSET_MSEC);
    ngx_conf_merge_msec_value(conf->cms.connect_retry, prev->cms.connect_retry,
                              NGX_CONF_UNSET_MSEC);
}


/*
 * WHAT: merge the CMS client group (Phase 50) — locate timeout, paths and vnid,
 *       then the selection knobs, the data-plane feeds and the resilience
 *       deadlines.
 * WHY:  the group is too wide to read as one body, and its one real ordering
 *       constraint (deadlines derive from the merged heartbeat interval) is
 *       easiest to enforce as call order.
 * HOW:  merge the three plain directives, then run the three groups in the
 *       order their dependencies require — deadlines last.
 */
static void
brix_merge_srv_cms(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_msec_value(conf->cms.locate_timeout, prev->cms.locate_timeout,
                              5000);
    ngx_conf_merge_str_value(conf->cms.paths,       prev->cms.paths,       "");
    ngx_conf_merge_str_value(conf->cms.vnid,        prev->cms.vnid,        "");

    brix_merge_srv_cms_selection(conf, prev);
    brix_merge_srv_cms_feeds(conf, prev);
    brix_merge_srv_cms_deadlines(conf, prev);
}

/*
 * WHAT: inherit the resolved-address fields (CMS manager, HTTP handoff, relay,
 *       and the upstream redirector host/port) from the parent scope.
 * WHY:  these are already-resolved runtime addresses that ngx_conf_merge_* can't
 *       express; grouping the NULL/len==0 guards keeps them together.
 * HOW:  copy the parent's address family only when the child left it unset.
 */
static void
brix_merge_srv_cluster_addrs(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    if (conf->cms.addr == NULL && prev->cms.addr != NULL) {
        conf->cms.addr = prev->cms.addr;
        conf->cms.manager = prev->cms.manager;
        conf->cms.managers = prev->cms.managers;
    }

    if (conf->http_handoff_addr == NULL && prev->http_handoff_addr != NULL) {
        conf->http_handoff_addr = prev->http_handoff_addr;
        conf->http_handoff_name = prev->http_handoff_name;
    }

    if (conf->relay_addr == NULL && prev->relay_addr != NULL) {
        conf->relay_addr = prev->relay_addr;
        conf->relay_name = prev->relay_name;
    }

    /* Inherit upstream redirector from parent scope if not set locally */
    if (conf->upstream_host.len == 0 && prev->upstream_host.len > 0) {
        conf->upstream_host = prev->upstream_host;
        conf->upstream_port = prev->upstream_port;
        conf->upstream_addr = prev->upstream_addr;
    }
}

/*
 * WHAT: merge the VO/group/manager-map rule arrays.
 * WHY:  the three arrays share an identical merge-and-fail-check shape; a helper
 *       keeps the NGX_CONF_ERROR handling out of the orchestrator.
 * HOW:  brix_merge_arrays() each child array over the parent; a NULL result with
 *       a non-empty parent or child signals allocation failure → NGX_CONF_ERROR.
 */
static char *
brix_merge_srv_rules(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_array_t *child_vo_rules;
    ngx_array_t *child_group_rules;
    ngx_array_t *child_manager_map;

    child_vo_rules = conf->vo_rules;
    conf->vo_rules = brix_merge_arrays(cf, prev->vo_rules, child_vo_rules,
                                         sizeof(brix_vo_rule_t));
    if (conf->vo_rules == NULL && (prev->vo_rules != NULL || child_vo_rules != NULL)) {
        return NGX_CONF_ERROR;
    }

    child_group_rules = conf->group_rules;
    conf->group_rules = brix_merge_arrays(cf, prev->group_rules,
                                            child_group_rules,
                                            sizeof(brix_group_rule_t));
    if (conf->group_rules == NULL
        && (prev->group_rules != NULL || child_group_rules != NULL)) {
        return NGX_CONF_ERROR;
    }

    /* Merge manager_map entries (prefix -> backend mappings) */
    child_manager_map = conf->manager_map;
    conf->manager_map = brix_merge_arrays(cf, prev->manager_map,
                                           child_manager_map,
                                           sizeof(brix_manager_map_t));
    if (conf->manager_map == NULL
        && (prev->manager_map != NULL || child_manager_map != NULL)) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * WHAT: refuse `brix_manager_mode on` together with `brix_read_only on` at
 *       config time — nginx -t fails and the server does not start.
 * WHY:  the two directives make CONTRADICTORY promises about the same request.
 *       manager_redirect_mutation() (dispatch_write.c) answers a path mutation
 *       with a REDIRECT to a data node, and it runs BEFORE the local write gate
 *       that brix_read_only arms — by design, because a manager holds no data
 *       and therefore cannot answer for it. So on a manager, `brix_read_only on`
 *       does NOT make the namespace read-only: it hands the client the address
 *       of a node that will happily accept the write. An operator who wrote both
 *       directives believes they have a read-only endpoint and does not. That is
 *       a security misconfiguration, not a preference, so it is fatal rather
 *       than a warning: the two are different ROLES and belong in different
 *       server {} blocks.
 * HOW:  both flags have settled by now (common.read_only in the security merge,
 *       manager_mode in the sizing merge above), so a plain conjunction suffices.
 *       Tested by nginx -t; see docs/03-configuration/read-only-root-gateway.md.
 */
static char *
brix_merge_srv_readonly_role_check(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *conf)
{
    if (conf->common.read_only != 1 || conf->manager_mode != 1) {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "brix_manager_mode and brix_read_only are mutually exclusive: a manager "
        "redirects mkdir/rm/rmdir/mv/chmod/truncate to a data node BEFORE the "
        "local read-only gate runs, so the endpoint would not be read-only. "
        "Put the manager and the read-only gateway in separate server {} blocks%s",
        conf->common.read_only_public == 1
            ? " (brix_read_only_public implies brix_read_only)" : "");

    return NGX_CONF_ERROR;
}

/* Cluster & sessions: manager/redirector mode, write recovery + staged uploads,
 * pipeline/registry/session sizing, active health checks, the traffic mirror,
 * the CMS client (+ resilience-timeout derivation), listen port, checksum-scan
 * limits, and the VO/group/manager-map rule arrays + redirector inheritance.
 * Also the point where the read-only role check runs: brix_read_only has settled
 * in the security merge and manager_mode settles in the sizing merge above. */
char *
brix_merge_srv_cluster(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    brix_merge_srv_cluster_sizing(conf, prev);
    if (brix_merge_srv_readonly_role_check(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    brix_merge_srv_healthcheck(conf, prev);
    brix_merge_srv_mirror(conf, prev);
    brix_merge_srv_cms(conf, prev);

    ngx_conf_merge_value(conf->listen_port,         prev->listen_port,     BRIX_DEFAULT_PORT);
    ngx_conf_merge_uint_value(conf->ckscan_max_depth,
                              prev->ckscan_max_depth, 32);
    ngx_conf_merge_uint_value(conf->ckscan_max_files,
                              prev->ckscan_max_files, 100000);

    brix_merge_srv_cluster_addrs(conf, prev);

    return brix_merge_srv_rules(cf, conf, prev);
}

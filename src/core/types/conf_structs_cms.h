/*
 * core/types/conf_structs_cms.h
 *
 * The CMS clustering config group — the cluster role/response enums, one
 * manager endpoint, the fsxeq operator-program slots, and brix_cms_conf_t
 * itself — split (file-size burndown, coding-standards §1) out of
 * conf_structs.h, which had outgrown the 600-line cap.  The CMS group is by
 * far the largest concept in that file and the only one whose fields all reach
 * through a single `conf->cms.<field>` prefix, so it lifts out whole.
 *
 * NOT self-contained and NOT a standalone TU: it is #included from
 * conf_structs.h at exactly the point the block used to occupy, so every
 * prerequisite (ngx core, the manager-endpoint cap, PATH_MAX) is already in
 * scope and the struct assembles byte-identically — zero ABI change, every
 * `conf->cms.<field>` access unchanged.  Do not include it directly; include
 * config.h.
 */

#ifndef BRIX_TYPES_CONF_STRUCTS_CMS_H
#define BRIX_TYPES_CONF_STRUCTS_CMS_H

/* Explicit CMS cluster role for the upward (node->manager) leg, Phase-61 W7:
 * Pander-parity login Mode bits + the inbound valid-ops table for frames from
 * the parent.  AUTO keeps the legacy derivation (server, or server|manager
 * when manager_mode) with the permissive dispatch table. */
#define BRIX_CMS_ROLE_AUTO        0
#define BRIX_CMS_ROLE_SERVER      1   /* kYR_server (0x8) */
#define BRIX_CMS_ROLE_MANAGER     2   /* kYR_manager (0x2), manVOps inbound */
#define BRIX_CMS_ROLE_SUPERVISOR  3   /* kYR_manager|kYR_server (0xA), supVOps */
#define BRIX_CMS_ROLE_PEER        4   /* §2.17: kYR_peer — overflow cluster
                                         consulted only on a local miss */
#define BRIX_CMS_ROLE_PROXY       5   /* §2.17: kYR_proxy|kYR_server — proxy
                                         data server (selectable normally) */

/* Phase-115 W2.1 [brix_cms_response redirect|proxy]: how a manager answers a
 * client once the registry / CMS wake has selected a data server.  REDIRECT is
 * the stock cmsd/xrootd kXR_redirect; PROXY pins the session to the selected
 * server and relays through the transparent proxy (src/net/proxy/cms_select.c). */
#define BRIX_CMS_RESPONSE_REDIRECT  0
#define BRIX_CMS_RESPONSE_PROXY     1

/* One configured CMS manager endpoint (an entry of brix_cms_conf_t.managers).
 * The raw string is NUL-terminated (brix_copy_conf_string) so log/action sites
 * can borrow it as a C string. */
typedef struct {
    ngx_str_t    raw;    /* directive text, e.g. "127.0.0.1:1213" */
    ngx_addr_t  *addr;   /* registry-owned address (phase-116): socklen == 0
                          * until the worker's runtime resolution lands */
    struct brix_dns_target_s  *dns;   /* the runtime DNS target behind addr */
} brix_cms_manager_ent_t;

/* Redundant-manager cap — stock cmsd client parity (its MaxMan). */
#define NGX_BRIX_CMS_MAX_MANAGERS  15

/*
 * §2.13 (cms.fsxeq): one operator program registered for one or more forwarded
 * namespace ops.  A directive line contributes exactly one of these and every
 * op the line names points at it, so `brix_cms_fsxeq mv rm /usr/local/bin/nsop`
 * stores the command once.  argv holds the FIXED prefix tokens (the program and
 * any literal arguments the operator baked into the line, NUL-terminated, from
 * cf->pool); the runner appends the op's own arguments after them — the same
 * shape stock XrdOucProg uses, where Run()'s arguments are appended to the
 * configured command line, so an operator can disambiguate a program shared
 * between ops by naming the op as a literal argument on the line.
 */
typedef struct {
    char      **argv;      /* NULL-terminated fixed prefix (cf->pool)         */
    ngx_uint_t  argc;      /* its token count (argv[argc] == NULL)            */
    ngx_str_t   display;   /* the whole command line, for log and error text  */
} brix_cms_fsxeq_prog_t;

/* The seven forwarded namespace ops stock's cms.fsxeq can replace, as slot
 * indices into brix_cms_conf_t.fsxeq[].  Deliberately NOT the node_ops action
 * enum: that enum lives in src/net/cms/ and also carries prepadd/prepdel, which
 * cms.fsxeq does not cover. */
#define BRIX_CMS_FSXEQ_CHMOD    0
#define BRIX_CMS_FSXEQ_MKDIR    1
#define BRIX_CMS_FSXEQ_MKPATH   2
#define BRIX_CMS_FSXEQ_MV       3
#define BRIX_CMS_FSXEQ_RM       4
#define BRIX_CMS_FSXEQ_RMDIR    5
#define BRIX_CMS_FSXEQ_TRUNC    6
#define BRIX_CMS_FSXEQ_OPS      7

/* Fixed prefix tokens + the two runtime arguments the widest op passes + NULL. */
#define BRIX_CMS_FSXEQ_ARGV_MAX 16

/* CMS manager heartbeat + client-side network-fault resilience.  Grouped as one
 * sub-struct so the per-server config block stays navigable; every field is
 * reached as conf->cms.<field>.  (The advertised listen_port stays a top-level
 * field — it is not CMS-specific.) */
typedef struct {
    ngx_msec_t          locate_timeout;   /* [brix_cms_locate_timeout 5s] */
    ngx_str_t           manager;          /* first manager's raw host:port (role/gate logs) */
    ngx_addr_t         *addr;             /* first manager's resolved address — the
                                             "has upstream" gate everywhere */
    ngx_array_t        *managers;         /* brix_cms_manager_ent_t[] — ALL managers from
                                             [brix_cms_manager h:p ...] (repeatable);
                                             NULL when the directive is absent */
    ngx_str_t           paths;            /* [brix_cms_paths /data] — exported path list */
    time_t              interval;         /* [brix_cms_interval 60] — heartbeat period */
    ngx_brix_cms_ctx_t **ctxs;            /* runtime: one heartbeat ctx per manager (heap;
                                             worker 0 only — NULL elsewhere) */
    ngx_uint_t          nctxs;            /* runtime: live ctx count; the "CMS client
                                             started on this worker" gate */
    ngx_uint_t          rr;               /* runtime: round-robin cursor for locate
                                             rotation across logged-in managers */
    ngx_uint_t          suspended;        /* set by kYR_status suspend; cleared by resume */
    ngx_msec_t          read_timeout;     /* [brix_cms_read_timeout] manager inactivity
                                             deadline; unset => max(3*interval, 90s). 0=off */
    ngx_msec_t          send_timeout;     /* [brix_cms_send_timeout] heartbeat send-stall
                                             deadline; unset => 10s. 0=off */
    ngx_flag_t          tcp_keepalive;    /* [brix_cms_tcp_keepalive on] SO_KEEPALIVE +
                                             tight probes on the manager socket */
    ngx_msec_t          tcp_user_timeout; /* [brix_cms_tcp_user_timeout] TCP_USER_TIMEOUT
                                             (ms); unset => read-timeout backstop. 0=off */
    ngx_msec_t          initial_delay;    /* [brix_cms_initial_delay] delay before the
                                             first connect; unset => 0 (loopback) / 10ms */
    ngx_msec_t          connect_retry;    /* [brix_cms_connect_retry] retry interval while
                                             the manager is not yet listening */
    ngx_str_t           vnid;             /* [brix_cms_vnid <id>] Phase-89 W9: virtual
                                             network id advertised in LOGIN envCGI
                                             ("vnid=<id>"); empty => envCGI stays empty */
    ngx_int_t           load_weight;      /* [brix_cms_load_weight 0-100] Phase-89 W4:
                                             manager-side selection weight for the
                                             heartbeat machine load; 0 = space/util
                                             only (byte-identical legacy scoring) */
    ngx_flag_t          affinity;         /* [brix_cms_affinity on] Phase-89 W5: pin
                                             repeated selections of a path to ONE
                                             eligible (fresh, non-blacklisted)
                                             server; drained hosts never sticky */
    ngx_flag_t          locate_multi;     /* [brix_cms_locate_multi on] Phase-89 W5:
                                             answer kXR_locate with the FULL live
                                             server set (kXR_ok, lateral redirect)
                                             instead of a single kXR_redirect */
    ngx_flag_t          fanout;           /* [brix_cms_fanout on] Phase-89 W8:
                                             fan a client kXR_rm/kXR_rmdir out to
                                             EVERY holder node (this worker's CMS
                                             conns) instead of redirecting to one */
    ngx_msec_t          fanout_window;    /* [brix_cms_fanout_window] W8 reply
                                             window: no kYR_error from any node
                                             within it => kXR_ok; unset => 500ms */
    ngx_uint_t          role;             /* [brix_cms_role auto|server|manager|
                                             supervisor] Phase-61 W7: BRIX_CMS_ROLE_*
                                             — explicit Pander login Mode + inbound
                                             valid-ops parity; auto = legacy */
    ngx_uint_t          response;         /* [brix_cms_response redirect|proxy]
                                             Phase-115 W2.1: BRIX_CMS_RESPONSE_* —
                                             answer a selection with kXR_redirect
                                             (default) or proxy the session to the
                                             selected server */
    ngx_flag_t          state_relay;      /* [brix_cms_state_relay on] Phase-61 W7:
                                             on a registry miss, relay a parent
                                             manager's kYR_state down to this
                                             tier's own nodes and echo the first
                                             kYR_have up (multi-tier recursion);
                                             off = registry-only legacy */
    ngx_int_t           delay_servers;    /* [brix_cms_delay_servers <n>] §2.2:
                                             SUPCount floor — hold selects until
                                             >= n data servers registered; 0=off */
    ngx_int_t           delay_hold;       /* [brix_cms_delay_hold <secs>] §2.2:
                                             kXR_wait seconds while below the
                                             floor; default 5 */
    ngx_int_t           sched_cpu;        /* [brix_cms_sched cpu N io N runq N
                                             mem N pag N space N fuzz N
                                             maxload N] §2.3 component weights;
                                             all UNSET/0 = legacy scoring */
    ngx_int_t           sched_io;
    ngx_int_t           sched_runq;
    ngx_int_t           sched_mem;
    ngx_int_t           sched_pag;
    ngx_int_t           sched_space;
    ngx_int_t           sched_fuzz;
    ngx_int_t           sched_maxload;
    ngx_flag_t          stage_select;     /* [brix_cms_stage_select on] §2.5:
                                             reads of a file no node holds go to
                                             the roomiest stage-capable node */
    ngx_msec_t          fxhold;           /* [brix_cms_fxhold <time>] §2.6: loc
                                             cache positive TTL (unset = 30s
                                             legacy; stock default is 8h) */
    ngx_msec_t          emptylife;        /* [brix_cms_emptylife <time>] §2.6:
                                             negative location-cache TTL; 0=off */
    ngx_flag_t          dfs;              /* [brix_cms_dfs on] §2.8: shared-FS
                                             cluster — skip the per-file state
                                             fan-out; select purely by load */
    ngx_str_t           perf_pgm;         /* [brix_cms_perf_pgm <cmd>] §2.11:
                                             external load-feed program; its
                                             stdout lines "cpu net xeq mem pag"
                                             override the /proc meter */
    ngx_msec_t          perf_int;         /* [brix_cms_perf_interval <time>]
                                             §2.11: freshness window (a line
                                             older than 2x this falls back to
                                             /proc); default 30s */
    ngx_str_t           altds;            /* [brix_cms_altds <port> [monitor]]
                                             §2.12: advertise a co-located
                                             foreign data server's port as this
                                             node's data port */
    ngx_int_t           altds_port;       /* parsed from the directive; 0=off */
    ngx_flag_t          altds_monitor;    /* liveness-probe the altds and drive
                                             kYR_status suspend/resume */
    ngx_msec_t          altds_interval;   /* probe cadence; default 10s */
    ngx_int_t           min_free_mb;      /* [brix_cms_min_free <MB>] §2.4: the
                                             mSpace policy floor advertised in the
                                             kYR_login payload — the free space
                                             (MB) below which the manager should
                                             stop selecting this node for writes.
                                             Default 100 (byte-identical to the
                                             prior hardcoded constant). */
    ngx_flag_t          space_enforce;    /* [brix_cms_space_enforce on|off]
                                             §2.4, MANAGER side: honour the
                                             floor each node advertised when
                                             choosing a WRITE target.  Off by
                                             default — turning it on changes
                                             where writes land. */
    ngx_int_t           space_hwm_mb;     /* [brix_cms_space_hwm <MB>] free
                                             space a blocked node must regain
                                             before it is eligible again.
                                             0 = its own floor (no hysteresis
                                             band); below the floor is clamped
                                             up to it. */
    brix_cms_fsxeq_prog_t *fsxeq[BRIX_CMS_FSXEQ_OPS];
                                          /* [brix_cms_fsxeq <ops> <prog...>]
                                             §2.13: the operator program that
                                             REPLACES the built-in execution of
                                             each named forwarded namespace op.
                                             A NULL slot keeps the built-in
                                             confined leg. */
    ngx_msec_t          fsxeq_timeout;    /* [brix_cms_fsxeq_timeout <time>]
                                             §2.13: deadline after which the
                                             program's whole process group is
                                             killed and the op fails; 10s. */
} brix_cms_conf_t;

#endif /* BRIX_TYPES_CONF_STRUCTS_CMS_H */

#ifndef NGX_XROOTD_PMARK_H
#define NGX_XROOTD_PMARK_H

/*
 * pmark.h — SciTags packet marking (network flow tagging) for nginx-xrootd.
 *
 * WHAT: Public types + API for the `src/pmark/` subsystem that labels each data
 *   flow with a SciTags (experiment, activity) pair, using the two SciTags
 *   techniques: (1) out-of-band "firefly" UDP reporting (firefly.c) and (2)
 *   in-band IPv6 Flow Label stamping (flowlabel.c). It mirrors XRootD's `pmark`
 *   directive family so a site keeps working with its SciTags/flowd dashboards
 *   after swapping an XRootD gateway for nginx-xrootd.  See
 *   docs/refactor/phase-34-packet-marking-scitags.md for the full design.
 *
 * WHY: It is a SHARED subsystem (called from the root:// stream module, the
 *   WebDAV/S3 HTTP modules, and TPC) rather than a standalone nginx module, so
 *   the per-server config lives in the common preamble (config/shared_conf.h)
 *   and the runtime state is one per-worker object plus one per-flow object.
 *
 * HOW: A flow-id is a 16-bit value `(experiment << 6) | activity` (10-bit
 *   experiment 1..1023, 6-bit activity 1..63).  Config is opt-in.  Marking is
 *   ALWAYS fail-open: a misconfiguration, an unreachable collector, or a kernel
 *   that refuses a flow label degrades to "not marked" and NEVER fails, blocks,
 *   or slows a transfer.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* ---- SciTags flow-id model (XrdNetPMark.hh:89-99) ---- */
#define XROOTD_PMARK_FLOW_MIN    65       /* smallest valid scitag.flow value   */
#define XROOTD_PMARK_FLOW_MAX    65535    /* 16-bit flow-id space               */
#define XROOTD_PMARK_ACT_BITS    6        /* low 6 bits = activity              */
#define XROOTD_PMARK_ACT_MASK    0x3F     /* activity mask                      */
#define XROOTD_PMARK_EXP_MIN     1
#define XROOTD_PMARK_EXP_MAX     1023     /* 10-bit experiment space            */
#define XROOTD_PMARK_ACT_MIN     1
#define XROOTD_PMARK_ACT_MAX     63

#define XROOTD_PMARK_FF_PORT     10514    /* default firefly collector UDP port */

/* IPv6 flow-label encoding (flowlabel.c).  glibc does not export
 * IPV6_FLOWLABEL_MASK, so define the 20-bit mask ourselves.  The version nibble
 * marks the flow as SciTags-tagged; pin the exact layout to the deployed SciTags
 * Flow Label spec version here and nowhere else. */
#define XROOTD_PMARK_FL_MASK     0x000FFFFFu
#define XROOTD_PMARK_FL_VERSION  0x1u

/* `xrootd_pmark_domain` enum (which address class is marked). */
enum {
    XROOTD_PMARK_DOMAIN_ANY    = 0,
    XROOTD_PMARK_DOMAIN_LOCAL  = 1,
    XROOTD_PMARK_DOMAIN_REMOTE = 2          /* default, matches XRootD */
};

/* Activity selection: which network role the local end plays for this flow.
 * Drives the "supplier is source" firefly src/dst convention + appname. */
enum {
    XROOTD_PMARK_ACT_READ  = 0,   /* client reads (server is source): http-get  */
    XROOTD_PMARK_ACT_WRITE = 1,   /* client writes (client is source): http-put */
    XROOTD_PMARK_ACT_TPC   = 2    /* third-party copy outbound                  */
};

/* ---- Config (lives inside ngx_http_xrootd_shared_conf_t .common) ---- */

/* One `xrootd_pmark_map_experiment {default|path <p>|vo <v>} <expName>`. */
typedef enum {
    XROOTD_PMARK_EXP_DEFAULT = 0,
    XROOTD_PMARK_EXP_PATH,
    XROOTD_PMARK_EXP_VO
} xrootd_pmark_exp_kind_t;

typedef struct {
    xrootd_pmark_exp_kind_t  kind;
    ngx_str_t                match;     /* path glob or VO name (empty if default) */
    ngx_str_t                exp_name;  /* experiment name (resolved via defsfile) */
} xrootd_pmark_exp_rule_t;

/* One `xrootd_pmark_map_activity <expName> {default|role <r>|user <u>} <actName>`. */
typedef enum {
    XROOTD_PMARK_ACTR_DEFAULT = 0,
    XROOTD_PMARK_ACTR_ROLE,
    XROOTD_PMARK_ACTR_USER
} xrootd_pmark_act_kind_t;

typedef struct {
    ngx_str_t                exp_name;  /* experiment this rule belongs to */
    xrootd_pmark_act_kind_t  kind;
    ngx_str_t                match;     /* role or user (empty if default) */
    ngx_str_t                act_name;  /* activity name (resolved via defsfile) */
} xrootd_pmark_act_rule_t;

typedef struct {
    ngx_flag_t    enable;          /* xrootd_pmark on|off (master switch)        */
    ngx_flag_t    firefly;         /* xrootd_pmark_firefly                       */
    ngx_flag_t    flowlabel;       /* xrootd_pmark_flowlabel (default on)        */
    ngx_flag_t    scitag_cgi;      /* honor client scitag.flow / SciTag: header  */
    ngx_flag_t    firefly_origin;  /* also report to the client origin           */
    ngx_flag_t    http_plain;      /* mark plain WebDAV/S3 GET/PUT (default off) */
    ngx_msec_t    echo;            /* xrootd_pmark_echo seconds (0 = off)        */
    ngx_uint_t    domain;          /* XROOTD_PMARK_DOMAIN_*                       */
    ngx_str_t     appname;         /* firefly context.application                 */
    ngx_str_t     defsfile;        /* scitags experiment/activity JSON registry  */
    ngx_array_t  *firefly_dest;    /* of ngx_str_t "host[:port]"                  */
    ngx_array_t  *exp_rules;       /* of xrootd_pmark_exp_rule_t                  */
    ngx_array_t  *act_rules;       /* of xrootd_pmark_act_rule_t                  */

    /* ---- Resolved at first use (runtime only; never merged) ----
     * The defsfile is parsed, mapping names are resolved to numeric ids, and
     * firefly_dest strings are resolved to sockaddrs ONCE per worker on the
     * first marked flow (guarded by rt_ready), then cached here.  Allocated from
     * the cycle pool so they live for the worker's lifetime. */
    unsigned      rt_ready:1;      /* resolution attempted (success or fail)     */
    unsigned      rt_ok:1;         /* resolution succeeded → marking is live      */
    ngx_array_t  *dest_sa;         /* of xrootd_pmark_dest_t (resolved collectors)*/
    ngx_array_t  *exp_rules_r;     /* of xrootd_pmark_exp_rule_r_t                */
    ngx_array_t  *act_rules_r;     /* of xrootd_pmark_act_rule_r_t                */
} xrootd_pmark_conf_t;

/* A resolved firefly collector address. */
typedef struct {
    struct sockaddr_storage  ss;
    socklen_t                len;
    int                      family;   /* AF_INET / AF_INET6 */
} xrootd_pmark_dest_t;

/* Resolved experiment rule (defsfile name → numeric id). */
typedef struct {
    xrootd_pmark_exp_kind_t  kind;
    ngx_str_t                match;
    ngx_uint_t               exp_id;
} xrootd_pmark_exp_rule_r_t;

/* Resolved activity rule (defsfile name → numeric id, scoped to an experiment). */
typedef struct {
    ngx_uint_t               exp_id;   /* experiment this rule applies to (0=any) */
    xrootd_pmark_act_kind_t  kind;
    ngx_str_t                match;
    ngx_uint_t               act_id;
} xrootd_pmark_act_rule_r_t;

/* ---- Per-flow handle (one per marked transfer) ---- */
typedef struct xrootd_pmark_flow_s {
    xrootd_pmark_conf_t *pm;       /* owning config (for collectors at end)   */
    ngx_uint_t    exp;             /* experiment id (1..1023), 0 = not marked */
    ngx_uint_t    act;             /* activity id (1..63)                     */
    ngx_int_t     fd;              /* socket the flow runs on (for TCP_INFO)  */
    unsigned      is_put:1;        /* supplier-is-source byte-swap convention */
    unsigned      firefly_started:1;
    unsigned      want_origin:1;   /* also report to client origin            */
    char          app[32];         /* appname snapshot                        */
    char          start_iso[40];   /* flow start time (firefly format)        */
    char          src_ip[64];      /* numeric src ip                          */
    char          dst_ip[64];      /* numeric dst ip                          */
    int           src_port;
    int           dst_port;
    char          afi;             /* '4' or '6'                              */
    struct sockaddr_storage peer_ss;  /* client peer (for origin firefly)     */
    socklen_t     peer_len;
} xrootd_pmark_flow_t;

/* ====================================================================== */
/* config.c — directive parsing + per-server config lifecycle             */
/* ====================================================================== */

/* Initialise a pmark config block to NGX_CONF_UNSET sentinels.  Called from
 * ngx_http_xrootd_shared_init() so every protocol inherits it. */
void  xrootd_pmark_conf_init(xrootd_pmark_conf_t *c);

/* Merge parent→child pmark config (defaults: disabled; flowlabel/scitag on;
 * firefly on; domain remote; firefly port 10514).  Called from
 * ngx_http_xrootd_shared_merge().  Returns NGX_CONF_OK / NGX_CONF_ERROR. */
char *xrootd_pmark_conf_merge(ngx_conf_t *cf, xrootd_pmark_conf_t *prev,
    xrootd_pmark_conf_t *conf);

/* Custom directive setters (registered in each module's command table; they cast
 * `conf` to ngx_http_xrootd_shared_conf_t* — valid because `common` is the first
 * member of every protocol conf struct — and write into ->pmark). */
char *xrootd_pmark_set_firefly_dest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *xrootd_pmark_set_map_experiment(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *xrootd_pmark_set_map_activity(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *xrootd_pmark_set_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* ====================================================================== */
/* scitag.c — flow-id encode/decode + scitag.flow parsing                 */
/* ====================================================================== */

/* Pack (experiment, activity) into a 16-bit flow-id. */
static ngx_inline ngx_uint_t
xrootd_pmark_flowid(ngx_uint_t exp, ngx_uint_t act)
{
    return ((exp & 0x3FF) << XROOTD_PMARK_ACT_BITS) | (act & XROOTD_PMARK_ACT_MASK);
}

/* Split a 16-bit flow-id into (experiment, activity).  Returns NGX_ERROR (and
 * leaves the exp/act outputs untouched) for an out-of-range value — caller must treat that
 * as "no tag", never as exp=act=0 being valid. */
static ngx_inline ngx_int_t
xrootd_pmark_flow_split(ngx_uint_t flow, ngx_uint_t *exp, ngx_uint_t *act)
{
    if (flow < XROOTD_PMARK_FLOW_MIN || flow > XROOTD_PMARK_FLOW_MAX) {
        return NGX_ERROR;
    }
    *exp = flow >> XROOTD_PMARK_ACT_BITS;
    *act = flow & XROOTD_PMARK_ACT_MASK;
    return NGX_OK;
}

/* Encode a SciTags flow-id into a 20-bit IPv6 flow label value (host order). */
static ngx_inline uint32_t
xrootd_pmark_flowlabel_encode(ngx_uint_t exp, ngx_uint_t act)
{
    uint32_t flowid = (uint32_t) xrootd_pmark_flowid(exp, act);
    return ((XROOTD_PMARK_FL_VERSION << 16) | flowid) & XROOTD_PMARK_FL_MASK;
}

/* Parse a `scitag.flow=<N>` token out of an opaque/CGI query string (root://
 * open opaque or an HTTP SciTag: header rendered as "scitag.flow=N").  On a
 * valid in-range value sets the exp/act outputs and returns NGX_OK; returns NGX_DECLINED
 * if absent and NGX_ERROR if present but out of range/malformed.  The caller
 * uses NGX_OK as a top-priority override (see mapping.c). */
ngx_int_t xrootd_pmark_parse_scitag(const char *cgi, ngx_uint_t *exp,
    ngx_uint_t *act);

/* Validate an (exp, act) pair against the SciTags ranges. */
static ngx_inline ngx_int_t
xrootd_pmark_codes_valid(ngx_uint_t exp, ngx_uint_t act)
{
    return (exp >= XROOTD_PMARK_EXP_MIN && exp <= XROOTD_PMARK_EXP_MAX
            && act >= XROOTD_PMARK_ACT_MIN && act <= XROOTD_PMARK_ACT_MAX)
           ? NGX_OK : NGX_ERROR;
}

/* ====================================================================== */
/* defsfile.c — scitags experiment/activity registry (JSON via jansson)   */
/* ====================================================================== */

/* Parsed registry: experiment name → id, and (experiment, activity name) → id. */
typedef struct {
    ngx_str_t   name;
    ngx_uint_t  id;
} xrootd_pmark_named_t;

typedef struct {
    ngx_str_t    exp_name;
    ngx_uint_t   exp_id;
    ngx_array_t *activities;   /* of xrootd_pmark_named_t */
} xrootd_pmark_exp_def_t;

/* Load `path` (scitags JSON) into `*out` (ngx_array_t of xrootd_pmark_exp_def_t,
 * allocated from `pool`).  Returns NGX_OK, NGX_DECLINED (file absent), or
 * NGX_ERROR (parse error).  Used during first-flow resolution. */
ngx_int_t xrootd_pmark_defsfile_load(const char *path, ngx_pool_t *pool,
    ngx_array_t **out, ngx_log_t *log);

/* Look up an experiment id by name in a loaded registry; 0 if not found. */
ngx_uint_t xrootd_pmark_defs_exp_id(ngx_array_t *defs, ngx_str_t *name);
/* Look up an activity id by (experiment id, activity name); 0 if not found. */
ngx_uint_t xrootd_pmark_defs_act_id(ngx_array_t *defs, ngx_uint_t exp_id,
    ngx_str_t *name);

/* ====================================================================== */
/* mapping.c — resolve (experiment, activity) for a transfer              */
/* ====================================================================== */

/* Ensure pm's runtime data (defsfile, resolved rules, resolved firefly dests)
 * is loaded; idempotent, runs once per worker.  Returns NGX_OK if marking is
 * live, NGX_DECLINED if disabled/unresolved (fail-open).  `pool` must be the
 * cycle pool (process-lifetime). */
ngx_int_t xrootd_pmark_runtime_ensure(xrootd_pmark_conf_t *pm, ngx_pool_t *pool,
    ngx_log_t *log);

/* Resolve (experiment, activity) for a flow using, in priority order:
 * client scitag (when scitag_cgi on) → path glob → VO → default; then activity
 * user → role → per-experiment default.  `vo_csv`/`user`/`path`/`cgi` are
 * borrowed C strings (any may be NULL/empty).  Returns NGX_OK + sets exp/act, or
 * NGX_DECLINED when nothing maps (→ flow is not marked).  Never fails a transfer. */
ngx_int_t xrootd_pmark_map_codes(xrootd_pmark_conf_t *pm,
    const char *vo_csv, const char *user, const char *path, const char *cgi,
    ngx_uint_t *exp, ngx_uint_t *act);

/* ====================================================================== */
/* sockstats.c — TCP_INFO + time/addr formatting helpers                  */
/* ====================================================================== */

typedef struct {
    uint64_t  bytes_recv;     /* tcpi_bytes_received (0 if unavailable) */
    uint64_t  bytes_sent;     /* tcpi_bytes_acked                      */
    uint32_t  rtt_us;         /* tcpi_rtt (microseconds)               */
} xrootd_pmark_sockstats_t;

/* Read TCP_INFO byte/rtt counters for `fd` (Linux); zeroes the struct and
 * returns NGX_DECLINED where unavailable.  Never fails the caller. */
ngx_int_t xrootd_pmark_sockstats(int fd, xrootd_pmark_sockstats_t *st);

/* Format "now" as a firefly timestamp: yyyy-mm-ddThh:mm:ss.uuuuuu+00:00. */
void xrootd_pmark_iso8601_now(char *buf, size_t buflen);

/* Format the IP + port of a connected socket end.  `which` = 0 for the peer
 * (getpeername), 1 for the local end (getsockname).  Fills ip[]/port and sets
 * *afi to '4' or '6'.  Returns NGX_OK / NGX_DECLINED. */
ngx_int_t xrootd_pmark_endpoint(int fd, int which, char *ip, size_t iplen,
    int *port, char *afi);

/* ====================================================================== */
/* firefly.c — per-flow firefly UDP lifecycle                            */
/* ====================================================================== */

/* Begin marking a flow on connection `c`.  Resolves codes via mapping (using the
 * borrowed identity strings + path + cgi), allocates a flow handle on `pool`,
 * captures the socket endpoints, and emits the "start" firefly.  `is_write`
 * selects the supplier-is-source convention.  Returns the handle (caller stores
 * it and passes it to flow_end), or NULL when the flow is not marked.  Always
 * fail-open. */
xrootd_pmark_flow_t *xrootd_pmark_flow_begin(xrootd_pmark_conf_t *pm,
    ngx_pool_t *pool, ngx_connection_t *c, int is_write,
    const char *vo_csv, const char *user, const char *path, const char *cgi,
    ngx_log_t *log);

/* Emit the "end" firefly (with final TCP_INFO byte/rtt counts) for `flow` and
 * release per-flow resources.  No-op when `flow` is NULL.  Must be called while
 * the socket fd is still open (read TCP_INFO before close). */
void xrootd_pmark_flow_end(xrootd_pmark_flow_t *flow, ngx_log_t *log);

/* Emit an "ongoing" firefly for a long-lived flow (echo timer). */
void xrootd_pmark_flow_echo(xrootd_pmark_flow_t *flow, ngx_log_t *log);

/* One-shot firefly (start+end) for a connected socket we don't hold a flow over
 * — used for outbound TPC sockets (libcurl) at close, when the fd is connected
 * and TCP_INFO is readable.  `peer_is_src`=1 when the remote supplies the data
 * (a pull).  No-op when firefly is off. */
void xrootd_pmark_firefly_oneshot(xrootd_pmark_conf_t *pm, int fd, ngx_uint_t exp,
    ngx_uint_t act, int peer_is_src, const char *app, ngx_log_t *log);

/* ngx_pool_cleanup_add() handler: `data` is an xrootd_pmark_flow_t* — emits the
 * end firefly at request/pool teardown.  Lets HTTP callers (per-request flows)
 * end a flow without storing it or threading a log. */
void xrootd_pmark_flow_cleanup(void *data);

/* HTTP convenience: begin a per-request flow on connection `c` and register a
 * `pool` cleanup to end it at request teardown (fd still open).  Caller decides
 * whether to mark and supplies the borrowed identity/path/cgi strings.  No-op if
 * the flow does not map.  Decouples the HTTP modules from the flow internals. */
void xrootd_pmark_http_mark(xrootd_pmark_conf_t *pm, ngx_pool_t *pool,
    ngx_connection_t *c, int is_write, const char *vo_csv, const char *user,
    const char *path, const char *cgi);

/* ====================================================================== */
/* flowlabel.c — IPv6 Flow Label stamping (REQUIRED; completes XRootD TODO)*/
/* ====================================================================== */

/* Stamp the SciTags flow label onto socket `fd` whose connected peer is `peer`
 * (an IPv6, non-mapped address).  No-op (NGX_DECLINED) on IPv4/mapped/disabled
 * or when the kernel refuses the label; NGX_OK when stamped.  Increments the
 * flowlabel_set / flowlabel_failed metrics on `c`.  Never fails a transfer. */
ngx_int_t xrootd_pmark_flowlabel_apply(ngx_connection_t *c, int fd,
    ngx_uint_t exp, ngx_uint_t act, ngx_log_t *log);

/* Variant for an UNconnected socket with an explicit destination (libcurl
 * opensocket / native-TPC connect): leases the label toward `dst` so the kernel
 * stamps it once curl/connect() reaches that address.  Same gates/semantics as
 * xrootd_pmark_flowlabel_apply. */
ngx_int_t xrootd_pmark_flowlabel_apply_addr(int fd, const struct sockaddr *dst,
    socklen_t dstlen, ngx_uint_t exp, ngx_uint_t act, ngx_log_t *log);

/* One-time per-worker capability probe: can we stamp a specific IPv6 flow label
 * on this host (kernel/CAP_NET_ADMIN/sysctls)?  Cached; logs once on failure. */
ngx_int_t xrootd_pmark_flowlabel_usable(ngx_log_t *log);

#endif /* NGX_XROOTD_PMARK_H */

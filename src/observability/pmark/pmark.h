#ifndef NGX_BRIX_PMARK_H
#define NGX_BRIX_PMARK_H

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
#define BRIX_PMARK_FLOW_MIN    65       /* smallest valid scitag.flow value   */
#define BRIX_PMARK_FLOW_MAX    65535    /* 16-bit flow-id space               */
#define BRIX_PMARK_ACT_BITS    6        /* low 6 bits = activity              */
#define BRIX_PMARK_ACT_MASK    0x3F     /* activity mask                      */
#define BRIX_PMARK_EXP_MIN     1
#define BRIX_PMARK_EXP_MAX     1023     /* 10-bit experiment space            */
#define BRIX_PMARK_ACT_MIN     1
#define BRIX_PMARK_ACT_MAX     63

#define BRIX_PMARK_FF_PORT     10514    /* default firefly collector UDP port */

/* IPv6 Flow Label encoding (flowlabel.c).  glibc does not export
 * IPV6_FLOWLABEL_MASK, so define the 20-bit mask ourselves.
 *
 * Layout is the WLCG SciTags spec, draft-cc-v6ops-wlcg-flow-label-marking,
 * which numbers the 20 bits 1..20 with bit 1 the MOST significant:
 *
 *   pos: 01 02|03 04 05 06 07 08 09 10 11|12|13 14 15 16 17 18|19 20
 *        E  E | C  C  C  C  C  C  C  C  C| E| A  A  A  A  A  A | E  E
 *
 *   A (activity, 6 bits)  = positions 13..18  -> host-order bits 2..7
 *   C (community, 9 bits) = positions 3..11   -> host-order bits 9..17,
 *                           **encoded in reversed bit order** per the spec
 *   E (entropy, 5 bits)   = positions 1,2,12,19,20 -> host-order bits 0,1,8,18,19
 *                           set at random ONCE per flow (ECMP spread; ignored on
 *                           decode).  See brix_pmark_flowlabel_encode().
 *
 * Worked check (CMS): scitag.flow=206 -> exp=3, act=14 ->
 *   (reverse9(3)=384)<<9 | 14<<2 = 0x30000 | 0x38 = 196664, i.e. the value CMS
 *   reads off the wire (cms-sw/cmssw c2797da). */
#define BRIX_PMARK_FL_MASK          0x000FFFFFu   /* 20-bit field             */
#define BRIX_PMARK_FL_ENTROPY_MASK  0x000C0103u   /* E bits 0,1,8,18,19       */

/* `brix_pmark_domain` enum (which address class is marked). */
enum {
    BRIX_PMARK_DOMAIN_ANY    = 0,
    BRIX_PMARK_DOMAIN_LOCAL  = 1,
    BRIX_PMARK_DOMAIN_REMOTE = 2          /* default, matches XRootD */
};

/* Activity selection: which network role the local end plays for this flow.
 * Drives the "supplier is source" firefly src/dst convention + appname. */
enum {
    BRIX_PMARK_ACT_READ  = 0,   /* client reads (server is source): http-get  */
    BRIX_PMARK_ACT_WRITE = 1,   /* client writes (client is source): http-put */
    BRIX_PMARK_ACT_TPC   = 2    /* third-party copy outbound                  */
};

/* ---- Config (lives inside ngx_http_brix_shared_conf_t .common) ---- */

/* One `brix_pmark_map_experiment {default|path <p>|vo <v>} <expName>`. */
typedef enum {
    BRIX_PMARK_EXP_DEFAULT = 0,
    BRIX_PMARK_EXP_PATH,
    BRIX_PMARK_EXP_VO
} brix_pmark_exp_kind_t;

typedef struct {
    brix_pmark_exp_kind_t  kind;
    ngx_str_t                match;     /* path glob or VO name (empty if default) */
    ngx_str_t                exp_name;  /* experiment name (resolved via defsfile) */
} brix_pmark_exp_rule_t;

/* One `brix_pmark_map_activity <expName> {default|role <r>|user <u>} <actName>`. */
typedef enum {
    BRIX_PMARK_ACTR_DEFAULT = 0,
    BRIX_PMARK_ACTR_ROLE,
    BRIX_PMARK_ACTR_USER
} brix_pmark_act_kind_t;

typedef struct {
    ngx_str_t                exp_name;  /* experiment this rule belongs to */
    brix_pmark_act_kind_t  kind;
    ngx_str_t                match;     /* role or user (empty if default) */
    ngx_str_t                act_name;  /* activity name (resolved via defsfile) */
} brix_pmark_act_rule_t;

typedef struct {
    ngx_flag_t    enable;          /* brix_pmark on|off (master switch)        */
    ngx_flag_t    firefly;         /* brix_pmark_firefly                       */
    ngx_flag_t    flowlabel;       /* brix_pmark_flowlabel (default on)        */
    ngx_flag_t    scitag_cgi;      /* honor client scitag.flow / SciTag: header  */
    ngx_flag_t    firefly_origin;  /* also report to the client origin           */
    ngx_flag_t    http_plain;      /* mark plain WebDAV/S3 GET/PUT (default off) */
    ngx_msec_t    echo;            /* brix_pmark_echo seconds (0 = off)        */
    ngx_uint_t    domain;          /* BRIX_PMARK_DOMAIN_*                       */
    ngx_str_t     appname;         /* firefly context.application                 */
    ngx_str_t     defsfile;        /* scitags experiment/activity JSON registry  */
    ngx_array_t  *firefly_dest;    /* of ngx_str_t "host[:port]"                  */
    ngx_array_t  *exp_rules;       /* of brix_pmark_exp_rule_t                  */
    ngx_array_t  *act_rules;       /* of brix_pmark_act_rule_t                  */

    /* ---- Resolved at first use (runtime only; never merged) ----
     * The defsfile is parsed, mapping names are resolved to numeric ids, and
     * firefly_dest strings are resolved to sockaddrs ONCE per worker on the
     * first marked flow (guarded by rt_ready), then cached here.  Allocated from
     * the cycle pool so they live for the worker's lifetime. */
    unsigned      rt_ready:1;      /* resolution attempted (success or fail)     */
    unsigned      rt_ok:1;         /* resolution succeeded → marking is live      */
    ngx_array_t  *dest_sa;         /* of brix_pmark_dest_t (resolved collectors)*/
    ngx_array_t  *exp_rules_r;     /* of brix_pmark_exp_rule_r_t                */
    ngx_array_t  *act_rules_r;     /* of brix_pmark_act_rule_r_t                */
} brix_pmark_conf_t;

/* A resolved firefly collector address. */
typedef struct {
    struct sockaddr_storage  ss;
    socklen_t                len;
    int                      family;   /* AF_INET / AF_INET6 */
} brix_pmark_dest_t;

/* Resolved experiment rule (defsfile name → numeric id). */
typedef struct {
    brix_pmark_exp_kind_t  kind;
    ngx_str_t                match;
    ngx_uint_t               exp_id;
} brix_pmark_exp_rule_r_t;

/* Resolved activity rule (defsfile name → numeric id, scoped to an experiment). */
typedef struct {
    ngx_uint_t               exp_id;   /* experiment this rule applies to (0=any) */
    brix_pmark_act_kind_t  kind;
    ngx_str_t                match;
    ngx_uint_t               act_id;
} brix_pmark_act_rule_r_t;

/* ---- Per-flow handle (one per marked transfer) ---- */
typedef struct brix_pmark_flow_s {
    brix_pmark_conf_t *pm;       /* owning config (for collectors at end)   */
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
} brix_pmark_flow_t;

/* ====================================================================== */
/* config.c — directive parsing + per-server config lifecycle             */
/* ====================================================================== */

/* Initialise a pmark config block to NGX_CONF_UNSET sentinels.  Called from
 * ngx_http_brix_shared_init() so every protocol inherits it. */
void  brix_pmark_conf_init(brix_pmark_conf_t *c);

/* Merge parent→child pmark config (defaults: disabled; flowlabel/scitag on;
 * firefly on; domain remote; firefly port 10514).  Called from
 * ngx_http_brix_shared_merge().  Returns NGX_CONF_OK / NGX_CONF_ERROR. */
char *brix_pmark_conf_merge(ngx_conf_t *cf, brix_pmark_conf_t *prev,
    brix_pmark_conf_t *conf);

/* Custom directive setters (registered in each module's command table; they cast
 * `conf` to ngx_http_brix_shared_conf_t* — valid because `common` is the first
 * member of every protocol conf struct — and write into ->pmark). */
char *brix_pmark_set_firefly_dest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_pmark_set_map_experiment(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_pmark_set_map_activity(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_pmark_set_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* ====================================================================== */
/* scitag.c — flow-id encode/decode + scitag.flow parsing                 */
/* ====================================================================== */

/* Pack (experiment, activity) into a 16-bit flow-id. */
static ngx_inline ngx_uint_t
brix_pmark_flowid(ngx_uint_t exp, ngx_uint_t act)
{
    return ((exp & 0x3FF) << BRIX_PMARK_ACT_BITS) | (act & BRIX_PMARK_ACT_MASK);
}

/* Split a 16-bit flow-id into (experiment, activity).  Returns NGX_ERROR (and
 * leaves the exp/act outputs untouched) for an out-of-range value — caller must treat that
 * as "no tag", never as exp=act=0 being valid. */
static ngx_inline ngx_int_t
brix_pmark_flow_split(ngx_uint_t flow, ngx_uint_t *exp, ngx_uint_t *act)
{
    if (flow < BRIX_PMARK_FLOW_MIN || flow > BRIX_PMARK_FLOW_MAX) {
        return NGX_ERROR;
    }
    *exp = flow >> BRIX_PMARK_ACT_BITS;
    *act = flow & BRIX_PMARK_ACT_MASK;
    return NGX_OK;
}

/* Reverse the low 9 bits of `v` (the SciTags community field is "used in reversed
 * order" — draft-cc-v6ops-wlcg-flow-label-marking §4). */
static ngx_inline uint32_t
brix_pmark_reverse9(ngx_uint_t v)
{
    uint32_t  r = 0;
    int       i;

    v &= 0x1FF;
    for (i = 0; i < 9; i++) {
        r = (r << 1) | (uint32_t) (v & 1u);
        v >>= 1;
    }
    return r;
}

/* Encode a SciTags (experiment, activity) pair into the 20-bit IPv6 Flow Label
 * value (host order) per draft-cc-v6ops-wlcg-flow-label-marking.  This is the
 * STRUCTURAL value only (entropy bits zero) so it is deterministic and decodable;
 * the caller ORs in random entropy (BRIX_PMARK_FL_ENTROPY_MASK) once per flow.
 * `act` is the 6-bit activity (bits 2..7); `exp` is the 9-bit community placed in
 * reversed order at bits 9..17. */
static ngx_inline uint32_t
brix_pmark_flowlabel_encode(ngx_uint_t exp, ngx_uint_t act)
{
    uint32_t  community = brix_pmark_reverse9(exp);
    uint32_t  activity  = (uint32_t) (act & BRIX_PMARK_ACT_MASK);

    return ((community << 9) | (activity << 2)) & BRIX_PMARK_FL_MASK;
}

/* Parse a `scitag.flow=<N>` token out of an opaque/CGI query string (root://
 * open opaque or an HTTP SciTag: header rendered as "scitag.flow=N").  On a
 * valid in-range value sets the exp/act outputs and returns NGX_OK; returns NGX_DECLINED
 * if absent and NGX_ERROR if present but out of range/malformed.  The caller
 * uses NGX_OK as a top-priority override (see mapping.c). */
ngx_int_t brix_pmark_parse_scitag(const char *cgi, ngx_uint_t *exp,
    ngx_uint_t *act);

/* Validate an (exp, act) pair against the SciTags ranges. */
static ngx_inline ngx_int_t
brix_pmark_codes_valid(ngx_uint_t exp, ngx_uint_t act)
{
    return (exp >= BRIX_PMARK_EXP_MIN && exp <= BRIX_PMARK_EXP_MAX
            && act >= BRIX_PMARK_ACT_MIN && act <= BRIX_PMARK_ACT_MAX)
           ? NGX_OK : NGX_ERROR;
}

/* ====================================================================== */
/* defsfile.c — scitags experiment/activity registry (JSON via jansson)   */
/* ====================================================================== */

/* Parsed registry: experiment name → id, and (experiment, activity name) → id. */
typedef struct {
    ngx_str_t   name;
    ngx_uint_t  id;
} brix_pmark_named_t;

typedef struct {
    ngx_str_t    exp_name;
    ngx_uint_t   exp_id;
    ngx_array_t *activities;   /* of brix_pmark_named_t */
} brix_pmark_exp_def_t;

/* Load `path` (scitags JSON) into `*out` (ngx_array_t of brix_pmark_exp_def_t,
 * allocated from `pool`).  Returns NGX_OK, NGX_DECLINED (file absent), or
 * NGX_ERROR (parse error).  Used during first-flow resolution. */
ngx_int_t brix_pmark_defsfile_load(const char *path, ngx_pool_t *pool,
    ngx_array_t **out, ngx_log_t *log);

/* Look up an experiment id by name in a loaded registry; 0 if not found. */
ngx_uint_t brix_pmark_defs_exp_id(ngx_array_t *defs, ngx_str_t *name);
/* Look up an activity id by (experiment id, activity name); 0 if not found. */
ngx_uint_t brix_pmark_defs_act_id(ngx_array_t *defs, ngx_uint_t exp_id,
    ngx_str_t *name);

/* ====================================================================== */
/* mapping.c — resolve (experiment, activity) for a transfer              */
/* ====================================================================== */

/* Ensure pm's runtime data (defsfile, resolved rules, resolved firefly dests)
 * is loaded; idempotent, runs once per worker.  Returns NGX_OK if marking is
 * live, NGX_DECLINED if disabled/unresolved (fail-open).  `pool` must be the
 * cycle pool (process-lifetime). */
ngx_int_t brix_pmark_runtime_ensure(brix_pmark_conf_t *pm, ngx_pool_t *pool,
    ngx_log_t *log);

/* Flow-identity inputs for brix_pmark_map_codes().  All fields are borrowed
 * C strings (any may be NULL/empty). */
typedef struct {
    const char  *vo_csv;    /* VO/role CSV from the client identity */
    const char  *user;      /* mapped user / DN */
    const char  *path;      /* transfer path (glob-matched)         */
    const char  *cgi;       /* opaque CGI (scitag.flow override)    */
} brix_pmark_flow_id_t;

/* Resolve (experiment, activity) for a flow using, in priority order:
 * client scitag (when scitag_cgi on) → path glob → VO → default; then activity
 * user → role → per-experiment default.  Returns NGX_OK + sets exp/act, or
 * NGX_DECLINED when nothing maps (→ flow is not marked).  Never fails a transfer. */
ngx_int_t brix_pmark_map_codes(brix_pmark_conf_t *pm,
    const brix_pmark_flow_id_t *flow, ngx_uint_t *exp, ngx_uint_t *act);

/* ====================================================================== */
/* sockstats.c — TCP_INFO + time/addr formatting helpers                  */
/* ====================================================================== */

typedef struct {
    uint64_t  bytes_recv;     /* tcpi_bytes_received (0 if unavailable) */
    uint64_t  bytes_sent;     /* tcpi_bytes_acked                      */
    uint32_t  rtt_us;         /* tcpi_rtt (microseconds)               */
} brix_pmark_sockstats_t;

/* Read TCP_INFO byte/rtt counters for `fd` (Linux); zeroes the struct and
 * returns NGX_DECLINED where unavailable.  Never fails the caller. */
ngx_int_t brix_pmark_sockstats(int fd, brix_pmark_sockstats_t *st);

/* Format "now" as a firefly timestamp: yyyy-mm-ddThh:mm:ss.uuuuuu+00:00. */
void brix_pmark_iso8601_now(char *buf, size_t buflen);

/* Format the IP + port of a connected socket end.  `which` = 0 for the peer
 * (getpeername), 1 for the local end (getsockname).  Fills ip[]/port and sets
 * *afi to '4' or '6'.  Returns NGX_OK / NGX_DECLINED. */
ngx_int_t brix_pmark_endpoint(int fd, int which, char *ip, size_t iplen,
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
brix_pmark_flow_t *brix_pmark_flow_begin(brix_pmark_conf_t *pm,
    ngx_pool_t *pool, ngx_connection_t *c, int is_write,
    const char *vo_csv, const char *user, const char *path, const char *cgi,
    ngx_log_t *log);

/* Emit the "end" firefly (with final TCP_INFO byte/rtt counts) for `flow` and
 * release per-flow resources.  No-op when `flow` is NULL.  Must be called while
 * the socket fd is still open (read TCP_INFO before close). */
void brix_pmark_flow_end(brix_pmark_flow_t *flow, ngx_log_t *log);

/* Emit an "ongoing" firefly for a long-lived flow (echo timer). */
void brix_pmark_flow_echo(brix_pmark_flow_t *flow, ngx_log_t *log);

/* One-shot firefly (start+end) for a connected socket we don't hold a flow over
 * — used for outbound TPC sockets (libcurl) at close, when the fd is connected
 * and TCP_INFO is readable.  `peer_is_src`=1 when the remote supplies the data
 * (a pull).  No-op when firefly is off. */
void brix_pmark_firefly_oneshot(brix_pmark_conf_t *pm, int fd, ngx_uint_t exp,
    ngx_uint_t act, int peer_is_src, const char *app, ngx_log_t *log);

/* ngx_pool_cleanup_add() handler: `data` is an brix_pmark_flow_t* — emits the
 * end firefly at request/pool teardown.  Lets HTTP callers (per-request flows)
 * end a flow without storing it or threading a log. */
void brix_pmark_flow_cleanup(void *data);

/* HTTP convenience: begin a per-request flow on connection `c` and register a
 * `pool` cleanup to end it at request teardown (fd still open).  Caller decides
 * whether to mark and supplies the borrowed identity/path/cgi strings.  No-op if
 * the flow does not map.  Decouples the HTTP modules from the flow internals. */
void brix_pmark_http_mark(brix_pmark_conf_t *pm, ngx_pool_t *pool,
    ngx_connection_t *c, int is_write, const char *vo_csv, const char *user,
    const char *path, const char *cgi);

/* ====================================================================== */
/* flowlabel.c — IPv6 Flow Label stamping (REQUIRED; completes XRootD TODO)*/
/* ====================================================================== */

/* Stamp the SciTags flow label onto socket `fd` whose connected peer is `peer`
 * (an IPv6, non-mapped address).  No-op (NGX_DECLINED) on IPv4/mapped/disabled
 * or when the kernel refuses the label; NGX_OK when stamped.  Increments the
 * flowlabel_set / flowlabel_failed metrics on `c`.  Never fails a transfer. */
ngx_int_t brix_pmark_flowlabel_apply(ngx_connection_t *c, int fd,
    ngx_uint_t exp, ngx_uint_t act, ngx_log_t *log);

/* Variant for an UNconnected socket with an explicit destination (libcurl
 * opensocket / native-TPC connect): leases the label toward `dst` so the kernel
 * stamps it once curl/connect() reaches that address.  Same gates/semantics as
 * brix_pmark_flowlabel_apply. */
ngx_int_t brix_pmark_flowlabel_apply_addr(int fd, const struct sockaddr *dst,
    socklen_t dstlen, ngx_uint_t exp, ngx_uint_t act, ngx_log_t *log);

/* One-time per-worker capability probe: can we stamp a specific IPv6 flow label
 * on this host (kernel/CAP_NET_ADMIN/sysctls)?  Cached; logs once on failure. */
ngx_int_t brix_pmark_flowlabel_usable(ngx_log_t *log);

#endif /* NGX_BRIX_PMARK_H */

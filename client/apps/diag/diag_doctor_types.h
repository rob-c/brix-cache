/*
 * diag_doctor_types.h — the doctor subsystem's endpoint model.
 *
 * WHAT: doctor_ep and every sub-record it aggregates — the advertised-config
 *       scrape (doctor_cfg), the mesh round-trip probe (doctor_lat), the deep
 *       read-only reconnaissance (doctor_recon), the CMS locate-plane
 *       classification (doctor_cmsloc) and the EOS /proc dialect
 *       (doctor_eos / doctor_eos_rep).
 * WHY:  split out of diag_internal.h (600-line cap, coding-standards §1) as one
 *       coherent group: these types are written by the doctor probes and read by
 *       the doctor renderers, and by nothing else in the tool.
 * HOW:  types only — no prototypes, no storage. Included from diag_internal.h
 *       after dx_finding/DOC_* so it is never included directly.
 */
#ifndef BRIX_DIAG_DOCTOR_TYPES_H
#define BRIX_DIAG_DOCTOR_TYPES_H

/*
 * WHAT: the advertised-configuration + capacity face of one endpoint, scraped
 *       over the wire by doctor_scrape_config (kXR_Qconfig + kXR_Qspace).
 * WHY:  the config/perf advisor (phase-93) classifies *values*, not error codes;
 *       this block holds the scraped scalars the computed rules run over.
 * HOW:  pointer-free and PII-free by construction — only advertised scalars, no
 *       path ever. Absent/unsupported keys keep their sentinel (strings "",
 *       ints -1 for numeric caps; booleans 0). space_* are -1 until Qspace runs.
 */
typedef struct {
    int      scraped;                   /* 1 = the Qconfig/Qspace scrape ran     */
    char     version[48];               /* kXR_Qconfig "version" ("" = absent)   */
    char     role[24];                  /* "manager"/"server"/... ("" = absent)  */
    char     sitename[64];              /* "" if unset/unsupported               */
    int      tpc, tpcdlg;               /* 0/1 advertised                        */
    int      have_adler32, have_crc32c; /* parsed from the "chksum" CSV          */
    int      bind_max, pio_max;         /* parallelism caps (-1 = absent)        */
    int      readv_iov_max, readv_ior_max; /* readv caps (-1 = absent)           */
    int      pgread;                    /* per-page CRC read supported (0/1)     */
    int64_t  space_total, space_free;   /* kXR_Qspace bytes (-1 = not pulled)    */
} doctor_cfg;

/*
 * WHAT: round-trip latency of one mesh node, sampled over the two XRootD control
 *       planes: the data-server plane (a kXR_stat "/" round-trip) and the CMS
 *       redirect plane (a kXR_locate "/" round-trip, the CMSD-served query).
 * WHY:  --latency answers "how far is each server, and is the redirect plane as
 *       responsive as the data plane?" Every sample is a full request→reply, so
 *       the figure is bi-directional (out and back) by construction.
 * HOW:  filled by doctor_latency_probe; probed=0 until it runs. Times are ms;
 *       *_ok is the successful-sample count per plane (0 = plane unreachable).
 */
typedef struct {
    int      probed;                    /* 1 = doctor_latency_probe ran          */
    int      samples;                   /* samples attempted per plane           */
    int      xr_ok, cms_ok;             /* successful samples, data / cms plane   */
    double   xr_min, xr_avg, xr_max;    /* data-plane stat RTT, ms               */
    double   cms_min, cms_avg, cms_max; /* cms-plane locate RTT, ms              */
} doctor_lat;

#define RECON_MAX_ROOTS 12

/*
 * WHAT: the deep read-only reconnaissance face of one endpoint (--deep-recon):
 *       operational counters parsed from `query stats a`, a full Qconfig key
 *       sweep (how many advertised keys the server actually answers), the
 *       decoded kXR_protocol capability bits, and a bounded list of top-level
 *       namespace roots our identity is allowed to see.
 * WHY:  --config-audit classifies a handful of values into advice; deep-recon
 *       instead surfaces the whole read-only picture an operator might want to
 *       eyeball on one server — traffic, logins, TPC accounting, capability
 *       flags, authorized roots — in a single pass. Diagnostic, not advisory.
 * HOW:  filled by doctor_recon_probe over the already-open connection. PII-free:
 *       only server-advertised scalars and the top-level path *names* the server
 *       itself returns from a dirlist of "/"; never a token or a user path. Every
 *       numeric field is int64 with -1 = "the server did not report it". No goto.
 */
typedef struct {
    int      probed;                 /* 1 = doctor_recon_probe ran            */
    /* --- link plane (stats id="link") --- */
    int64_t  conns_total;            /* <tot> cumulative connections          */
    int64_t  bytes_in, bytes_out;    /* <in>/<out> bytes over all links       */
    /* --- xrootd op plane (stats id="xrootd") --- */
    int64_t  ops_open, ops_rd, ops_wr;   /* <ops><open>/<rd>/<wr>             */
    int64_t  ops_err, ops_rdr, ops_dly;  /* <err>/<rdr>/<dly>                 */
    int64_t  lgn_num, lgn_au, lgn_af;    /* <lgn> total / authed / auth-failed */
    /* --- ofs TPC accounting (stats id="ofs" -> <tpc>) --- */
    int      have_tpc;                   /* 1 = a <tpc> block was present       */
    int64_t  tpc_grant, tpc_deny, tpc_err;
    /* --- oss capacity (stats id="oss", first path; best-effort) --- */
    int64_t  oss_total, oss_free;        /* bytes                               */
    int64_t  ino_total, ino_free;        /* inodes                              */
    /* --- http plane (stats id="http"; best-effort) --- */
    int      have_http;
    int64_t  http_reqs, http_in, http_out, http_tpc_pull, http_tpc_push;
    /* --- Qconfig key sweep --- */
    int      cfg_probed, cfg_supported;  /* keys tried / keys the server answers */
    char     cid[64], cms[96];           /* cluster id / cms manager (if advertised) */
    /* --- capability bits, decoded from server_flags --- */
    unsigned caps;
    /* --- bounded authorized-root discovery (top-level names only) --- */
    int      roots_listed;               /* 1 = a dirlist of "/" succeeded       */
    int      nroots;                     /* entries captured (<= RECON_MAX_ROOTS) */
    int      roots_more;                 /* 1 = "/" held more than we captured   */
    char     roots[RECON_MAX_ROOTS][64];
} doctor_recon;

/*
 * CMS-plane classification of a node, read straight from the manager's
 * kXR_locate answer (each token is "<type><access>host:port"). This is the
 * authority for what a node IS even when we cannot open an inbound connection
 * to it — so a firewalled/IPv6-only holder is still typed, not a blank DOWN.
 *   type : 'S'/'s' data server · 'M'/'m' subordinate manager (redirector)
 *          lowercase = pending (queued/staging, not yet serving)
 *   acc  : 'r' read-only · 'w' read/write
 */
typedef enum {
    DOC_CMS_NONE = 0,   /* not learned from a locate (e.g. a directly-probed root) */
    DOC_CMS_SERVER,     /* 'S'/'s' — data server (a file holder)                   */
    DOC_CMS_MANAGER     /* 'M'/'m' — subordinate manager / redirector              */
} doctor_cms_role;

typedef struct {
    doctor_cms_role role;    /* server vs redirector, from the locate type byte */
    int             pending; /* lowercase type => queued/staging, not yet online */
    int             write;   /* 'w' access => read/write; else read-only          */
    int             reported;/* 1 => this classification came from a CMS locate    */
} doctor_cmsloc;

/*
 * EOS dialect classification (diag_doctor_eos.c). A stock kXR_locate against an
 * EOS MGM only ever returns the MGM itself, so the CMS plane cannot see the FST
 * farm behind it. EOS instead overloads the XRootD protocol with a /proc command
 * channel (open+read "/proc/{user,admin}/?mgm.cmd=..."): `mgm.cmd=version` types
 * the MGM, and `mgm.cmd=fs&mgm.subcmd=ls&mgm.outformat=m` (admin) enumerates the
 * FST inventory. `kind` records what was learned about THIS endpoint.
 */
typedef enum {
    DOC_EOS_NONE = 0,   /* not an EOS node (no version banner / not from fs ls)     */
    DOC_EOS_MGM,        /* endpoint is an EOS MGM (version banner seen)             */
    DOC_EOS_FST         /* endpoint is an FST enumerated from the MGM `fs ls`       */
} doctor_eos_kind;

typedef struct {
    doctor_eos_kind kind;
    /* --- MGM (kind == DOC_EOS_MGM) --- */
    char    instance[64];   /* EOS_INSTANCE                                         */
    char    version[32];    /* EOS_SERVER_VERSION                                   */
    int     gated;          /* FST enumeration attempted but admin-gated (NotAuthorized) */
    int     sampled;        /* FSTs came from unprivileged fileinfo replica sampling */
    int     fst_count;      /* FSTs enumerated (0 when gated with no sampling)      */
    /* --- FST (kind == DOC_EOS_FST) --- */
    char    geotag[40];     /* stat.geotag                                         */
    char    cfgstatus[16];  /* configstatus: rw|ro|drain|off|empty...              */
    int     booted;         /* stat.boot == "booted"                               */
    int     active;         /* stat.active == "online"                             */
    int64_t cap_bytes;      /* stat.statfs.capacity                                */
    int64_t free_bytes;     /* stat.statfs.freebytes                               */
} doctor_eos;

/*
 * One replica record parsed from an EOS `fileinfo` reply — the unprivileged
 * (user-plane) FST-discovery path. When admin `fs ls` is gated for our identity,
 * `fileinfo` on real files still names the FSTs holding their replicas; walking a
 * sample of files and unioning these records surfaces the storage farm without
 * admin rights (partial coverage: only FSTs that hold a sampled file appear).
 */
typedef struct {
    char host[256];         /* replica FST host (bare hostname column)             */
    int  port;              /* FST port (default 1095 — fileinfo omits it)         */
    char geotag[40];        /* geotag column                                       */
    char cfgstatus[16];     /* configstatus column: rw|ro|drain|off...             */
    int  booted;            /* boot column == "booted"                             */
    int  active;            /* active column == "online"                           */
} doctor_eos_rep;

typedef struct {
    dx_proto      proto;             /* which protocol battery produced this endpoint */
    char          host[256];
    int           port;
    int           connected;
    int           status;            /* DOC_GREEN/YELLOW/RED */
    brix_netfacts nf;                /* phases / family / TCP_INFO / flowlabel */
    int           tls_active;
    char          tls_ver[24], tls_cipher[48];
    char          auth[24];          /* chosen auth proto, or "anon" */
    int           gototls;           /* server advertised kXR_gotoTLS */
    unsigned      caps;              /* server_flags */
    int           have_xfer;
    int64_t       xfer_bytes;
    double        ttfb_ms, mbps;
    int           holders;           /* locate token count */
    int           ghost;             /* a located holder that would not serve */
    int           metrics_http;      /* /metrics HTTP status (0 = not pulled) */
    int           shedding;          /* /metrics shows kXR_wait / budget shedding */
    int           offline_seen;      /* read probe saw a kXR_offline (tape) file */
    int           skipped;           /* IPv6-only node not probed — local IPv6 is down (not a fault) */
    doctor_cfg    cfg;               /* advertised config/capacity (phase-93 audit) */
    doctor_lat    lat;               /* --latency round-trip probe (phase-93 mesh latency) */
    doctor_recon  recon;             /* --deep-recon read-only reconnaissance (phase-93) */
    doctor_cmsloc cms;               /* CMS locate-plane role/access (mesh map) */
    doctor_eos    eos;               /* EOS dialect: MGM banner / enumerated FST */
    int64_t       mgr_stat_size;     /* manager-side stat size, for cns-stat-drift */
    long          mgr_stat_mtime;    /* manager-side stat mtime, for cns-stat-drift */
    int           mgr_stat_have;     /* 1 = mgr_stat_* valid (manager stat succeeded) */
    int           nissues;
    char          issues[DOC_MAXISS][160];
    int           ndx;               /* active-diagnosis findings */
    dx_finding    dx[DOC_MAXDX];
} doctor_ep;

#endif /* BRIX_DIAG_DOCTOR_TYPES_H */

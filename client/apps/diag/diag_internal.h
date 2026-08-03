/*
 * diag_internal.h - private split contract for xrddiag.c and its Phase-38 siblings.
 * Not a public API: include only from client/apps/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_DIAG_INTERNAL_H
#define BRIX_DIAG_INTERNAL_H

#include "brix.h"
#include "core/compat/crypto.h"   
#include "core/compat/hex.h"      
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>     
#include <stdarg.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef struct {
    brix_opts   conn;          
    const char *url;           
    const char *ref_url;       
    int         streams;       
    int         metrics_port;  
    const char *cluster_url;   
    int         authorized;    
    int         probe_timeout_ms; 
    const char *playback_url;  
    const char *davs;
    const char *davs_tls;      /* --davs-tls host:port: HTTPS WebDAV compare plane */
    int         sweep;
    int         json;          
    int         dashboard_port;
    int         allow_write;   
    int         auth_suite;    
    int         verify_tls;    
    const char *urls[8];       
    int         nurls;
    int         interval_s;    
    int         count;         
    int         watch_prom;
    const char *prom_path;
    int         config_audit;      /* --config-audit: scrape + classify remote config/perf */
    int         all_servers;       /* --all-servers: manager fan-out to every located DS    */
    int         cap_threshold_pct; /* capacity-low WARN threshold, free%% (0 = default 5)    */
    int         map;               /* --map: draw the discovered CMS mesh as a diagram       */
    const char *map_format;        /* --map-format: ascii (default) | dot | mermaid          */
    int         latency;           /* --latency: round-trip probe every mesh node (xr + cms) */
    int         latency_count;     /* --latency-count: samples per plane (0 = default 5)     */
    int         deep_recon;        /* --deep-recon: read-only deep server reconnaissance     */
    const char *tpc_target;        /* --tpc-target host[:port]: TPC egress self-test source  */
} diag_args;

extern int g_fails;

#define DOC_GREEN  0
#define DOC_YELLOW 1
#define DOC_RED    2
#define DOC_MAXISS 8
#define DX_OK   DOC_GREEN
#define DX_WARN DOC_YELLOW
#define DX_FAIL DOC_RED
#define DOC_MAXDX 20
typedef struct {
    char probe[16];     /* subsystem id: auth/namespace/read/checksum/locate/load/write/stage */
    int  verdict;       /* DX_OK / DX_WARN / DX_FAIL */
    int  kxr;           /* the kXR_* code observed (0 if none / not a server error) */
    char cause[160];    /* root-cause classification (PII-free) */
    char remedy[200];   /* operator remediation (PII-free) */
} dx_finding;

typedef enum {
    DXP_ROOT = 0,   /* root:// / roots:// (libbrix) */
    DXP_HTTP,       /* http://  (cleartext XrdHttp/WebDAV GET) */
    DXP_HTTPS,      /* https:// (TLS XrdHttp GET) */
    DXP_DAVS,       /* davs:// / dav:// (WebDAV class-2 over TLS) */
    DXP_S3,         /* s3:// / s3s:// (S3 REST, SigV4) */
    DXP_CMS         /* cms:// (cluster manager: locate + redirect trace) */
} dx_proto;

/*
 * WHAT: a parsed deep-dive URL — scheme battery + TLS flag + authority + path.
 * WHY:  dx_url_parse used to fill five separate out-parameters (8 params
 *       total); the out-struct carries the same fields as one unit and travels
 *       whole into the protocol batteries (doctor_http / doctor_s3).
 * HOW:  filled only by dx_url_parse: proto/tls/port start from the matched
 *       DX_SCHEMES row, host/port come from the authority, path defaults "/".
 */
typedef struct {
    dx_proto proto;               /* protocol battery to route to           */
    int      tls;                 /* 1 = the scheme implies TLS             */
    char     host[256];           /* host name or IPv6 literal (unbracketed)*/
    int      port;                /* explicit, or the per-scheme default    */
    char     path[XRDC_PATH_MAX]; /* absolute request path ("/" if absent)  */
} dx_url_t;

/* The doctor endpoint model (doctor_ep + its sub-records) — split out for
 * the 600-line cap; see coding-standards §1. */
#include "diag_doctor_types.h"

#define DX_ANY (-9999)
typedef struct {
    const char *probe;   /* subsystem id, or NULL = any probe */
    int         kxr;     /* kXR_* code, or DX_ANY = any code */
    int         sev;     /* DX_WARN / DX_FAIL */
    const char *cause;
    const char *remedy;
} dx_rule;

extern const dx_rule DX_RULES[];

/*
 * WHAT: one classified finding, by reference — the argument block of dx_record().
 * WHY:  dx_record used to take the five finding fields positionally (6 params,
 *       over the parameter gate); one descriptor keeps every callsite a single
 *       expression with the fields in dx_finding storage order.
 * HOW:  callsites pass a compound literal ordered exactly as dx_finding stores
 *       it: probe, verdict, kxr, cause, remedy. cause/remedy may be NULL
 *       (recorded as ""). dx_record copies everything, so temporaries are safe.
 */
typedef struct {
    const char *probe;    /* subsystem id (see dx_finding.probe)     */
    int         verdict;  /* DX_OK / DX_WARN / DX_FAIL               */
    int         kxr;      /* the kXR_* code observed (0 if none)     */
    const char *cause;    /* root-cause classification (PII-free)    */
    const char *remedy;   /* operator remediation (PII-free)         */
} dx_note;

/*
 * WHAT: credential selection for one scoped diagnostic connection.
 * WHY:  dx_connect_as took the three selection knobs positionally (7 params);
 *       grouping them names each knob at the callsite.
 * HOW:  force_anon suppresses credentials entirely; token_override (NULL =
 *       use the environment as-is) is swapped into $BEARER_TOKEN around the
 *       connect; auth_force (NULL = negotiate) pins the auth protocol.
 */
typedef struct {
    int         force_anon;      /* 1 = login with NO credential            */
    const char *token_override;  /* bearer token to present (NULL = env)    */
    const char *auth_force;      /* forced auth protocol (NULL = negotiate) */
} dx_cred_sel;

/*
 * WHAT: the resolved probe target (a readable remote file), if any.
 * WHY:  doctor_diagnose took the (target, have_target) split pair (6 params);
 *       the pair is one fact — "a target path, possibly absent".
 * HOW:  filled by doctor_one from its xfer-probe resolution; path is only
 *       meaningful when have is 1.
 */
typedef struct {
    const char *path;   /* resolved file path (valid only when have == 1) */
    int         have;   /* 1 = a readable target was resolved             */
} dx_target;

/*
 * WHAT: the request identity to sign — every SigV4 input except the payload.
 * WHY:  s3_sign took the six signing inputs positionally (8 params); the
 *       descriptor keeps the signer call within the parameter gate.
 * HOW:  host must be the exact Host header value sent (host:port) — the
 *       server canonicalises it verbatim, so a bare host would mismatch.
 */
typedef struct {
    const char *method;   /* HTTP method to sign                    */
    const char *host;     /* exact Host header value (host:port)    */
    const char *uri;      /* path-style request URI                 */
    const char *ak, *sk;  /* AWS access key id / secret             */
    const char *region;   /* signing region (e.g. "us-east-1")      */
} s3_sign_req;
typedef struct {
    int         up;                 /* 1 = connected, 0 = down/unreachable */
    double      connect_ms;         /* full connect (TCP+TLS+login+auth) */
    double      tcp_ms, tls_ms, auth_ms;  /* connect-phase split (netfacts) */
    double      read_ms;            /* tiny-read TTFB, -1 if not measured */
    double      locate_ms;          /* kXR_locate RTT, -1 if not measured */
    int         holders;            /* located replica count, -1 if unknown */
    int         tls_active;         /* 1 if the data plane negotiated TLS */
    const char *proto;              /* "root" / "roots" */
    char        endpoint[288];      /* the URL the user passed */
} watch_sample;

extern volatile sig_atomic_t g_watch_stop;


/* diag_compare.c */
void probe(const char *name, int ok, const char *fmt, ...);

/* xrddiag.c */
void note(const char *name, const char *fmt, ...);

/* diag_doctor.c */
int download_to_fd(brix_conn *c, const char *path, int fd, int64_t *out_bytes, brix_status *st);

/* diag_topology.c */
int resolve_target(brix_conn *c, const brix_url *u, char *target, size_t tsz, brix_statinfo *sti, brix_status *st);

/* diag_check.c */
int do_check(const diag_args *a);

/* diag_bench.c */
double bench_one(brix_conn *c, const char *target, brix_status *st);
void bench_sweep(brix_conn *c, const char *target);
int do_bench(const diag_args *a);

/* diag_metabench.c */
int do_metabench(const diag_args *a);

/* diag_topology.c */
int do_topology(const diag_args *a);

/* diag_watch.c */
int do_status(const diag_args *a);

/* diag_compare.c */
int remote_md5(brix_conn *c, const char *path, char *hex, size_t hexsz, brix_status *st);

/* diag_topology.c */
void parse_http_hostport(const char *s, char *host, size_t hsz, int *port);

/* diag_compare.c */
int do_compare_davs(const diag_args *a);
int do_compare(const diag_args *a);

/* diag_topology.c */
int resolve_once(const char *host, int port, char *ip, size_t ipsz, int *is_loop, brix_status *st);
int probe_open(brix_conn *c, const char *urlbuf, const diag_args *a, int tmo, brix_status *st);
int raw_send_expect_reject(brix_conn *c, const uint8_t hdr24[24], const uint8_t *body, uint32_t bodylen, int lie_dlen, uint32_t fake_dlen);

/* diag_misc.c */
int do_probe_robustness(const diag_args *a);
int do_replay(const diag_args *a);

/* diag_doctor.c */
void doc_issue(doctor_ep *e, int sev, const char *fmt, ...);
int doctor_xfer(brix_conn *c, const char *path, double *ttfb_ms, double *mbps, int64_t *bytes);
void doctor_metrics(const char *host, int port, doctor_ep *e);

/* xrddiag.c */
void dx_record(doctor_ep *e, const dx_note *n);
void dx_record_status(doctor_ep *e, const char *probe, const brix_status *st);
int dx_is_loopback(const char *host);

/* diag_check.c */
void dx_probe_auth(const brix_conn *c, doctor_ep *e);
void dx_probe_namespace(brix_conn *c, doctor_ep *e);
void dx_probe_read(brix_conn *c, const char *target, doctor_ep *e);
void dx_probe_checksum(brix_conn *c, const char *target, doctor_ep *e);
void dx_probe_write(brix_conn *c, doctor_ep *e);
void dx_probe_stage(brix_conn *c, const char *target, doctor_ep *e);

/* xrddiag.c */
int dx_b64url_enc(const unsigned char *in, size_t n, char *out, size_t outsz);
int dx_make_jwt(const char *header, const char *payload, const char *sig, char *out, size_t outsz);
int dx_connect_as(const diag_args *a, const brix_url *u, const dx_cred_sel *sel, brix_conn *c, brix_status *st);

/* diag_check.c */
int dx_authz_anon(const diag_args *a, const brix_url *u, const char *target, int have_target, char *sec_out, size_t sec_sz, doctor_ep *e);
void dx_authz_forged(const diag_args *a, const brix_url *u, const char *probe, const char *bad_token, doctor_ep *e);
void dx_authz_expired(const diag_args *a, const brix_url *u, const char *tok, doctor_ep *e);
void dx_authz_scope(const diag_args *a, const brix_url *u, const char *tok, doctor_ep *e);

/* diag_doctor.c */
void doctor_auth_suite(const diag_args *a, const brix_url *u, const char *target, int have_target, doctor_ep *e);
void doctor_diagnose(const diag_args *a, brix_conn *c, const brix_url *u, const dx_target *t, doctor_ep *e);

/* xrddiag.c */
const char * dx_proto_name(dx_proto p);
int dx_url_parse(const char *url, dx_url_t *u);
void dx_http_status(doctor_ep *e, const char *probe, int status);
void dx_http_fail(doctor_ep *e, int tls, const brix_status *st);

/* diag_doctor.c */
void doctor_http(const diag_args *a, const dx_url_t *u, doctor_ep *e);

/* xrddiag.c */
int s3_sign(const s3_sign_req *q, char *hdrs, size_t hdrsz);

/* diag_doctor.c */
void doctor_s3(const diag_args *a, const dx_url_t *u, doctor_ep *e);
void doctor_cms(const diag_args *a, const char *host, int port, const char *path, doctor_ep *e);
void doctor_one(const diag_args *a, const char *url, doctor_ep *e);
const char * doc_color(int s);
int doctor_cross(const doctor_ep *eps, int n, FILE *out);

/* xrddiag.c */
void fjson_str(FILE *out, const char *s);
const char * dx_verdict_name(int v);

/* diag_doctor.c */
void doctor_emit_json(const doctor_ep *eps, int n, FILE *out);
void doctor_print_diagnosis(const doctor_ep *e);

/* xrddiag.c */
int js_str(const char *json, const char *key, char *out, size_t osz);
long long js_sum(const char *json, const char *key);
int js_count(const char *json, const char *key);

/* diag_misc.c */
int do_srr(const diag_args *a);
int do_tape(const diag_args *a);

/* diag_doctor.c */
void doctor_dispatch(const diag_args *a, const char *url, doctor_ep *e);
int do_remote_doctor(const diag_args *a);

/* diag_tpc_egress.c — TPC egress (SSRF-control) self-test against your OWN gw */
typedef enum {
    TPCE_ERR_CONNECT = 0,  /* could not reach/log in to the gateway itself      */
    TPCE_REFUSED_POLICY,   /* gateway declined to originate (SSRF guard fired)   */
    TPCE_CONN_REFUSED,     /* egress permitted; source port closed (RST)         */
    TPCE_FILTERED,         /* egress permitted; source silent (probe timed out)  */
    TPCE_REACHED_NOENT,    /* egress permitted; source up, self-test lfn absent  */
    TPCE_REACHED_ERROR,    /* egress permitted; source answered with an error    */
    TPCE_ACCEPTED,         /* egress permitted; pull completed (worst case)      */
    TPCE_ARM_ERROR,        /* gateway refused the arm for a non-policy reason    */
} tpce_verdict;

typedef struct {
    tpce_verdict verdict;
    int          egress_permitted;  /* 1 if the gateway agreed to originate      */
    int          arm_kxr;           /* kXR_* (or local <0) from the destination arm */
    int          trig_kxr;          /* kXR_* (or local <0) from the trigger sync    */
    double       arm_ms;            /* wall time of the arm (open) step             */
    double       trig_ms;           /* wall time of the trigger (sync) step, if run */
    char         gw_host[256];      /* gateway host we asked to originate (no port)  */
    char         target[288];       /* the source host[:port] we named              */
    char         detail[256];       /* short PII-free classification note            */
} tpce_result;

int  tpce_run(const diag_args *a, const char *gw_url, const char *target,
              tpce_result *out);
tpce_verdict tpce_classify_trigger(const brix_status *st, double elapsed_ms,
                                   double budget_ms, char *detail, size_t dsz);
void tpce_report(const tpce_result *r);
void tpce_emit_json(const tpce_result *r, FILE *out);
int  do_tpc_egress(const diag_args *a);

/* diag_doctor_audit.c (phase-93 config/performance advisor) */
void doctor_cfg_parse_chksum(const char *csv, int *have_adler32, int *have_crc32c);
int  doctor_cfg_capacity_pct(int64_t total, int64_t freeb);
int  doctor_cfg_version_skew(const doctor_ep *eps, int n);
int  doctor_cfg_manager_count(const doctor_ep *eps, int n);
int  doctor_cfg_cap_threshold(const diag_args *a);
void doctor_scrape_config(brix_conn *c, doctor_ep *e);
void doctor_audit_rules(const diag_args *a, doctor_ep *e);
void doctor_audit_perf(doctor_ep *e);
void doctor_cross_cluster(doctor_ep *eps, int n, FILE *out);
void doctor_emit_config_json(const doctor_ep *e, FILE *out);
void doctor_report_config(const doctor_ep *e);
int  doctor_fanout(const diag_args *a, doctor_ep **eps_out, int *n_out, int *truncated);

/* diag_doctor_graph.c (phase-93 mesh topology diagram) */
void doctor_render_map(const doctor_ep *eps, int n, const char *format, FILE *out);
int  doctor_map_graph_only(const char *format);

/* diag_doctor_eos.c (EOS /proc dialect: detect MGM + enumerate FST farm)
 * doctor_eos_map connects to the manager and, when it is an EOS MGM, records the
 * banner on arr[0].eos and (admin) replaces the CMS self-node with the real FST
 * inventory. The rest are the pure text parsers, unit-tested off the wire. */
int  doctor_eos_map(const diag_args *a, doctor_ep *arr, int cap, int *n);
int  doctor_eos_proc(brix_conn *c, const char *dir, const char *cmd,
                     char **out, brix_status *st);   /* one /proc round-trip */
int  doctor_eos_stdout(const char *body, const char **start, int *len);
int  doctor_eos_kv(const char *rec, const char *key, char *out, size_t osz);
int  doctor_eos_retc(const char *body);
int  doctor_eos_parse_version(const char *body, doctor_eos *eos);
int  doctor_eos_parse_fs(const char *sout, int len, doctor_ep *arr, int cap, int start);
int  doctor_eos_report_fst(const doctor_ep *e);   /* 1 if it rendered an FST block */
void doctor_eos_report_mgm(const doctor_ep *e);   /* "  eos: ..." line, or nothing */
void doctor_eos_emit_json(const doctor_ep *e, FILE *out);  /* ,"eos":{...} or nothing */

/* diag_doctor_eos_fileinfo.c (EOS unprivileged FST discovery via `fileinfo`)
 * When admin `fs ls` is NotAuthorized, discover_fileinfo walks a bounded sample of
 * files under a root, reads each file's `fileinfo` replica table (a user-plane
 * command), and appends the distinct FSTs it names to arr[start..]. The parser and
 * URL-path helper are pure over caller buffers and unit-tested off recorded EOS
 * output. Returns the number of distinct FSTs appended (0 if none reachable). */
int  doctor_eos_url_path(const char *url, char *out, size_t osz);
int  doctor_eos_parse_fileinfo(const char *sout, int len,
                               doctor_eos_rep *out, int cap);
int  doctor_eos_discover_fileinfo(brix_conn *c, const char *root, doctor_ep *arr,
                                  int cap, int start, int *n, brix_status *st);

/* diag_doctor_latency.c (phase-93 mesh round-trip latency) */
int  doctor_have_ipv6(void);                       /* 1 = host can route IPv6 */
int  doctor_host_ipv6_only(const char *host);      /* 1 = host resolves to AAAA only */
void doctor_latency_probe(const diag_args *a, doctor_ep *e);
void doctor_render_latency(const doctor_ep *eps, int n, FILE *out);
void doctor_emit_latency_json(const doctor_ep *e, FILE *out);   /* ,"latency":{...} or nothing */

/* diag_doctor_recon.c (phase-93 deep read-only reconnaissance)
 * doctor_recon_probe scrapes `query stats a`, sweeps the full Qconfig key set,
 * decodes the capability bits and lists the authorized top-level roots over one
 * already-open connection. The XML/flag parsers are pure over caller buffers and
 * unit-tested off recorded server output. PII-free; no goto. */
void doctor_recon_probe(const diag_args *a, brix_conn *c, doctor_ep *e);
int64_t doctor_recon_xml_i64(const char *xml, const char *id, const char *tag);
void doctor_recon_parse_stats(const char *xml, doctor_recon *r);
int  doctor_recon_caps_str(unsigned f, char *out, size_t osz);   /* count of bits named */
void doctor_report_recon(const doctor_ep *e);
void doctor_emit_recon_json(const doctor_ep *e, FILE *out);       /* ,"recon":{...} or nothing */

/* diag_watch.c */
void watch_on_signal(int sig);
int watch_count_tokens(const char *s);
void watch_prom_label(const char *s, char *out, size_t osz);
int watch_probe_once(const diag_args *a, const char *url, watch_sample *out);
void watch_emit_human(const watch_sample *s, FILE *out);
void watch_emit_json(const watch_sample *s, FILE *out);
void watch_emit_prom(const watch_sample *samples, int n, FILE *out);
int watch_write_prom_atomic(const char *path, const watch_sample *samples, int n, brix_status *st);
void watch_sleep(int seconds);
int do_watch(const diag_args *a);

/* xrddiag.c */
void usage(const char *prog);

/* Absorbed micro-tools (multi-call personalities; see xrddiag.c main).
 * xrdqstats.c / wait41.c / mpxstats.c — former standalone binaries, now
 * reachable as `xrddiag <name>` subcommands or via same-named symlinks. */
int brix_qstats_main(int argc, char **argv);
int brix_wait41_main(int argc, char **argv);
int brix_mpxstats_main(int argc, char **argv);

#endif /* BRIX_DIAG_INTERNAL_H */

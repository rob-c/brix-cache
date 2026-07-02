/*
 * diag_internal.h - private split contract for xrddiag.c and its Phase-38 siblings.
 * Not a public API: include only from client/apps/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_DIAG_INTERNAL_H
#define XROOTD_DIAG_INTERNAL_H

#include "xrdc.h"
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
    xrdc_opts   conn;          
    const char *url;           
    const char *ref_url;       
    int         streams;       
    int         metrics_port;  
    const char *cluster_url;   
    int         authorized;    
    int         probe_timeout_ms; 
    const char *playback_url;  
    const char *davs;          
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
    DXP_ROOT = 0,   /* root:// / roots:// (libxrdc) */
    DXP_HTTP,       /* http://  (cleartext XrdHttp/WebDAV GET) */
    DXP_HTTPS,      /* https:// (TLS XrdHttp GET) */
    DXP_DAVS,       /* davs:// / dav:// (WebDAV class-2 over TLS) */
    DXP_S3,         /* s3:// / s3s:// (S3 REST, SigV4) */
    DXP_CMS         /* cms:// (cluster manager: locate + redirect trace) */
} dx_proto;

typedef struct {
    dx_proto      proto;             /* which protocol battery produced this endpoint */
    char          host[256];
    int           port;
    int           connected;
    int           status;            /* DOC_GREEN/YELLOW/RED */
    xrdc_netfacts nf;                /* phases / family / TCP_INFO / flowlabel */
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
    int           nissues;
    char          issues[DOC_MAXISS][160];
    int           ndx;               /* active-diagnosis findings */
    dx_finding    dx[DOC_MAXDX];
} doctor_ep;

#define DX_ANY (-9999)
typedef struct {
    const char *probe;   /* subsystem id, or NULL = any probe */
    int         kxr;     /* kXR_* code, or DX_ANY = any code */
    int         sev;     /* DX_WARN / DX_FAIL */
    const char *cause;
    const char *remedy;
} dx_rule;

extern const dx_rule DX_RULES[];
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
int download_to_fd(xrdc_conn *c, const char *path, int fd, int64_t *out_bytes, xrdc_status *st);

/* diag_topology.c */
int resolve_target(xrdc_conn *c, const xrdc_url *u, char *target, size_t tsz, xrdc_statinfo *sti, xrdc_status *st);

/* diag_check.c */
int do_check(const diag_args *a);

/* diag_bench.c */
double bench_one(xrdc_conn *c, const char *target, xrdc_status *st);
void bench_sweep(xrdc_conn *c, const char *target);
int do_bench(const diag_args *a);

/* diag_metabench.c */
int do_metabench(const diag_args *a);

/* diag_topology.c */
int do_topology(const diag_args *a);

/* diag_watch.c */
int do_status(const diag_args *a);

/* diag_compare.c */
int remote_md5(xrdc_conn *c, const char *path, char *hex, size_t hexsz, xrdc_status *st);

/* diag_topology.c */
void parse_http_hostport(const char *s, char *host, size_t hsz, int *port);

/* diag_compare.c */
int do_compare_davs(const diag_args *a);
int do_compare(const diag_args *a);

/* diag_topology.c */
int resolve_once(const char *host, int port, char *ip, size_t ipsz, int *is_loop, xrdc_status *st);
int probe_open(xrdc_conn *c, const char *urlbuf, const diag_args *a, int tmo, xrdc_status *st);
int raw_send_expect_reject(xrdc_conn *c, const uint8_t hdr24[24], const uint8_t *body, uint32_t bodylen, int lie_dlen, uint32_t fake_dlen);

/* diag_misc.c */
int do_probe_robustness(const diag_args *a);
int do_replay(const diag_args *a);

/* diag_doctor.c */
void doc_issue(doctor_ep *e, int sev, const char *fmt, ...);
int doctor_xfer(xrdc_conn *c, const char *path, double *ttfb_ms, double *mbps, int64_t *bytes);
void doctor_metrics(const char *host, int port, doctor_ep *e);

/* xrddiag.c */
void dx_record(doctor_ep *e, const char *probe, int verdict, int kxr, const char *cause, const char *remedy);
void dx_record_status(doctor_ep *e, const char *probe, const xrdc_status *st);
int dx_is_loopback(const char *host);

/* diag_check.c */
void dx_probe_auth(const xrdc_conn *c, doctor_ep *e);
void dx_probe_namespace(xrdc_conn *c, doctor_ep *e);
void dx_probe_read(xrdc_conn *c, const char *target, doctor_ep *e);
void dx_probe_checksum(xrdc_conn *c, const char *target, doctor_ep *e);
void dx_probe_write(xrdc_conn *c, doctor_ep *e);
void dx_probe_stage(xrdc_conn *c, const char *target, doctor_ep *e);

/* xrddiag.c */
int dx_b64url_enc(const unsigned char *in, size_t n, char *out, size_t outsz);
int dx_make_jwt(const char *header, const char *payload, const char *sig, char *out, size_t outsz);
int dx_connect_as(const diag_args *a, const xrdc_url *u, int force_anon, const char *token_override, const char *auth_force, xrdc_conn *c, xrdc_status *st);

/* diag_check.c */
int dx_authz_anon(const diag_args *a, const xrdc_url *u, const char *target, int have_target, char *sec_out, size_t sec_sz, doctor_ep *e);
void dx_authz_forged(const diag_args *a, const xrdc_url *u, const char *probe, const char *bad_token, doctor_ep *e);
void dx_authz_expired(const diag_args *a, const xrdc_url *u, const char *tok, doctor_ep *e);
void dx_authz_scope(const diag_args *a, const xrdc_url *u, const char *tok, doctor_ep *e);

/* diag_doctor.c */
void doctor_auth_suite(const diag_args *a, const xrdc_url *u, const char *target, int have_target, doctor_ep *e);
void doctor_diagnose(const diag_args *a, xrdc_conn *c, const xrdc_url *u, const char *target, int have_target, doctor_ep *e);

/* xrddiag.c */
const char * dx_proto_name(dx_proto p);
int dx_url_parse(const char *url, dx_proto *proto, int *tls, char *host, size_t hsz, int *port, char *path, size_t psz);
void dx_http_status(doctor_ep *e, const char *probe, int status);
void dx_http_fail(doctor_ep *e, int tls, const xrdc_status *st);

/* diag_doctor.c */
void doctor_http(const diag_args *a, dx_proto proto, int tls, const char *host, int port, const char *path, doctor_ep *e);

/* xrddiag.c */
int s3_sign(const char *method, const char *host, const char *uri, const char *ak, const char *sk, const char *region, char *hdrs, size_t hdrsz);

/* diag_doctor.c */
void doctor_s3(const diag_args *a, int tls, const char *host, int port, const char *uri, doctor_ep *e);
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

/* diag_watch.c */
void watch_on_signal(int sig);
int watch_count_tokens(const char *s);
void watch_prom_label(const char *s, char *out, size_t osz);
int watch_probe_once(const diag_args *a, const char *url, watch_sample *out);
void watch_emit_human(const watch_sample *s, FILE *out);
void watch_emit_json(const watch_sample *s, FILE *out);
void watch_emit_prom(const watch_sample *samples, int n, FILE *out);
int watch_write_prom_atomic(const char *path, const watch_sample *samples, int n, xrdc_status *st);
void watch_sleep(int seconds);
int do_watch(const diag_args *a);

/* xrddiag.c */
void usage(void);

#endif /* XROOTD_DIAG_INTERNAL_H */

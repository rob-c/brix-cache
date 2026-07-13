/*
 * xrd_internal.h - private split contract for xrd.c and its Phase-38 siblings.
 * Not a public API: include only from client/apps/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_XRD_INTERNAL_H
#define BRIX_XRD_INTERNAL_H

#include "brix.h"   
#include "core/compat/crypto.h"  
#include <ctype.h>      
#include <errno.h>
#include <fcntl.h>      
#include <libgen.h>
#include <stdarg.h>     
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>   
#include <unistd.h>
extern const char *FS_VERBS[];

#define XRD_CAPS_MAX 16
typedef struct { char key[24]; char val[256]; } xrd_cap_kv;

typedef struct {
    char           host[256];
    int            port;
    int            connected;
    char           err[XRDC_MSG_MAX];   /* holds a full brix_status message */
    int            tls_active;
    const char    *tls_ver;
    const char    *tls_cipher;
    uint32_t       server_flags;
    char           auth[40];        /* negotiated auth ("anonymous" if none) */
    char           sec_list[256];
    brix_cert_info cert;
    xrd_cap_kv     caps[XRD_CAPS_MAX];
    int            ncaps;
    int            clock_have;
    const char    *clock_method;
    long           server_epoch;
    double         offset_s;
    double         rtt_ms;
} xrd_probe;

#define XRD_MAX_CHECKS 40
typedef struct {
    char name[40];
    int  ok;            /* 1 pass, 0 fail */
    int  skipped;       /* 1 = not run (n/a or rw not requested) */
    char detail[200];
} xrd_check;

typedef struct {
    char      endpoint[320];
    char      protocol[12];          /* "root" / "https" / "s3" / ... */
    int       reachable;
    char      err[XRDC_MSG_MAX];
    xrd_check checks[XRD_MAX_CHECKS];
    int       n, npass, nfail, nskip;
} xrd_battery;

#define XRD_DOCTOR_MAX_EP 9   /* primary + up to 8 --also endpoints */
extern const char *XRD_CAP_KEYS[];

/*
 * WHAT: locally-discovered credential facts for the doctor report.
 * WHY:  xrd_doctor_json took the four presence/path fields positionally
 *       (7 params, over the parameter gate); grouping them names each fact.
 * HOW:  filled by the doctor run from bearer-token discovery + the default
 *       GSI proxy path probe; paths are meaningful only when *_present is 1.
 */
typedef struct {
    int         token_present;   /* 1 = a bearer token was discovered      */
    const char *token_path;      /* where it came from (when present)      */
    int         proxy_present;   /* 1 = a readable GSI proxy exists        */
    const char *proxy_path;      /* the default proxy path (when present)  */
} xrd_cred_facts;


/* xrd.c */
int is_fs_verb(const char *s);
void usage(void);
void exec_tool(const char *tool, char **argv);
char * map_fs_arg(const char *arg, const char *ehost, int eport, int *mismatch);

/* xrd_battery.c */
void bat_add(xrd_battery *b, const char *name, int status, const char *fmt, ...);
void fill_pattern(uint8_t *buf, size_t n);
int tmpfile_with(const uint8_t *buf, size_t n);
void battery_root(const brix_url *u, const brix_opts *o, int do_write, xrd_battery *b);
void battery_web(const brix_weburl *u, int do_write, const char *bearer, int verify, xrd_battery *b);
void battery_s3(const brix_weburl *u, int do_write, const char *ak, const char *sk, const char *region, int verify, xrd_battery *b);
void xrd_run_battery(const char *endpoint, int do_write, int verify, xrd_battery *b);

/* xrd_doctor.c */
void xrd_doctor_probe(const char *endpoint, xrd_probe *p);
void xrd_json_str(FILE *f, const char *s);
void xrd_doctor_json(const xrd_probe *p, const xrd_cred_facts *cf, const xrd_battery *bats, int nbats);
int xrd_doctor(int argc, char **argv);

/* xrd_mount.c */
int xrd_login(int argc, char **argv);
int xrd_ping(int argc, char **argv);
const char * xrd_role_str(uint32_t flags);

/* xrd_clockskew.c */
void xrd_fmt_epoch(long e, char *buf, size_t sz);
double xrd_fabs(double x);

/* xrd_doctor.c */
void xrd_probe_caps(brix_conn *c, xrd_probe *p);

/* xrd_clockskew.c */
int xrd_parse_http_date(const char *s, time_t *out);
int xrd_clockskew_http(const char *endpoint, xrd_probe *p, char *err, size_t errsz);
int xrd_clockskew_root(const char *endpoint, const brix_opts *o, xrd_probe *p, char *err, size_t errsz);
int xrd_measure_clock_skew(const char *endpoint, const brix_opts *o, xrd_probe *p, char *err, size_t errsz);

/* xrd_doctor.c */
int xrd_certinfo(int argc, char **argv);

/* xrd_clockskew.c */
int xrd_clockskew(int argc, char **argv);

/* xrd_mount.c */
int xrd_whoami(int argc, char **argv);
int xrd_caps(int argc, char **argv);
int run_cmd(char *const cmd_argv[]);
void mountinfo_unescape(const char *in, char *out, size_t outsz);
int xrd_list_mounts(void);
int xrd_mount(int argc, char **argv);
int xrd_unmount(int argc, char **argv);

#endif /* BRIX_XRD_INTERNAL_H */

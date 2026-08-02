/*
 * xrdcp_internal.h - private split contract for xrdcp.c and its Phase-38 siblings.
 * Not a public API: include only from client/apps/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_XRDCP_INTERNAL_H
#define BRIX_XRDCP_INTERNAL_H

#include "brix.h"
#include "cli/xferjournal.h"
#include "cli/cli_hint.h"   /* brix_hint_url_double_slash, brix_cred_hint_for_status_url */
#include "core/compat/crypto.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  
#include <sys/stat.h>
#include <time.h>     
#include <unistd.h>

/* parse_and_validate_args signals "usage/help printed, exit 0" with this rc so
 * the mode is distinguishable from a real usage error (50). Shared between the
 * parse pipeline (xrdcp_parse.c) and main's exit handling (xrdcp.c). */
#define XRDCP_PARSE_EXIT_OK 100

/* A growable, strdup-owned string list (source/positional/exclude/include/
 * expanded-source vectors main threads through the pipeline). */
typedef struct {
    char  **items;
    size_t  n;
    size_t  cap;
} xrdcp_strlist;

/*
 * WHAT: The complete parsed-option + connection state main threads through the
 *       parse → credential → dispatch pipeline.
 * WHY:  These flags and pointers were passed loose (up to 29 parameters), which
 *       is unreviewable and trips the parameter gate. Bundling them keeps every
 *       pipeline helper at a reviewable arity with explicit, single-owner data
 *       flow; `copt`/`conn` point at main's stack objects, the rest are the
 *       parse outputs that live beyond `brix_copy_opts`.
 * HOW:  main zero-inits one instance, points `copt`/`conn` at its locals, and
 *       hands the address to each pipeline stage. Parse writes the scalars;
 *       later stages read them. Byte-frozen: same values, same order.
 */
typedef struct {
    brix_copy_opts *copt;          /* the parsed brix_copy_opts (main's local) */
    brix_opts      *conn;          /* the connection opts (main's local) */
    struct brix_cred_store *cred_store; /* built by the credential stage; INERT */
    const char     *from;          /* --from manifest path (NULL = none) */
    const char     *journal_path;  /* --journal <path> or derived from --resume */
    const char     *oidc_account;  /* --oidc-account (or $OIDC_ACCOUNT) */
    const char     *proxy;         /* --proxy X.509 proxy path override */
    const char     *dst;           /* resolved destination (last positional) */
    int             resume;        /* --resume: derive journal from --from */
    int             retries;       /* --retry <n> budget */
    int             jobs;          /* -j/--jobs concurrency */
    int             force_progress;/* --progress */
    int             no_progress;   /* -N/--no-progress */
    int             verify;        /* --verify */
    int             auto_refresh;  /* --auto-refresh */
    int             sync_mode;     /* --sync / --sync-check */
} xrdcp_opts_t;

/*
 * WHAT: The set of strdup-owned string vectors main owns for one invocation.
 * WHY:  The positional/source/expanded/exclude/include lists were passed as
 *       five (array,count,cap) triples — 15 loose parameters — through the same
 *       helpers. One struct keeps the pipeline signatures under the gate and
 *       makes ownership (main frees them all) explicit.
 * HOW:  main zero-inits it; parse fills `pos` (+ srcs via the manifest), the
 *       credential stage fills `exp`, and main frees every vector on exit.
 */
typedef struct {
    xrdcp_strlist pos;    /* positional args (sources + dst) */
    xrdcp_strlist srcs;   /* sources after manifest merge, pre-glob */
    xrdcp_strlist exp;    /* sources after glob expansion */
    xrdcp_strlist excl;   /* --exclude patterns */
    xrdcp_strlist incl;   /* --include patterns */
} xrdcp_lists_t;

typedef struct {
    char           **items;
    size_t           n;
    const char      *dst;
    const brix_copy_opts *o;
    const brix_opts *co;
    int              retries;
    int              sync_mode;
    size_t           next;    /* next item index to claim */
    size_t           ok;
    size_t           skip;
    size_t           fail;
    pthread_mutex_t  lock;
    brix_journal    *jrn;     /* NULL = journalling disabled */
} batch_ctx;

typedef struct {
    const brix_weburl    *u;        /* dst endpoint (host/port/tls/is_s3) */
    const char           *base;     /* dst path, trailing '/' trimmed */
    const char           *scheme;   /* web_scheme_str(u->proto) */
    const char           *bearer;   /* WebDAV Authorization, NULL ⇒ anon */
    const brix_copy_opts *fo;       /* per-file opts (recursive cleared) */
    const brix_opts      *co;       /* connection opts (verify/ca_dir) */
    int                   retries;
    size_t                ok;
    size_t                fail;
} web_upload_ctx;

typedef struct {
    const char *label;
    uint64_t    start_ns;
    uint64_t    last_ns;
} xrdcp_prog;


/* xrdcp.c */
void usage_fp(FILE *out, const char *prog);
void usage(const char *prog);
int str_append(char ***list, size_t *n, size_t *cap, const char *s);
void str_free(char **list, size_t n);
void merge_alias_auth(const char *arg, brix_copy_opts *o);
void path_basename(const char *p, char *out, size_t sz);
int read_manifest(const char *file, char ***list, size_t *n, size_t *cap);
int is_root_url(const char *s);
int is_s3_url(const char *s);
int uses_cred_auth(const char *s);
int is_local_dir(const char *p);

/* xrdcp_recursive.c */
int source_has_glob(const char *s);
int expand_source(const char *s_in, const brix_opts *co, char ***out, size_t *n, size_t *cap);

/* xrdcp.c */
int dest_is_dir(const char *dst, const brix_opts *co);
int join_dest(const char *dstdir, const char *base, char *out, size_t sz);
int both_web(const char *src, const char *dst);

/* xrdcp_transfer.c */
int copy_one_with_retry(const char *src, const char *dst, const brix_copy_opts *o, const brix_opts *co, int retries, brix_status *st);
int entry_meta(const char *url, const brix_opts *co, long long *size, long long *mtime);
int transfer_one(const char *src, const char *dst, const brix_copy_opts *o, const brix_opts *co, int retries, int sync_mode, brix_status *st);
int relay_web_to_web(const char *src, const char *dst, const brix_copy_opts *o, const brix_opts *co, int retries, brix_status *st);
int batch_copy_one(const char *item, const char *dstdir, const brix_copy_opts *o, const brix_opts *co, int retries, int sync_mode, char *dpath, size_t dpsz, brix_status *st);
void * batch_worker(void *arg);
void batch_parallel(char **items, size_t n, const char *dst, const brix_copy_opts *o, const brix_opts *co, int retries, int sync_mode, int jobs, brix_journal *jrn, size_t *ok, size_t *skip, size_t *fail);

/* xrdcp.c */
const char * web_scheme_str(brix_web_proto pr);

/* xrdcp_recursive.c */
void mkdirs_for(const char *filepath);

/* xrdcp.c */
int rel_is_unsafe(const char *rel);

/* xrdcp_recursive.c */

/* The invariant inputs of one mkcol_parents call (web endpoint, base path,
 * credentials), bundled so the ancestor-collection builder stays under the
 * 5-parameter gate. */
typedef struct {
    const brix_weburl *du;      /* web destination endpoint                  */
    const char        *base;    /* dst base path, trailing '/' trimmed       */
    const char        *bearer;  /* WebDAV Authorization token, NULL = anon   */
    const brix_opts   *co;      /* connection opts (verify/ca_dir; may be NULL) */
} mkcol_ctx_t;

/* WHAT: bundled arguments for one recursive placement (source URL, relative
 * destination path, per-file opts, connection opts, retry budget, status out).
 * WHY: recursive_place fans out to a web and a local placement helper; a struct
 * keeps each helper at a reviewable parameter count with explicit data flow.
 * HOW: built on the stack by recursive_place's callers; read-only for the
 * placement helpers except `st`. */
typedef struct {
    const char           *rel;      /* destination path relative to dstroot */
    const char           *srcurl;   /* fully-qualified source URL */
    const brix_copy_opts *fo;       /* per-file copy opts (may be NULL) */
    const brix_opts      *co;       /* connection opts (may be NULL) */
    int                   retries;  /* copy retry budget */
    brix_status          *st;       /* error detail out */
} place_ctx_t;

int mkcol_parents(const mkcol_ctx_t *m, const char *rel, brix_status *st);
int recursive_place(const char *dstroot, const place_ctx_t *p);
void ensure_web_dst_base(const char *dstroot, const brix_copy_opts *fo, const brix_opts *co);
int recursive_s3_download(const brix_weburl *u, const char *dstdir, const brix_copy_opts *fo, const brix_opts *co, int retries);
int recursive_web_download(const char *src, const char *dstdir, const brix_copy_opts *o, const brix_opts *co, int retries);
int web_join(const char *base, const char *rel, char *out, size_t outsz);
void web_upload_walk(web_upload_ctx *c, const char *localdir, const char *rel);
int recursive_web_upload(const char *localdir, const char *dst, const brix_copy_opts *o, const brix_opts *co, int retries);

/* xrdcp.c */
void xrdcp_progress(void *arg, long long done, long long total);

/* xrdcp_parse.c — CLI argument parse + validation pipeline. Fills *o and *l
 * from argv; returns 0 on success, XRDCP_PARSE_EXIT_OK when --help/--version was
 * handled (caller exits 0), or a nonzero usage/OOM exit code. */
int parse_and_validate_args(int argc, char **argv, xrdcp_opts_t *o, xrdcp_lists_t *l);

/* xrdcp_dispatch.c — route the finalized job to its transfer mode (recursive
 * web, single, or batch). Returns the process exit code. */
int dispatch_transfer(xrdcp_opts_t *o, xrdcp_lists_t *l);

#endif /* BRIX_XRDCP_INTERNAL_H */

/*
 * xrdcp_internal.h - private split contract for xrdcp.c and its Phase-38 siblings.
 * Not a public API: include only from client/apps/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_XRDCP_INTERNAL_H
#define XROOTD_XRDCP_INTERNAL_H

#include "xrdc.h"
#include "compat/crypto.h"   
#include <dirent.h>   
#include <errno.h>
#include <glob.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  
#include <sys/stat.h>
#include <time.h>     
#include <unistd.h>

typedef struct {
    char           **items;
    size_t           n;
    const char      *dst;
    const xrdc_copy_opts *o;
    const xrdc_opts *co;
    int              retries;
    int              sync_mode;
    size_t           next;   /* next item index to claim */
    size_t           ok;
    size_t           skip;
    size_t           fail;
    pthread_mutex_t  lock;
} batch_ctx;

typedef struct {
    const xrdc_weburl    *u;        /* dst endpoint (host/port/tls/is_s3) */
    const char           *base;     /* dst path, trailing '/' trimmed */
    const char           *scheme;   /* web_scheme_str(u->proto) */
    const char           *bearer;   /* WebDAV Authorization, NULL ⇒ anon */
    const xrdc_copy_opts *fo;       /* per-file opts (recursive cleared) */
    const xrdc_opts      *co;       /* connection opts (verify/ca_dir) */
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
void usage(void);
int str_append(char ***list, size_t *n, size_t *cap, const char *s);
void str_free(char **list, size_t n);
void merge_alias_auth(const char *arg, xrdc_copy_opts *o);
void path_basename(const char *p, char *out, size_t sz);
int read_manifest(const char *file, char ***list, size_t *n, size_t *cap);
int is_root_url(const char *s);
int is_s3_url(const char *s);
int uses_cred_auth(const char *s);
int is_local_dir(const char *p);

/* xrdcp_recursive.c */
int source_has_glob(const char *s);
int expand_source(const char *s_in, const xrdc_opts *co, char ***out, size_t *n, size_t *cap);

/* xrdcp.c */
int dest_is_dir(const char *dst, const xrdc_opts *co);
int join_dest(const char *dstdir, const char *base, char *out, size_t sz);
int both_web(const char *src, const char *dst);

/* xrdcp_transfer.c */
int copy_one_with_retry(const char *src, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, xrdc_status *st);
int entry_size(const char *url, const xrdc_opts *co, long long *size);
int transfer_one(const char *src, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, int sync_mode, xrdc_status *st);
int relay_web_to_web(const char *src, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, xrdc_status *st);
int batch_copy_one(const char *item, const char *dstdir, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, int sync_mode, char *dpath, size_t dpsz, xrdc_status *st);
void * batch_worker(void *arg);
void batch_parallel(char **items, size_t n, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, int sync_mode, int jobs, size_t *ok, size_t *skip, size_t *fail);

/* xrdcp.c */
const char * web_scheme_str(xrdc_web_proto pr);

/* xrdcp_recursive.c */
void mkdirs_for(const char *filepath);

/* xrdcp.c */
int rel_is_unsafe(const char *rel);

/* xrdcp_recursive.c */
int mkcol_parents(const xrdc_weburl *du, const char *base, const char *rel, const char *bearer, const xrdc_opts *co, xrdc_status *st);
int recursive_place(const char *dstroot, const char *rel, const char *srcurl, const xrdc_copy_opts *fo, const xrdc_opts *co, int retries, xrdc_status *st);
void ensure_web_dst_base(const char *dstroot, const xrdc_copy_opts *fo, const xrdc_opts *co);
int recursive_s3_download(const xrdc_weburl *u, const char *dstdir, const xrdc_copy_opts *fo, const xrdc_opts *co, int retries);
int recursive_web_download(const char *src, const char *dstdir, const xrdc_copy_opts *o, const xrdc_opts *co, int retries);
int web_join(const char *base, const char *rel, char *out, size_t outsz);
void web_upload_walk(web_upload_ctx *c, const char *localdir, const char *rel);
int recursive_web_upload(const char *localdir, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries);

/* xrdcp.c */
void xrdcp_progress(void *arg, long long done, long long total);

#endif /* XROOTD_XRDCP_INTERNAL_H */

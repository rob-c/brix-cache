/*
 * xrdfs_internal.h - private split contract for xrdfs.c and its Phase-38 siblings.
 * Not a public API: include only from client/apps/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_XRDFS_INTERNAL_H
#define BRIX_XRDFS_INTERNAL_H

#include "brix.h"
#include "core/compat/crypto.h"   
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>     
#include <fnmatch.h>   
#include <regex.h>     
#include <signal.h>    
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>  
#include <time.h>
#include <unistd.h>    
#define XRDFS_MAXTOK 64

typedef struct {
    const brix_weburl *u;
    const char        *base;     /* URL path component, trailing '/' trimmed */
    const char        *bearer;   /* WebDAV bearer token (or NULL = anonymous) */
    int                verify;   /* verify the TLS server chain (https/davs) */
    const char        *ca_dir;   /* CA hash dir for verification (or NULL) */
} web_ctx;

extern volatile sig_atomic_t tail_stop;
#define XRDFS_DD_MAXBS (256LL << 20)   /* cap a single block buffer at 256 MiB */
#define XRDFS_MAXDEPTH 64   /* recursion bound (defensive; trees aren't cyclic) */
typedef int (*xrdfs_visit)(const char *full, const brix_dirent *e, int depth, void *u);

typedef struct {
    brix_conn *c;
    int        mode;
    int        failures;
} chmod_walk;

typedef struct {
    int64_t bytes;
    long    files;
    long    dirs;
} du_acc;

typedef struct {
    const char *name_glob;   /* -name PATTERN (fnmatch on basename), or NULL */
    int         type;        /* -type: 0=any, 1=file, 2=dir */
    int         size_sign;   /* -size: -1 (<), 0 (none/exact), +1 (>) */
    int64_t     size_val;    /* -size threshold in bytes */
} find_pred;

typedef struct {
    long ndirs;
    long nfiles;
    int  maxdepth;   /* -L; <0 = unlimited */
    int  dirs_only;  /* -d */
} tree_opts;

typedef int (*xrdfs_fn)(brix_conn *, const char *, int, char **);

typedef struct {
    const char *name;
    xrdfs_fn    fn;
    const char *help;
} xrdfs_cmd;

extern const xrdfs_cmd COMMANDS[];


/* xrdfs_fmt.c */
int endpoint_to_url(const char *ep, brix_url *u, brix_status *st);
void build_path(const char *cwd, const char *arg, char *out, size_t outsz);
void flags_to_str(int f, char *out, size_t sz);
void print_stat_time(const char *label, long epoch);
void print_statinfo(const char *path, const brix_statinfo *si);

/* xrdfs_meta.c */
int do_stat(brix_conn *c, const char *cwd, int argc, char **argv);
int ls_print_dir(brix_conn *c, const char *path, int want_long, int recursive, int human, brix_status *st);
int do_ls(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_web.c */
void web_build_path(const char *base, const char *cwd, const char *arg, char *out, size_t outsz);
int web_ls_print_dir(const web_ctx *w, const char *path, int want_long, int recursive, int human, brix_status *st);
int web_ls(const web_ctx *w, const char *cwd, int argc, char **argv);
int web_stat(const web_ctx *w, const char *cwd, int argc, char **argv);
int web_dispatch(const web_ctx *w, int argc, char **argv);

/* xrdfs_meta.c */
int do_mkdir(brix_conn *c, const char *cwd, int argc, char **argv);
int do_rm(brix_conn *c, const char *cwd, int argc, char **argv);
int do_rmdir(brix_conn *c, const char *cwd, int argc, char **argv);
int do_mv(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_fmt.c */
int parse_chmod_mode(const char *s);

/* xrdfs_meta.c */
int do_chmod(brix_conn *c, const char *cwd, int argc, char **argv);
int do_truncate(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_data.c */
int stream_file(brix_conn *c, const char *path, int64_t start, int64_t limit, brix_status *st);
int do_cat(brix_conn *c, const char *cwd, int argc, char **argv);
int head_lines(brix_conn *c, const char *path, long nlines, brix_status *st);
int do_head(brix_conn *c, const char *cwd, int argc, char **argv);
void tail_sigint(int sig);
int tail_start_for_lines(brix_conn *c, const char *path, int64_t size, long nlines, int64_t *start, brix_status *st);
int tail_follow(brix_conn *c, const char *path, int64_t from, double interval, brix_status *st);
int do_tail(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_meta.c */
int do_locate(brix_conn *c, const char *cwd, int argc, char **argv);
int do_statvfs(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_fmt.c */
int64_t df_field(const char *reply, const char *key);
int df_parse_space(const char *reply, int64_t *total, int64_t *avail, int64_t *used, int64_t *largest);

/* xrdfs_meta.c */
int do_df(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_fmt.c */
int two_digits(const char *p);
int touch_parse_time(const char *s, struct timespec *out);

/* xrdfs_meta.c */
int do_touch(brix_conn *c, const char *cwd, int argc, char **argv);
int do_ln(brix_conn *c, const char *cwd, int argc, char **argv);
int do_readlink(brix_conn *c, const char *cwd, int argc, char **argv);
int do_cksum(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_data.c */
int do_wc(brix_conn *c, const char *cwd, int argc, char **argv);
int slurp_file(brix_conn *c, const char *path, uint8_t **out, int64_t *len, brix_status *st);
int do_cmp(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_meta.c */
int xattr_ls(brix_conn *c, const char *path);
int do_xattr(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_data.c */
int do_grep(brix_conn *c, const char *cwd, int argc, char **argv);
int do_hexdump(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_fmt.c */
int64_t parse_bytes(const char *s);
void rate_pace(const struct timespec *start, int64_t sent, double rate);

/* xrdfs_data.c */
int do_dd(brix_conn *c, const char *cwd, int argc, char **argv);
int do_upload(brix_conn *c, const char *cwd, int argc, char **argv);
int do_download(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_meta.c */
int do_query(brix_conn *c, const char *cwd, int argc, char **argv);
int do_prepare(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs.c */
int wait_online(brix_conn *c, const char *path, int timeout_s, brix_status *st);

/* xrdfs_meta.c */
int do_stage(brix_conn *c, const char *cwd, int argc, char **argv);
int do_evict(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs.c */
int do_explain(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_fmt.c */
int parse_u64_strict(const char *s, unsigned long long *out);

/* xrdfs_data.c */
int do_readv(brix_conn *c, const char *cwd, int argc, char **argv);
int do_writev(brix_conn *c, const char *cwd, int argc, char **argv);

/* xrdfs_fmt.c */
int is_dot(const char *name);
void fmt_size(int64_t n, char *out, size_t sz, int human);
int join_path(const char *dir, const char *name, char *out, size_t sz);

/* xrdfs_walk.c */
int walk_dir(brix_conn *c, const char *path, int depth, xrdfs_visit visit, void *u, brix_status *st);
int chmod_visit(const char *full, const brix_dirent *e, int depth, void *u);
int chmod_recursive(brix_conn *c, const char *path, int mode, int *failures, brix_status *st);
int du_visit(const char *full, const brix_dirent *e, int depth, void *u);
int do_du(brix_conn *c, const char *cwd, int argc, char **argv);
int find_visit(const char *full, const brix_dirent *e, int depth, void *u);
int do_find(brix_conn *c, const char *cwd, int argc, char **argv);
int tree_recurse(brix_conn *c, const char *path, const char *prefix, int depth, tree_opts *o, brix_status *st);
int do_tree(brix_conn *c, const char *cwd, int argc, char **argv);
const xrdfs_cmd * find_command(const char *name);

/* xrdfs.c */
int dispatch(brix_conn *c, char *cwd, size_t cwdsz, int ntok, char **tok, int *quit);
int tokenize(char *line, char **tok, int maxtok);
int repl(brix_conn *c, const char *host, int port);
void usage(void);

#endif /* BRIX_XRDFS_INTERNAL_H */

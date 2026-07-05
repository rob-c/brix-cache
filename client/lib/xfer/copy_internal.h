/*
 * copy_internal.h - private split contract for copy.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_COPY_INTERNAL_H
#define BRIX_COPY_INTERNAL_H

#include "brix.h"
#include "auth/cred/cred.h"                 
#include "fs/vfs.h"                  
#include "protocols/shared/zip.h"                  
#include "core/compat/host_format.h"  
#include "core/compat/hex.h"          
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>     
#include <errno.h>
#include <dirent.h>    
#include <sys/stat.h>  
#include <signal.h>    
#include <stdatomic.h> 
#define XRDC_COPY_CHUNK  (8u * 1024u * 1024u)
#define XRDC_CK_OK          0    
#define XRDC_CK_MISMATCH  (-1)   
#define XRDC_CK_UNVERIFIED  1    
extern volatile sig_atomic_t g_brix_copy_quit;

typedef ssize_t (*pump_src_fn)(void *ctx, uint8_t *buf, int64_t off, size_t cap,
                               brix_status *st);

typedef int (*pump_sink_fn)(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                            brix_status *st);

#define XRDC_RESILIENT_FLOOR (256u * 1024u)
typedef struct {
    brix_conn  *c;
    brix_file  *f;
    int         pgrw;
    /* resilient download source only (zero for upload sink / non-resilient): */
    int         resilient;
    const char *path;        /* source/dest path, for reopen */
    const char *opaque;      /* compress opaque or NULL */
    int         max_stall_ms;
    size_t      cur_chunk;   /* adaptive read size (shrinks on loss) */
    int         posc;        /* resilient upload sink only: posc flag for reopen */
} pump_remote_t;

typedef struct {
    brix_vfs_file *vf;
} pump_local_t;

#define XRDC_WEB_TIMEOUT_MS 300000   /* 5 min per-read ceiling for big files */
typedef struct { brix_conn *c; brix_file *f; brix_status *st; } zip_remote_ctx;

typedef struct { int fd; } unzip_sink_ctx;

typedef struct { int fd; uint64_t off; } zipw_local_sink;

typedef struct { brix_conn *c; brix_file *f; uint64_t off; brix_status *st; } zipw_remote_sink;


/* copy.c */
void copy_signal_handler(int sig);

/* copy_local.c */
int make_temp_path(const char *dst, char *out, size_t outsz);
int open_download_temp(const char *dst, char *tmp, size_t tmpsz, brix_status *st);
int atomic_dest_finish(const char *tmp, const char *dest, int rc, brix_status *st);

/* copy_pump.c */
int write_all(int fd, const uint8_t *buf, size_t n, brix_status *st);

/* copy.c */
int copy_stall_ms(const brix_copy_opts *o, int dflt);

/* copy_pump.c */
int pump_remote_reopen(pump_remote_t *r, brix_status *st);
ssize_t pump_src_remote(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st);
int pump_sink_reopen(pump_remote_t *r, brix_status *st);
int pump_sink_remote(void *ctx, const uint8_t *buf, int64_t off, size_t n, brix_status *st);
ssize_t pump_src_local(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st);
int pump_sink_local(void *ctx, const uint8_t *buf, int64_t off, size_t n, brix_status *st);
ssize_t pump_src_local_vfs(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st);
int pump_sink_local_vfs(void *ctx, const uint8_t *buf, int64_t off, size_t n, brix_status *st);
int transfer_pump(pump_src_fn src, void *sctx, pump_sink_fn sink, void *kctx, int64_t expected, const brix_copy_opts *o, int64_t progress_total, brix_status *st);

/* copy_local.c */
int download_stream_body(brix_conn *c, const brix_url *su, const brix_statinfo *si, pump_sink_fn sink, void *sinkctx, const brix_copy_opts *o, brix_streamset *ss, brix_status *st);

/* copy.c */
int resilient_setup(brix_conn *c, const brix_url *su, const brix_opts *co, brix_statinfo *si, int max_stall_ms, brix_status *st);

/* copy_local.c */
int copy_download(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int upload_stream_body(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, pump_src_fn src, void *srcctx, int64_t total, brix_status *st);
int copy_upload(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy_remote.c */
int r2r_teardown(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df, int src_up, int dst_up, int sopen, int dopen, int rc, brix_status *st);
int r2r_stream_body(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df, const brix_statinfo *si, const brix_copy_opts *o, brix_status *st);
int copy_remote_to_remote(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int cksum_verify(brix_conn *c, const char *remote_path, const char *local_path, const char *spec, int silent, brix_status *st);
int gen_tpc_key(char *out, size_t outsz);
int tpc_teardown(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df, char *src_opaque, char *dst_opaque, int su_up, int du_up, int sopen, int dopen, int rc, brix_status *st);
int copy_tpc(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy.c */
int copy_one_r2l(brix_conn *c, const char *rpath, const char *lpath, int64_t expected_size, brix_status *st);
int copy_one_l2r(brix_conn *c, const char *lpath, const char *rpath, const brix_copy_opts *o, brix_status *st);

/* copy_recursive.c */
int copy_tree_download(brix_conn *c, const char *rpath, const char *lpath, const char *rel, const brix_copy_opts *o, brix_status *st);
int copy_tree_upload(brix_conn *c, const char *lpath, const char *rpath, const char *rel, const brix_copy_opts *o, brix_status *st);
int recursive_dest_root(const char *dstdir, const char *srcpath, char *out, size_t outsz);
int copy_recursive(const brix_url *su, const brix_url *du, int download, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int web_auth_headers(const brix_weburl *u, const char *method, const brix_copy_opts *o, const brix_opts *co, char *hdrs, size_t hdrsz, brix_status *st);
int copy_web_download(const brix_weburl *su, const brix_url *du, int to_stdout, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy_local.c */
int copy_web_upload(const brix_url *su, const brix_weburl *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int copy_web(const char *src, const char *dst, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy_zip.c */
ssize_t zip_remote_pread(void *vctx, uint64_t off, void *buf, size_t len);
int unzip_sink_write(void *sc, const uint8_t *d, size_t l);
int copy_unzip(const brix_url *su, const char *archive_path, const char *member, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int unzip_member_from_src(const char *src, const brix_url *su, char *member, size_t member_sz, char *arch, size_t arch_sz);
int zipw_local_write(void *cx, const void *d, size_t n);
int zipw_remote_write(void *cx, const void *d, size_t n);
ssize_t zipw_local_pread(void *cx, uint64_t off, void *buf, size_t len);
const char * zip_member_basename(const char *p);
int zip_read_seed(brix_zip_pread_fn pr, void *ctx, uint64_t size, uint64_t *base, uint8_t **seed_cd, size_t *seed_len, size_t *seed_n, brix_status *st);
int zip_emit_member(brix_zip_writer *w, const char *member, int srcfd, brix_status *st);
int copy_zip_store_local(const char *member, int srcfd, const brix_url *du, int append, brix_status *st);
int copy_zip_store_remote(const char *member, int srcfd, const brix_url *du, int append, const brix_opts *co, brix_status *st);

/* copy_block.c */
int copy_remote_to_block(const char *src_url, const char *dst_url, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int copy_block_to_remote(const char *src_url, const char *dst_url, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int copy_vfs_to_vfs(const char *src_url, const char *dst_url, const brix_copy_opts *o, brix_status *st);
int copy_block(const char *src, const char *dst, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy_zip.c */
int copy_zip_store(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

#endif /* BRIX_COPY_INTERNAL_H */

/*
 * vfs_s3_internal.h - private split contract for vfs_s3.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_VFS_S3_INTERNAL_H
#define XROOTD_VFS_S3_INTERNAL_H

#include "vfs.h"
#include "xrdc.h"
#include "compat/host_format.h"   
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define S3_PART_MAX_DEFAULT  (64LL * 1024 * 1024)
#define S3_PART_MAX_ENV      "S3_PART_MAX_OVERRIDE"
#define S3_PREAD_MAX         (7LL * 1024 * 1024)
#define S3_REQ_TIMEOUT_MS    300000   
#define S3_AUTH_HDRS_CAP     4096     
#define S3_ETAG_LEN          96       
#define S3_UPLOAD_ID_LEN     128      
#define S3_ETAG_INIT_CAP     16       
#define S3_PUT_BUF_INIT      (64 * 1024)  
#define S3_REGION_DEFAULT    "us-east-1"
typedef struct {
    char val[S3_ETAG_LEN];
} s3_part_etag;

typedef struct {
    xrdc_vfs_file  base;          
    
    char           host[256];
    int            port;
    int            tls;
    char           key_path[XRDC_PATH_MAX];   
    
    char           ak[128];        
    char           sk[256];        
    char           region[64];     
    
    int64_t        obj_size;       
    
    int            is_write;       
    int            is_mpu;         
    int64_t        part_size;      
    
    void          *put_buf;        
    size_t         put_len;        
    size_t         put_cap;        
    int64_t        put_write_off;  
    
    char           upload_id[S3_UPLOAD_ID_LEN]; 
    int            part_count;     
    s3_part_etag  *etags;          
    int            etag_cap;       
    int64_t        mpu_write_off;  
    void          *part_buf;       
    size_t         part_buf_len;   
} vfs_s3_file;

extern const xrdc_vfs_ops s_s3_ops;
extern const xrdc_vfs_backend s_s3_backend;


/* vfs_s3_http.c */
void s3_creds_load(vfs_s3_file *sf, const xrdc_vfs_open_opts *opts);
int s3_sign(vfs_s3_file *sf, const char *method, const char *canon_qs, char *hdrs, size_t hdrsz, xrdc_status *st);
int s3_http_err(int status, const char *op, const char *path, xrdc_status *st);
int xml_extract_tag(const char *xml, const char *tag, char *out, size_t outsz);

/* vfs_s3_io.c */
int s3_load_size(vfs_s3_file *sf, xrdc_status *st);

/* vfs_s3_http.c */
int s3_etag_ensure_cap(vfs_s3_file *sf, int needed, xrdc_status *st);

/* vfs_s3_mpu.c */
int s3_mpu_upload_part(vfs_s3_file *sf, int part_num, const void *data, size_t len, xrdc_status *st);
int s3_mpu_flush_part_buf(vfs_s3_file *sf, xrdc_status *st);
int s3_mpu_create(vfs_s3_file *sf, xrdc_status *st);
size_t s3_mpu_complete_xml_size(int n_parts);
int s3_mpu_complete(vfs_s3_file *sf, xrdc_status *st);
void s3_mpu_abort_upload(vfs_s3_file *sf);

/* vfs_s3_io.c */
ssize_t s3_pread(xrdc_vfs_file *f, int64_t off, void *buf, size_t n, xrdc_status *st);
int s3_pwrite_check_sequential(int64_t off, int64_t expected_off, const char *path, xrdc_status *st);
int s3_pwrite_single(vfs_s3_file *sf, int64_t off, const void *data, size_t n, xrdc_status *st);
int s3_pwrite_mpu(vfs_s3_file *sf, int64_t off, const void *data, size_t n, xrdc_status *st);
int s3_pwrite(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n, xrdc_status *st);
int s3_fstat(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st);
int s3_truncate(xrdc_vfs_file *f, int64_t size, xrdc_status *st);
int s3_sync(xrdc_vfs_file *f, xrdc_status *st);
int s3_commit_single(vfs_s3_file *sf, xrdc_status *st);
int s3_commit_mpu(vfs_s3_file *sf, xrdc_status *st);
int s3_commit(xrdc_vfs_file *f, xrdc_status *st);
void s3_abort(xrdc_vfs_file *f);
void s3_close(xrdc_vfs_file *f);

/* vfs_s3.c */
int64_t s3_part_size_from_env(void);
vfs_s3_file * s3_alloc_handle(void);
int s3_open_read(vfs_s3_file *sf, xrdc_status *st);
int s3_open_write_single(vfs_s3_file *sf, const xrdc_vfs_open_opts *opts, xrdc_status *st);
int s3_open_write_mpu(vfs_s3_file *sf, xrdc_status *st);
int s3_be_open(const xrdc_vfs_backend *be, const char *url, int flags, const xrdc_vfs_open_opts *opts, xrdc_vfs_file **out, xrdc_status *st);
int s3_be_stat(const xrdc_vfs_backend *be, const char *url, xrdc_vfs_stat *out, xrdc_status *st);

#endif /* XROOTD_VFS_S3_INTERNAL_H */

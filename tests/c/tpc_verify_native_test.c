/* Real source-stat framing and destination checksum computation with finite wire replies. */
#include "tpc/engine/tpc_internal.h"
#include "tpc/outbound/source_internal.h"
#include "fs/backend/sd_registry.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_stream_brix_srv_conf_t config;
    brix_tpc_pull_t task;
    const char *operation, *mode, *reply;
    int sends, receives, fd, opens;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }

int __wrap_tpc_send_all(brix_tpc_pull_t *task,int fd,const void *bytes,size_t length)
{
    fixture *f=state();assert(task==&f->task && fd==91);f->sends++;
    const u_char *wire=bytes;uint16_t request=xrdw_get_u16(wire+2);
    assert(length==24+strlen(task->src_path) && xrdw_get_u32(wire+20)==strlen(task->src_path));
    assert(!memcmp(wire+24,task->src_path,strlen(task->src_path)));
    if(!strcmp(f->operation,"stat")) { assert(wire[1]==4 && request==kXR_stat); }
    else { assert(wire[1]==5 && request==kXR_query && xrdw_get_u16(wire+4)==kXR_Qcksum); }
    return mode("send-error")?-1:0;
}
int __wrap_tpc_recv_response(brix_tpc_pull_t *task,int fd,uint16_t *status,u_char **body,uint32_t *length)
{
    fixture *f=state();assert(task==&f->task && fd==91);f->receives++;
    if(mode("recv-error")) { return -1; }
    *status=mode("refused")?kXR_error:kXR_ok;*length=(uint32_t)strlen(f->reply);
    *body=mode("no-body")?NULL:(u_char *)strdup(f->reply);return 0;
}
ngx_fd_t __wrap_brix_vfs_writer_fd(brix_vfs_writer_t *writer)
{ assert(writer==(void *)&state()->opens);return mode("object")?NGX_INVALID_FILE:state()->fd; }
int __real_brix_vfs_open_fd(ngx_log_t *,const char *,const char *,int,mode_t);
int __wrap_brix_vfs_open_fd(ngx_log_t *log,const char *root,const char *path,int flags,mode_t permissions)
{
    fixture *f=state();assert(log==&f->log && !strcmp(path,f->task.dst_path));
    assert(flags==(O_RDONLY|O_NOFOLLOW) && !permissions);f->opens++;
    if(mode("open-error")) { errno=EACCES;return -1; }
    return __real_brix_vfs_open_fd(log,root,path,flags,permissions);
}
int main(int argc,char **argv)
{
    assert(argc==6);fixture f={0};ngx_cycle=&f.cycle;f.operation=argv[1];f.mode=argv[2];f.reply=argv[3];
    ngx_open_file_t output={.fd=STDERR_FILENO};f.log=(ngx_log_t){.log_level=NGX_LOG_ERR,.file=&output};
    f.cycle.log=&f.log;ngx_time_init();ngx_os_argv=argv;assert(ngx_os_init(&f.log)==NGX_OK);
    f.task.conf=&f.config;snprintf(f.config.common.root_canon,sizeof(f.config.common.root_canon),"%s",argv[4]);
    snprintf(f.task.dst_path,sizeof(f.task.dst_path),"%s",argv[5]);strcpy(f.task.src_path,"/origin/object");
    f.fd=open(argv[5],O_RDONLY);assert(f.fd>=0);brix_sd_posix_wrap(&f.task.dst_obj,f.fd);
    if(mode("writer") || mode("object")) { f.task.dst_writer=(void *)&f.opens; }
    int rc=!strcmp(f.operation,"stat")?tpc_stat_source(&f.task,91):tpc_verify_source_checksum(&f.task,91);
    printf("%d %u %u %llu %d %d %d\n",rc,(unsigned)f.task.xrd_error,
        (unsigned)f.task.src_size_known,(unsigned long long)f.task.src_size,f.sends,f.receives,f.opens);
    assert(fcntl(f.fd,F_GETFD)>=0);close(f.fd);return 0;
}

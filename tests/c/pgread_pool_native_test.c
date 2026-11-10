/* Pool pgread send ownership and wire bytes over a finite socket boundary. */
#include "core/ngx_brix_module.h"
#include "core/aio/pgreads_internal.h"
#include <assert.h>
#include <poll.h>

typedef struct {
    ngx_cycle_t cycle;
    brix_ctx_t secondary;
    ngx_connection_t connection;
    brix_pgread_aio_t task;
    const char *mode;
    u_char *image,*delivered;
    size_t sent,capacity;
    unsigned calls,polls,jobs;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }
ssize_t __wrap_send(int fd,const void *data,size_t length,int flags)
{
    fixture *f=state();assert(fd==12345 && flags==MSG_NOSIGNAL && length);
    assert(data==f->image+f->sent);f->calls++;
    if(mode("interrupt") && f->calls==1) { errno=EINTR;return -1; }
    if(mode("zero")) { return 0; }
    if(mode("socket-error") || mode("errno-zero")) { errno=mode("errno-zero")?0:ECONNRESET;return -1; }
    if(mode("blocked") || (mode("stall") && f->sent>0)
        || (mode("progress") && f->calls%12)) { errno=EAGAIN;return -1; }
    if(mode("short") || mode("stall") || mode("progress")) { length=ngx_min(length,7); }
    assert(f->sent+length<=f->capacity);memcpy(f->delivered+f->sent,data,length);f->sent+=length;
    return (ssize_t)length;
}
int __wrap_poll(struct pollfd *fds,nfds_t count,int timeout)
{ assert(count==1 && fds->fd==12345 && fds->events==POLLOUT && timeout==25);state()->polls++;return 0; }
void __real_brix_vfs_io_execute(brix_vfs_job_t *job);
void __wrap_brix_vfs_io_execute(brix_vfs_job_t *job)
{
    fixture *f=state();f->jobs++;assert(job->op==BRIX_VFS_IO_PGREAD);
    if(mode("read-error") || (mode("late-read-error") && f->jobs==2)) {
        job->nio=-1;job->io_errno=EIO;return;
    }
    __real_brix_vfs_io_execute(job);
}
static void save_bytes(const char *path,const void *data,size_t size)
{ FILE *out=fopen(path,"wb");assert(out);assert(fwrite(data,1,size,out)==size);assert(fclose(out)==0); }
int main(int argc,char **argv)
{
    assert(argc==8);fixture *f=calloc(1,sizeof(*f));assert(f);ngx_cycle=&f->cycle;
    f->mode=argv[2];f->connection.fd=12345;f->task.sec_ctx=&f->secondary;f->task.sec_c=&f->connection;
    f->task.fd=open(argv[3],O_RDONLY);assert(f->task.fd>=0);
    f->task.offset=(off_t)strtoll(argv[6],NULL,10);f->task.rlen=(size_t)strtoull(argv[7],NULL,10);
    f->capacity=f->task.rlen+f->task.rlen/1024+4096;
    f->image=calloc(1,f->capacity);f->delivered=calloc(1,f->capacity);assert(f->image && f->delivered);
    f->task.scratch=f->image+sizeof(ServerStatusResponse_pgRead);
    f->task.streamid[0]=0x31;f->task.streamid[1]=0x92;
    f->secondary.out.send_token=mode("token-owned");f->secondary.out.send_busy=mode("busy-ring");
    int rc=1;
    if(!strcmp(argv[1],"stream")) { rc=(int)brix_pgread_pool_stream(&f->task); }
    else {
        brix_vfs_job_t job;
        brix_vfs_job_read_init(&job,f->task.fd,f->task.offset,f->task.rlen,f->task.scratch,f->task.rlen,0);
        job.op=BRIX_VFS_IO_PGREAD;__real_brix_vfs_io_execute(&job);
        f->task.nread=mode("read-error")?-1:job.nio;f->task.out_size=job.out_size;
        brix_pgread_pool_send(&f->task);
    }
    assert(f->sent==f->task.pool_sent && f->task.pool_image_len<=f->capacity);
    assert(!memcmp(f->image,f->delivered,f->sent));
    save_bytes(argv[4],f->image,f->task.pool_image_len);save_bytes(argv[5],f->delivered,f->sent);
    printf("%d %ld %zu %lu %u %u %u %u %u %d %d %u\n",rc,(long)f->task.nread,f->task.pool_image_len,
        (unsigned long)f->secondary.out.send_token,f->task.pool_sent_all,f->task.pool_token_held,
        f->task.pool_chunked,(unsigned)f->task.pool_frames,f->task.chunk_error,f->task.pool_send_errno,
        f->task.io_errno,f->polls);
    close(f->task.fd);free(f->image);free(f->delivered);free(f);return 0;
}

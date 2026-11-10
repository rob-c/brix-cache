/* Real GridFTP event callbacks with finite socket/event-provider outcomes. */
#include "protocols/gridftp/ev/ftp_ev.h"
#include "fs/vfs/vfs_ops.h"
#include <assert.h>
#include <fcntl.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    ngx_log_t log;
    ftp_ev_t fc;
    ftp_ev_dc_t dc;
    ngx_connection_t control, slots[4];
    ngx_event_t reads[4], writes[4];
    int armed, slots_used, accepts, accepted[65], ready, tls, resumed, metrics, notes;
    int read_arms, write_arms, sends, closed_files, closed_dirs, aborted, ssl_closed;
    int peer_fd, active_fd, reply_code;
    u_char delivered[128];
    size_t delivered_len;
    ngx_connection_t listener;
    ngx_event_t listener_read, listener_write;
    ngx_ssl_connection_t child_ssl;
    void (*tls_done)(ngx_connection_t *);
    ngx_connection_t *tls_child;
    u_char blocks[256];
    size_t block_length, block_offset;
    int writer_opens, writer_commits, unlinks, receives, block_mode;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }

ngx_connection_t *__wrap_ngx_get_connection(ngx_socket_t fd,ngx_log_t *log)
{
    fixture *f=state();
    if(mode("connection") || (mode("data-connection") && f->slots_used==1)) { return NULL; }
    assert(f->slots_used<4);int i=f->slots_used++;
    ngx_connection_t *c=&f->slots[i];
    c->fd=fd;c->log=log;c->read=&f->reads[i];c->write=&f->writes[i];
    c->read->data=c;c->write->data=c;c->write->write=1;return c;
}
void __wrap_ngx_close_connection(ngx_connection_t *c)
{
    assert(c && c->fd>=0);
    if(c->read->timer_set) { ngx_del_timer(c->read); }
    if(c->write->timer_set) { ngx_del_timer(c->write); }
    if(c->read->posted) { ngx_delete_posted_event(c->read); }
    assert(close(c->fd)==0);c->fd=-1;
}
ngx_int_t __wrap_ngx_handle_read_event(ngx_event_t *ev,ngx_uint_t flags)
{
    assert(ev && !flags);state()->read_arms++;
    if(mode("block-listener-arm") && ev==&state()->listener_read) { return NGX_ERROR; }
    if(mode("read-arm") || (state()->read_arms>1 && (mode("again-arm") || mode("flood-arm")))) { return NGX_ERROR; }
    return NGX_OK;
}
ngx_int_t __wrap_ngx_handle_write_event(ngx_event_t *ev,size_t lowat)
{ assert(ev && !lowat);state()->write_arms++;return mode("write-arm")?NGX_ERROR:NGX_OK; }
int __real_ngx_nonblocking(ngx_socket_t);
int __wrap_ngx_nonblocking(ngx_socket_t fd)
{ return mode("nonblocking")?-1:__real_ngx_nonblocking(fd); }
int __real_socket(int,int,int);
int __wrap_socket(int domain,int type,int protocol)
{
    if(state()->armed && mode("socket")) { errno=EMFILE;return -1; }
    int fd=__real_socket(domain,type,protocol);
    if(state()->armed) { state()->active_fd=fd; }
    return fd;
}
int __wrap_connect(int fd,const struct sockaddr *address,socklen_t length)
{
    const struct sockaddr_in *in=(const struct sockaddr_in *)address;
    assert(fd==state()->active_fd && length==sizeof(*in) && in->sin_port==htons(45678));
    if(mode("connect")) { errno=ECONNREFUSED;return -1; }
    if(mode("immediate")) { return 0; }
    errno=EINPROGRESS;return -1;
}
int __real_bind(int,const struct sockaddr *,socklen_t);
int __wrap_bind(int fd,const struct sockaddr *address,socklen_t length)
{
    if(state()->armed && mode("bind")) { errno=EADDRNOTAVAIL;return -1; }
    return __real_bind(fd,address,length);
}
int __wrap_getsockopt(int fd,int level,int option,void *value,socklen_t *length)
{
    assert(fd==state()->active_fd && level==SOL_SOCKET && option==SO_ERROR && *length==sizeof(int));
    *(int *)value=mode("socket-error")?ECONNREFUSED:0;
    if(mode("getsockopt")) { errno=EBADF;return -1; }return 0;
}
int __wrap_getpeername(int fd,struct sockaddr *address,socklen_t *length)
{
    assert(fd==state()->control.fd && *length>=sizeof(struct sockaddr_in));
    if(mode("peer-error")) { errno=ENOTCONN;return -1; }
    struct sockaddr_in in={.sin_family=AF_INET,.sin_addr.s_addr=htonl(0xc0000201)};
    memcpy(address,&in,sizeof(in));*length=sizeof(in);return 0;
}
int __wrap_accept(int fd,struct sockaddr *address,socklen_t *length)
{
    fixture *f=state();assert(fd==f->fc.pasv_fd);
    if(mode("accept-error")) { errno=ECONNABORTED;return -1; }
    if(mode("again") || mode("again-arm") || (f->accepts && !mode("flood") && !mode("flood-arm"))) {
        errno=EAGAIN;return -1;
    }
    int i=f->accepts++;assert(i<65);
    if(i) { assert(fcntl(f->accepted[i-1],F_GETFD)==-1 && errno==EBADF); }
    struct sockaddr_in in={.sin_family=AF_INET,.sin_addr.s_addr=htonl(0xc0000201)};
    if(mode("offpeer") || mode("flood") || mode("flood-arm")) { in.sin_addr.s_addr=htonl(0xc0000202); }
    assert(*length>=sizeof(in));memcpy(address,&in,sizeof(in));*length=sizeof(in);
    f->accepted[i]=dup(f->peer_fd);assert(f->accepted[i]>=0);return f->accepted[i];
}
void __wrap_brix_ftp_ev_data_ready(ftp_ev_dc_t *dc)
{ assert(dc==&state()->dc && dc->dconn && !dc->connecting);state()->ready++; }
void __wrap_brix_ftp_ev_dc_start_tls(ftp_ev_dc_t *dc)
{ assert(dc==&state()->dc && dc->fc->prot=='P' && !state()->ready);state()->tls++; }
void __wrap_brix_ftp_ev_metric_xfer(const ftp_ev_dc_t *dc,ngx_int_t rc)
{ assert(dc==&state()->dc && (rc==NGX_OK || rc==NGX_ERROR));state()->metrics++; }
void __wrap_brix_ftp_ev_cns_note_stored(ftp_ev_t *fc,const char *path)
{ assert(fc==&state()->fc && !strcmp(path,"/object"));state()->notes++; }
ngx_int_t __wrap_brix_ftp_ev_reply(ftp_ev_t *fc,const char *format,...)
{ assert(fc==&state()->fc);state()->reply_code=atoi(format);return NGX_OK; }
void __wrap_brix_ftp_ev_resume(ftp_ev_t *fc)
{ assert(fc==&state()->fc && !fc->dc && fc->state==FTP_EV_ST_CMD);state()->resumed++; }
ngx_int_t __wrap_brix_vfs_close(brix_vfs_file_t *file,ngx_log_t *log)
{ assert(file==(void *)&state()->closed_files && log==&state()->log);state()->closed_files++;return NGX_OK; }
ngx_int_t __wrap_brix_vfs_closedir(brix_vfs_dir_t *directory,ngx_log_t *log)
{ assert(directory==(void *)&state()->closed_dirs && log==&state()->log);state()->closed_dirs++;return NGX_OK; }
void __wrap_brix_vfs_writer_abort(brix_vfs_writer_t *writer)
{ assert(writer==(void *)&state()->aborted);state()->aborted++; }
ngx_int_t __wrap_ngx_ssl_shutdown(ngx_connection_t *c)
{ assert(c->ssl->no_wait_shutdown && c->ssl->no_send_shutdown);state()->ssl_closed++;return NGX_OK; }

void __wrap_brix_ftp_ev_vfs_ctx(ftp_ev_t *fc,const char *path,void *ctx)
{ assert(fc==&state()->fc && !strcmp(path,"/object"));memset(ctx,0,sizeof(brix_vfs_ctx_t)); }
brix_vfs_writer_t *__wrap_brix_vfs_writer_open(brix_vfs_ctx_t *ctx,unsigned flags,int verify,int *error)
{
    fixture *f=state();assert(ctx->declared_size==7 && flags==f->dc.flags && verify==f->dc.verify);f->writer_opens++;
    if(mode("writer-busy") || mode("writer-error")) { *error=mode("writer-busy")?EBUSY:EIO;return NULL; }
    return (void *)&f->aborted;
}
ngx_int_t __wrap_brix_vfs_writer_write(brix_vfs_writer_t *writer,const void *bytes,size_t length,off_t offset)
{
    fixture *f=state();assert(writer==(void *)&f->aborted && offset>=0 && (size_t)offset+length<sizeof(f->delivered));
    if(mode("writer-write")) { return NGX_ERROR; }
    memcpy(f->delivered+offset,bytes,length);f->delivered_len+=length;return NGX_OK;
}
ngx_int_t __wrap_brix_vfs_writer_commit(brix_vfs_writer_t *writer)
{
    fixture *f=state();assert(writer==(void *)&f->aborted);f->writer_commits++;
    assert(f->delivered_len==7 && !memcmp(f->delivered,"ABCDEFG",7));
    return mode("writer-commit")?NGX_ERROR:NGX_OK;
}
ngx_int_t __wrap_brix_vfs_unlink(brix_vfs_ctx_t *ctx)
{ assert(ctx && state()->aborted==1);state()->unlinks++;return NGX_OK; }
ngx_int_t __wrap_brix_ftp_ev_tls_begin(ftp_ev_t *fc,ngx_connection_t *c,ngx_pool_t **pool,
    int client,void (*done)(ngx_connection_t *))
{
    fixture *f=state();assert(fc==&f->fc && !client && !f->writer_opens);f->tls++;
    if(mode("tls-start")) { return NGX_ERROR; }
    *pool=ngx_create_pool(4096,&f->log);assert(*pool);c->ssl=&f->child_ssl;
    f->tls_done=done;f->tls_child=c;return NGX_AGAIN;
}
ngx_int_t __wrap_brix_ftp_ev_tls_verify(ftp_ev_t *fc,ngx_connection_t *c)
{ assert(fc==&state()->fc && c==state()->tls_child && !state()->writer_opens);return mode("tls-identity")?NGX_ERROR:NGX_OK; }
ngx_int_t __wrap_brix_ftp_ev_flush(ftp_ev_t *fc)
{ assert(fc==&state()->fc);return NGX_OK; }

static ssize_t block_recv(ngx_connection_t *c,u_char *bytes,size_t capacity)
{
    fixture *f=state();assert(c);f->receives++;
    if(mode("block-error")) { return NGX_ERROR; }
    if(mode("block-again") && f->receives==1) { return NGX_AGAIN; }
    size_t n=ngx_min(capacity,f->block_length-f->block_offset);
    if(mode("block-fragments")) { n=ngx_min(n,3); }
    memcpy(bytes,f->blocks+f->block_offset,n);f->block_offset+=n;return (ssize_t)n;
}
static void block(fixture *f,u_char descriptor,uint64_t length,uint64_t offset,const char *payload)
{
    assert(f->block_length+FTP_EB_HDR+7<sizeof(f->blocks));
    ftp_eb_pack(f->blocks+f->block_length,descriptor,length,offset);f->block_length+=FTP_EB_HDR;
    if(payload) { memcpy(f->blocks+f->block_length,payload,(size_t)length);f->block_length+=(size_t)length; }
}
static ngx_int_t receive_blocks(fixture *f)
{
    f->block_mode=1;f->control.pool=ngx_create_pool(4096,&f->log);assert(f->control.pool);
    f->dc.buf=ngx_pnalloc(f->control.pool,BRIX_FTP_EV_XFER_BUF);assert(f->dc.buf);
    f->dc.writing=1;f->dc.declared_size=7;f->dc.eb_eof_total=-1;
    f->listener=(ngx_connection_t){.fd=dup(f->peer_fd),.log=&f->log,
        .read=&f->listener_read,.write=&f->listener_write,.data=&f->dc};
    f->listener_read.data=&f->listener;f->listener_write.data=&f->listener;
    f->fc.pasv_fd=f->listener.fd;f->dc.lc=&f->listener;
    if(mode("timeout")) { f->listener_read.timedout=1; }
    brix_ftp_ev_eb_accept(&f->listener_read);
    if(f->tls_done && f->fc.dc) { f->tls_done(f->tls_child); }
    if(!f->fc.dc || !f->dc.eb_nconns) { return NGX_OK; }
    block(f,0,3,mode("hole")?1:0,"ABC");
    block(f,0,4,mode("overlap")?2:(mode("hole")?4:3),"DEFG");
    block(f,FTP_EB_EOF,0,1,NULL);block(f,FTP_EB_EOD,0,0,NULL);
    if(mode("block-overflow")) { ftp_eb_pack(f->blocks,0,UINT64_MAX,0); }
    if(mode("short-header")) { f->block_length=3; }
    if(mode("short-payload")) { f->block_length=FTP_EB_HDR+1; }
    ngx_connection_t *child=&f->slots[0];child->recv=block_recv;
    if(mode("child-timeout")) { child->read->timedout=1; }
    if(child->read->posted) { ngx_delete_posted_event(child->read); }
    child->read->handler(child->read);
    if(mode("block-again") && f->fc.dc) { child->read->handler(child->read); }
    assert(!f->fc.dc);return NGX_OK;
}

static ssize_t sink(ngx_connection_t *c,u_char *data,size_t length)
{
    fixture *f=state();assert(c==f->dc.dconn);f->sends++;
    if(mode("send-error")) { return NGX_ERROR; }
    if(mode("send-zero")) { return 0; }
    if(mode("write-arm") || (mode("again") && f->sends==1)) { return NGX_AGAIN; }
    if(mode("short") && length>3) { length=3; }
    assert(f->delivered_len+length<=sizeof(f->delivered));
    memcpy(f->delivered+f->delivered_len,data,length);f->delivered_len+=length;return (ssize_t)length;
}
static ngx_int_t open_channel(fixture *f,const char *operation)
{
    f->fc.active=!strcmp(operation,"active");
    if(f->fc.active) { f->fc.active_sa=(struct sockaddr_in){.sin_family=AF_INET,.sin_port=htons(45678),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)}; }
    else { f->fc.pasv_fd=mode("no-listener")?-1:dup(f->peer_fd); }
    ngx_int_t rc=brix_ftp_ev_data_open(&f->dc);assert(!f->fc.active);
    if(rc!=NGX_OK) { return rc; }
    ngx_event_t *event=f->dc.lc?f->dc.lc->read:f->dc.dconn->write;
    if(mode("timeout")) { event->timedout=1; }
    event->handler(event);return rc;
}
static ngx_int_t drain(fixture *f)
{
    f->dc.dconn=__wrap_ngx_get_connection(dup(f->peer_fd),&f->log);assert(f->dc.dconn);
    f->dc.dconn->data=&f->dc;f->dc.dconn->send=sink;
    f->dc.buf=(u_char *)"byte-exact-data";f->dc.buf_len=strlen((char *)f->dc.buf);
    if(mode("empty")) { f->dc.buf_len=0; }
    ngx_event_t *event=f->dc.dconn->write;
    ngx_add_timer(event,1000);if(mode("timeout")) { event->timedout=1; }
    ngx_int_t rc=brix_ftp_ev_send_drain(event);
    if(rc==NGX_AGAIN) { assert(event->timer_set && f->dc.buf_pos==0);rc=brix_ftp_ev_send_drain(event); }
    if(rc==NGX_OK) { assert(f->delivered_len==f->dc.buf_len && !memcmp(f->delivered,f->dc.buf,f->dc.buf_len)); }
    return rc;
}
int main(int argc,char **argv)
{
    assert(argc==4);fixture f={0};ngx_cycle=&f.cycle;f.mode=argv[2];f.active_fd=-1;
    ngx_open_file_t log_file={.fd=STDERR_FILENO};f.log=(ngx_log_t){.log_level=NGX_LOG_ERR,.file=&log_file};
    f.cycle.log=&f.log;ngx_time_init();ngx_os_argv=argv;assert(ngx_os_init(&f.log)==NGX_OK);
    assert(ngx_event_timer_init(&f.log)==NGX_OK);ngx_queue_init(&ngx_posted_events);
    f.control=(ngx_connection_t){.fd=socket(AF_INET,SOCK_STREAM,0),.log=&f.log};assert(f.control.fd>=0);
    int pair[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);f.peer_fd=pair[0];
    f.fc.c=&f.control;f.fc.prot=argv[3][0];f.fc.pasv_fd=-1;f.fc.dc=&f.dc;f.fc.state=FTP_EV_ST_XFER;
    f.dc.fc=&f.fc;strcpy(f.dc.abs,"/object");f.armed=1;ngx_int_t rc;
    if(!strcmp(argv[1],"blocks")) { rc=receive_blocks(&f); }
    else if(!strcmp(argv[1],"drain")) { rc=drain(&f); }
    else if(!strcmp(argv[1],"finish")) {
        f.dc.fh=(void *)&f.closed_files;f.dc.dh=(void *)&f.closed_dirs;f.dc.writing=1;
        if(mode("writer")) { f.dc.writer=(void *)&f.aborted; }
        f.dc.dpool=ngx_create_pool(4096,&f.log);assert(f.dc.dpool);
        f.dc.dconn=__wrap_ngx_get_connection(dup(f.peer_fd),&f.log);
        ngx_ssl_connection_t ssl={0};f.dc.dconn->ssl=&ssl;
        if(mode("specific")) { f.dc.fail_reply="450 File busy\r\n"; }
        rc=(mode("failure") || mode("specific"))?NGX_ERROR:NGX_OK;
        brix_ftp_ev_data_finish(&f.dc,rc);
        assert(f.closed_files==1 && f.closed_dirs==1 && f.ssl_closed==1 && !f.dc.dpool);
        assert(f.aborted==mode("writer"));
    } else { rc=open_channel(&f,argv[1]); }
    printf("%ld %d %d %d %d %d %d %d %d %zu %d %d %d %d\n",(long)rc,f.ready,f.tls,f.resumed,
        f.metrics,f.notes,f.reply_code,f.accepts,f.dc.lc && f.dc.lc->read->posted,f.delivered_len,
        f.writer_opens,f.writer_commits,f.aborted,f.unlinks);
    if(f.fc.dc && (f.dc.lc || f.dc.dconn)) { brix_ftp_ev_data_finish(&f.dc,NGX_ERROR); }
    assert(f.resumed<=1 && f.metrics==f.resumed && !f.dc.dconn && !f.dc.lc);
    if(f.active_fd>=0) { assert(fcntl(f.active_fd,F_GETFD)==-1 && errno==EBADF); }
    for(int i=0;i<f.accepts;i++) { assert(fcntl(f.accepted[i],F_GETFD)==-1 && errno==EBADF); }
    close(pair[0]);close(pair[1]);close(f.control.fd);
    if(f.control.pool) { ngx_destroy_pool(f.control.pool); }return 0;
}

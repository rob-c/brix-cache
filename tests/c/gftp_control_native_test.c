/* Exercise real FTP framing with finite socket and GSI-provider outcomes. */
#include "fs/backend/gsiftp/gftp_client.h"
#include "fs/backend/gsiftp/gftp_gsi.h"
#include "net/dns/dns.h"
#include <assert.h>
#include <poll.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    char incoming[70000], outgoing[16000];
    size_t offset, length, sent;
    int polls, reads, writes, sockets, connects, closes, auth, freed, alloc_fail;
    brix_dns_policy_t dns;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }

int __wrap_poll(struct pollfd *p,nfds_t count,int timeout)
{
    fixture *f=state();assert(count==1 && timeout>0 && p->fd==91);f->polls++;
    if(mode("poll-interrupt") && f->polls==1) { errno=EINTR;return -1; }
    if(mode("timeout")) { return 0; }
    if(mode("poll-error")) { errno=EBADF;return -1; }
    p->revents=mode("poll-hangup")?POLLHUP:p->events;return 1;
}
ssize_t __wrap_recv(int fd,void *buffer,size_t cap,int flags)
{
    fixture *f=state();assert(fd==91 && !flags);f->reads++;
    if(mode("read-error")) { errno=ECONNABORTED;return -1; }
    if(f->reads==1 && (mode("read-interrupt") || mode("read-again"))) {
        errno=mode("read-again")?EAGAIN:EINTR;return -1;
    }
    size_t n=ngx_min(cap,f->length-f->offset);
    if(mode("fragmented")) { n=ngx_min(n,2); }
    memcpy(buffer,f->incoming+f->offset,n);f->offset+=n;return (ssize_t)n;
}
ssize_t __wrap_send(int fd,const void *buffer,size_t length,int flags)
{
    fixture *f=state();assert(fd==91 && flags==MSG_NOSIGNAL);f->writes++;
    if(mode("write-zero")) { return 0; }
    if(mode("write-error")) { errno=EPIPE;return -1; }
    if(f->writes==1 && (mode("write-interrupt") || mode("write-again"))) {
        errno=mode("write-again")?EAGAIN:EINTR;return -1;
    }
    if(mode("short-write")) { length=ngx_min(length,2); }
    assert(f->sent+length<sizeof(f->outgoing));
    memcpy(f->outgoing+f->sent,buffer,length);f->sent+=length;return (ssize_t)length;
}
int __wrap_socket(int family,int type,int protocol)
{
    fixture *f=state();assert(family==AF_INET && type==SOCK_STREAM && !protocol);f->sockets++;
    if(mode("socket-error") || (mode("socket-retry") && f->sockets==1)) { errno=EMFILE;return -1; }
    return 91;
}
int __real_close(int);
int __wrap_close(int fd)
{ if(fd!=91) { return __real_close(fd); }state()->closes++;return 0; }
int __real_fcntl64(int,int,...);
int __wrap_fcntl64(int fd,int command,...)
{
    long argument=0;
    if(command!=F_GETFL && command!=F_GETFD) {
        va_list args;va_start(args,command);argument=va_arg(args,long);va_end(args);
    }
    if(fd!=91) { return __real_fcntl64(fd,command,argument); }
    assert(command==F_GETFL || command==F_SETFL);return 0;
}
int __wrap_connect(int fd,const struct sockaddr *address,socklen_t len)
{
    fixture *f=state();const struct sockaddr_in *in=(const void *)address;
    assert(fd==91 && len==sizeof(*in) && in->sin_port==htons(2811));f->connects++;
    if(mode("connect-error") || (mode("connect-retry") && f->connects==1)) { errno=ECONNREFUSED;return -1; }
    return 0;
}
ngx_uint_t __wrap_brix_dns_resolve_sync(const brix_dns_policy_t *policy,const char *host,
    in_port_t port,brix_af_policy_t af,int type,brix_dns_addr_t *addresses,
    ngx_uint_t cap,char *error,size_t error_cap)
{
    fixture *f=state();assert(policy==&f->dns && !strcmp(host,"origin.test") && port==2811);
    assert(af==BRIX_AF_AUTO && type==SOCK_STREAM && cap>=2 && error_cap>8);
    if(mode("dns-error")) { strcpy(error,"no answer");return 0; }
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(port)};
    for(int i=0;i<2;i++) { memcpy(&addresses[i].ss,&address,sizeof(address));addresses[i].len=sizeof(address); }
    return 2;
}
int __wrap_getpeername(int fd,struct sockaddr *address,socklen_t *length)
{
    assert(fd==91);
    if(mode("peer-error")) { errno=ENOTCONN;return -1; }
    if(mode("peer-short")) { *length=0;return 0; }
    if(mode("peer-other")) { address->sa_family=AF_UNIX;*length=sizeof(*address);return 0; }
    if(mode("ipv6")) {
        struct sockaddr_in6 in={.sin6_family=AF_INET6};assert(inet_pton(AF_INET6,"2001:db8::1",&in.sin6_addr)==1);
        memcpy(address,&in,sizeof(in));*length=sizeof(in);return 0;
    }
    struct sockaddr_in in={.sin_family=AF_INET,.sin_addr.s_addr=htonl(0xc0000201)};
    memcpy(address,&in,sizeof(in));*length=sizeof(in);return 0;
}
int __wrap_gftp_authenticate(gftp_session_t *s,const gftp_session_cfg_t *cfg)
{
    fixture *f=state();assert(cfg->dns==&f->dns && s->want_mode==GFTP_DMODE_E);
    assert(s->want_prot==GFTP_DPROT_P && s->want_streams==3);
    assert(s->proxy_path==cfg->proxy_path && s->ca_dir==cfg->ca_dir);f->auth++;
    s->gsi=(void *)&f->auth;return mode("auth-error")?-1:0;
}
void __wrap_gftp_gsi_free(gftp_gsi_t *gsi)
{ if(gsi) { assert(gsi==(void *)&state()->auth);state()->freed++; } }
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n)
{ if(ngx_cycle && state()->alloc_fail) { state()->alloc_fail=0;return NULL; }return __real_malloc(n); }
int __wrap_gftp_gsi_wrap(gftp_gsi_t *gsi,const void *input,size_t len,
    uint8_t **output,size_t *output_len,gftp_session_t *s)
{
    (void)gsi;assert(len==6 && !memcmp(input,"NOOP\r\n",len));
    if(mode("wrap-error")) { gftp_set_error(s,EACCES,"wrap refused");return -1; }
    *output=malloc(len);assert(*output);memcpy(*output,input,len);*output_len=len;return 0;
}
char *__real_gftp_base64_encode(const uint8_t *,size_t);
char *__wrap_gftp_base64_encode(const uint8_t *data,size_t len)
{
    if(mode("encode-error")) { return NULL; }
    char *encoded=__real_gftp_base64_encode(data,len);
    if(mode("frame-alloc")) { state()->alloc_fail=1; }return encoded;
}
int __wrap_gftp_gsi_unwrap(gftp_gsi_t *gsi,const void *input,size_t len,
    uint8_t **output,size_t *output_len,gftp_session_t *s)
{
    (void)gsi;
    if(mode("unwrap-error")) { gftp_set_error(s,EACCES,"unwrap refused");return -1; }
    *output=malloc(len);assert(*output);memcpy(*output,input,len);*output_len=len;return 0;
}
static void prepare_reply(fixture *f,gftp_session_t *s,const char *text)
{
    if(mode("secure") || mode("unwrap-error") || mode("secure-malformed") || mode("frame-alloc") || mode("encode-error") || mode("wrap-error")) {
        const char *plain=mode("secure-malformed")?"incomplete":text;
        char *encoded=__real_gftp_base64_encode((const uint8_t *)plain,strlen(plain));assert(encoded);
        snprintf(f->incoming,sizeof(f->incoming),"632 %s\r\n",encoded);free(encoded);s->secure=1;
    } else { snprintf(f->incoming,sizeof(f->incoming),"%s",text); }
    if(mode("unprotected")) { s->secure=1; }
    if(mode("bad-base64")) { strcpy(f->incoming,"631 %%%\r\n");s->secure=1; }
    if(mode("overflow")) { memset(f->incoming,'x',sizeof(f->incoming)-1);memcpy(f->incoming,"220-",4); }
    if(mode("eof")) { f->incoming[0]=0; }
    f->length=strlen(f->incoming);
}
int main(int argc,char **argv)
{
    assert(argc==4);fixture f={0};ngx_cycle=&f.cycle;f.mode=argv[2];
    gftp_session_t s={.fd=91,.timeout_ms=1234};prepare_reply(&f,&s,argv[3]);
    int rc;
    if(!strcmp(argv[1],"open")) {
        gftp_session_cfg_t cfg={.host="origin.test",.port=2811,.timeout_ms=1234,
            .dns=&f.dns,.mode=GFTP_DMODE_E,.prot=GFTP_DPROT_P,.streams=3,
            .proxy_path="proxy",.ca_dir="trust"};
        rc=gftp_session_open(&s,&cfg);
        if(!rc && !strncmp(f.mode,"peer-",5)) { assert(!s.peer_ip[0]); }
        else if(!rc) { assert(!strcmp(s.peer_ip,mode("ipv6")?"2001:db8::1":"192.0.2.1")); }
        gftp_session_close(&s);gftp_session_close(&s);gftp_session_close(NULL);
        assert(s.fd==-1 && !s.gsi && !s.secure);
    } else if(!strcmp(argv[1],"reply")) { rc=gftp_read_reply(&s); }
    else {
        char huge[5000];memset(huge,'x',sizeof(huge)-1);huge[sizeof(huge)-1]=0;
        const char *command=mode("long-command")?huge:"NOOP";
        rc=!strcmp(argv[1],"expect")?gftp_expect(&s,200,299,"%s",command):gftp_command(&s,"%s",command);
        if(!rc) { assert(!strcmp(f.outgoing,s.secure?"ENC Tk9PUA0K\r\n":"NOOP\r\n")); }
    }
    int saved_errno=rc<0?errno:0;
    printf("%d %d %d %zu %zu %d %d %d %d\n",rc,saved_errno,s.code,f.sent,
        strlen(s.cont),s.cont_truncated,f.closes,f.auth,f.freed);
    gftp_set_error(NULL,EINVAL,"no session");assert(errno==EINVAL);ngx_cycle=NULL;return 0;
}

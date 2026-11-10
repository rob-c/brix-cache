/* Real async file handles over a finite transport: wire identity, retry and codecs. */
#include "core/aio/aio.h"
#include "core/compat/codec_core.h"
#include "protocols/root/protocol/protocol.h"
#include "protocols/root/protocol/frame_hdr.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *mode,*operation;
    int writable,force,posc,armed,opens,calls,backs,closes,syncs,codec;
    uint64_t clock;
    uint8_t handle[4];
} fixture;
static fixture *state(void)
{ const char *p=getenv("BRIX_AIO_HANDLE_FIXTURE");return p?(fixture *)(uintptr_t)strtoull(p,NULL,16):NULL; }
static int mode(const char *m) { return state() && state()->armed && !strcmp(state()->mode,m); }
void *__real_calloc(size_t,size_t);
void *__wrap_calloc(size_t n,size_t s) { return mode("owner-oom")?NULL:__real_calloc(n,s); }
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n) { return mode("payload-oom")?NULL:__real_malloc(n); }
int __real_brix_codec_available(brix_codec_id_t);
int __wrap_brix_codec_available(brix_codec_id_t c)
{ return mode("unavailable")?0:__real_brix_codec_available(c); }
uint8_t *__real_brix_deflate_frame(uint8_t,const void *,size_t,size_t *,brix_status *);
uint8_t *__wrap_brix_deflate_frame(uint8_t c,const void *p,size_t n,size_t *out,brix_status *st)
{
    if(mode("compress-error")) { brix_status_set(st,XRDC_EPROTO,0,"finite codec refusal");return NULL; }
    return __real_brix_deflate_frame(c,p,n,out,st);
}
uint64_t __wrap_brix_mono_ns(void) { state()->clock+=1000000;return state()->clock; }
void __wrap_brix_backoff_sleep_fast(unsigned attempt)
{ assert(attempt==(unsigned)state()->backs++);state()->clock+=30000000;assert(state()->backs<8); }
static int refuse(brix_status *st,int code)
{ brix_status_set(st,code,0,"finite transport refusal");return -1; }
static void reply(uint8_t **body,uint32_t *len,const void *data,size_t n)
{ *body=__real_malloc(n?n:1);assert(*body);memcpy(*body,data,n);*len=(uint32_t)n; }
static int open_reply(const ClientRequestHdr *hdr,const void *payload,uint32_t n,
    const brix_aio_opts *opts,uint8_t **body,uint32_t *length,brix_status *st)
{
    fixture *f=state();f->opens++;xrdw_open_req_t r;assert(!xrdw_open_req_unpack(hdr->body,&r));
    const char *path=f->posc?"/fixture?opaque=value":"/fixture";
    assert(n==strlen(path) && !memcmp(payload,path,n));
    unsigned expected=f->writable?kXR_open_updt|kXR_mkpath:kXR_open_read;
    if(f->writable) {
        if(f->posc) { expected|=kXR_posc; }
        if(f->opens==1 && f->force==1) { expected|=kXR_delete; }
        if(f->opens==1 && f->force==0) { expected|=kXR_new; }
    }
    assert(r.options==expected && r.mode==(f->writable?0644:0));
    assert(opts->deadline_ms==100 && opts->max_retries==3 && opts->retry_safe==1);
    if(mode("open-error")) { return refuse(st,kXR_NotAuthorized); }
    if(f->opens>1 && (mode("reopen-deadline") || mode("reopen-permanent") ||
       (mode("reopen-once") && f->opens==2))) {
        return refuse(st,mode("reopen-permanent")?kXR_NotAuthorized:XRDC_ESOCK);
    }
    uint8_t wire[12]={0};memset(f->handle,f->opens,4);memcpy(wire,f->handle,4);
    xrd_put_u32_be(wire+4,mode("legacy-codec")?0:BRIX_INLINE_CMP_MAGIC);wire[8]=(uint8_t)f->codec;
    reply(body,length,wire,mode("short-open")?3:12);return 0;
}
static int data_refusal(brix_status *st)
{
    fixture *f=state();f->calls++;
    if(mode("permanent")) { return refuse(st,kXR_NotAuthorized); }
    if(mode("deadline") || (f->calls==1 && (mode("transient") || mode("stale") ||
       !strncmp(f->mode,"reopen-",7)))) {
        return refuse(st,mode("stale")?kXR_FileNotOpen:XRDC_ESOCK);
    }
    return 0;
}
int __wrap_brix_aio_call_ex(brix_aconn *ac,const void *header,const void *payload,uint32_t n,
    const brix_aio_opts *opts,uint16_t *status,uint8_t **body,uint32_t *length,brix_status *st)
{
    fixture *f=state();assert(ac==(brix_aconn *)f);const ClientRequestHdr *hdr=header;
    unsigned op=xrd_get_u16_be((const uint8_t *)header+2);*status=kXR_ok;
    if(op==kXR_open) { return open_reply(hdr,payload,n,opts,body,length,st); }
    assert(opts->deadline_ms==100 && opts->max_retries==0 && opts->retry_safe==0);
    if(op==kXR_read) {
        xrdw_read_req_t r;assert(!xrdw_read_req_unpack(hdr->body,&r));
        assert(!memcmp(r.fhandle,f->handle,4) && r.offset==123 && r.rlen==64 && !payload && !n);
    } else if(op==kXR_write) {
        xrdw_write_req_t r;assert(!xrdw_write_req_unpack(hdr->body,&r));
        assert(!memcmp(r.fhandle,f->handle,4) && r.offset==123 && r.pathid==0);
        if(f->codec && !mode("legacy-codec")) {
            char plain[64];assert(brix_inflate_frame((uint8_t)f->codec,payload,n,plain,sizeof(plain),st)==7);
            assert(!memcmp(plain,"payload",7));
        } else { assert(n==7 && !memcmp(payload,"payload",7)); }
    } else {
        assert(op==kXR_stat);xrdw_stat_req_t r;assert(!xrdw_stat_req_unpack(hdr->body,&r));
        assert(!memcmp(r.fhandle,f->handle,4) && !payload && !n);
    }
    if(data_refusal(st)) { return -1; }
    if(op==kXR_write) { return 0; }
    if(op==kXR_stat) {
        char large[1024]={0};const char *line=mode("bad-stat")?"hostile":"42 987 0 123";
        if(mode("long-stat")) { reply(body,length,large,sizeof(large)); }
        else { reply(body,length,line,mode("empty-stat")?0:strlen(line)); }
        return 0;
    }
    if(f->codec && !mode("legacy-codec") && !mode("corrupt-frame")) {
        size_t len;*body=__real_brix_deflate_frame((uint8_t)f->codec,"payload",7,&len,st);
        assert(*body);*length=(uint32_t)len;return 0;
    }
    reply(body,length,"payload",mode("empty-read")?0:7);return 0;
}
int __wrap_brix_aio_call(brix_aconn *ac,const void *header,const void *payload,uint32_t n,
    uint16_t *status,uint8_t **body,uint32_t *length,int deadline,brix_status *st)
{
    fixture *f=state();assert(ac==(brix_aconn *)f && !payload && !n && !body && !length);
    const ClientRequestHdr *hdr=header;unsigned op=xrd_get_u16_be((const uint8_t *)header+2);
    if(op==kXR_sync) {
        xrdw_sync_req_t r;assert(!xrdw_sync_req_unpack(hdr->body,&r));
        assert(!memcmp(r.fhandle,f->handle,4) && deadline==100);f->syncs++;
    } else {
        assert(op==kXR_close);xrdw_close_req_t r;assert(!xrdw_close_req_unpack(hdr->body,&r));
        assert(!memcmp(r.fhandle,f->handle,4) && deadline==5000);f->closes++;
    }
    *status=kXR_ok;return mode("sync-error")?refuse(st,XRDC_ESOCK):0;
}
int main(int argc,char **argv)
{
    assert(argc==6);fixture f={.mode=argv[2],.operation=argv[1],.force=atoi(argv[3]),
        .posc=atoi(argv[4]),.codec=atoi(argv[5])};f.writable=!strcmp(f.operation,"write");
    char address[32];snprintf(address,sizeof(address),"%llx",(unsigned long long)(uintptr_t)&f);
    assert(!setenv("BRIX_AIO_HANDLE_FIXTURE",address,1));f.armed=1;brix_status st={0};
    brix_mfile *file=brix_mfile_open((brix_aconn *)&f,"/fixture",f.writable,f.force,f.posc,
        f.posc?"opaque=value":NULL,100,3,&st);
    if(!file) { assert(st.kxr);printf("OPEN-REFUSED %d %d\n",st.kxr,f.opens); }
    else {
        char out[64]={0};brix_statinfo info={0};int rc;
        if(!strcmp(f.operation,"read")) {
            rc=(int)brix_mfile_pread(file,123,out,sizeof(out),&st);
            if(rc>0) { assert(rc==7 && !memcmp(out,"payload",7)); }
        } else if(!strcmp(f.operation,"write")) { rc=brix_mfile_pwrite(file,123,"payload",7,&st); }
        else { rc=brix_mfile_stat(file,&info,&st);if(!rc) { assert(info.id==42 && info.size==987); } }
        int code=st.kxr;const char *original=f.mode;
        /* A failed reopen leaves no handle; a later sync must acquire one or report refusal. */
        if(!strcmp(original,"reopen-deadline")) { f.mode="normal"; }
        int synced=brix_mfile_sync(file,&st);int closed=brix_mfile_close(file,&st);
        printf("RESULT %d %d %d %d %d %d %d %d %d\n",rc,code,f.opens,f.calls,f.backs,synced,closed,f.syncs,f.closes);
    }
    f.armed=0;assert(!unsetenv("BRIX_AIO_HANDLE_FIXTURE"));return 0;
}

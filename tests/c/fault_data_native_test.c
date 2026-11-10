/* Real fault kernels with finite I/O, timing and randomness providers. */
#include "brix_fault_proxy_state.h"
#include "brix_fault_http.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#undef main

typedef struct {
    const char *mode;
    unsigned char bytes[4096];
    size_t length;
    unsigned long slept;
    int writes, sleeps, random;
} fixture;

static fixture *state(void)
{
    const char *value=getenv("BRIX_FAULT_DATA_TEST_STATE");
    return value?(fixture *)(uintptr_t)strtoull(value,NULL,16):NULL;
}
static int mode(const char *name) { return !strcmp(state()->mode,name); }
ssize_t __real_write(int,const void *,size_t);
ssize_t __wrap_write(int fd,const void *bytes,size_t length)
{
    fixture *f=state();
    if(!f || fd!=90) { return __real_write(fd,bytes,length); }
    f->writes++;
    if(mode("write-error")) { errno=EIO;return -1; }
    if(mode("interrupted") && f->writes==1) { errno=EINTR;return -1; }
    if(mode("short") && length>2) { length=2; }
    assert(f->length+length<=sizeof(f->bytes));
    memcpy(f->bytes+f->length,bytes,length);f->length+=length;
    return (ssize_t)length;
}
int __wrap_usleep(useconds_t duration)
{
    fixture *f=state();assert(f && f->sleeps<32);
    f->slept+=duration;f->sleeps++;return 0;
}
int __wrap_rand_r(unsigned *seed)
{
    (void)seed;fixture *f=state();assert(f && f->random<512);f->random++;
    return mode("normal-jitter")?50000:0;
}

/* Pacing budgets and mutation counts describe delivered logical bytes. */
static void forwarding(void)
{
    fixture *f=state();unsigned seed=7;unsigned long count=0,total=0;
    char bytes[]="abcdefg";g_up.chunk_bytes=3;
    if(mode("drip")) { g_up.drip_bytes=2;g_up.drip_ms=3;g_up.latency_ms=5; }
    if(mode("duplicate")) { g_up.dup_ppm=1000000; }
    if(mode("corrupt")) { g_up.corrupt_ppm=1000000; }
    if(mode("lossy") || mode("one-shot")) { g_up.lossy_ppm=1000000; }
    if(mode("one-shot")) { g_one_shot=1; }
    if(mode("blocked")) { g_blocked=1; }
    if(mode("epoch")) { g_drop_epoch++; }
    if(mode("truncate")) { g_up.truncate_at=4; }
    if(mode("already-cut")) { g_up.truncate_at=4;count=4; }
    int rc=forward_faulted(90,bytes,7,0,&g_up,&seed,&count,&total);
    printf("%d %lu %lu %lu %lu %lu %d %lu %zu\n",rc,count,total,C.severs,
        C.corrupt,C.dups,f->writes,f->slept,f->length);
    for(size_t i=0;i<f->length;i++) { printf("%02x",f->bytes[i]); }
    putchar('\n');
    if(mode("one-shot")) { assert(g_up.lossy_ppm==0 && g_one_shot==0); }
}

static void pacing(void)
{
    lever_t lever={0};unsigned seed=1;unsigned long sent=0;
    if(mode("uniform")) { lever.jitter_ms=7; }
    if(mode("normal-jitter")) { lever.jitter_ms=7;lever.lat_dist=1;lever.lat_sigma_ms=2; }
    if(mode("negative-jitter")) { lever.jitter_ms=1;lever.lat_dist=1;lever.lat_sigma_ms=2; }
    if(mode("reorder")) { lever.reorder_ppm=1000000;lever.reorder_ms=3; }
    if(mode("rate") || mode("burst") || mode("spent-burst")) {
        lever.rate_kbps=1;
        if(!mode("rate")) { lever.burst_bytes=100; }
        if(mode("spent-burst")) { sent=100; }
    }
    fault_delays(1024,&seed,&lever,sent);
    printf("%d %lu %d\n",state()->sleeps,state()->slept,state()->random);
}

static void replaying(void)
{
    fixture *f=state();unsigned char a[]="A",b[]="BC",c[]="D";
    fp_replay_rec records[]={{1,1,a,1},{0,10,a,1},{0,15,b,2},{0,70015,c,1}};
    g_replay_store=(fp_replay_store){records,4};
    if(mode("up")) { g_replay_updir=1; }
    if(mode("blocked")) { g_blocked=1; }
    if(mode("epoch")) { g_drop_epoch=1; }
    replay_to_client(90,0);
    assert(C.replayed==f->length);
    printf("%lu %d %lu %zu\n",C.replayed,f->writes,f->slept,f->length);
    for(size_t i=0;i<f->length;i++) { printf("%02x",f->bytes[i]); }
    putchar('\n');g_replay_store=(fp_replay_store){0};
}

static void http_config(fp_http_cfg *config)
{
    if(mode("added")) { config->add_cl=1;config->cl_val=9;config->add_te=1;config->dup_cl=1;config->dup_cl_val=3; }
    if(mode("injected")) {
        memcpy(config->inj_name,"X-Test",6);config->inj_name_len=6;
        memcpy(config->inj_val,"a\0b",3);config->inj_val_len=3;
        memcpy(config->append,"\0TAIL",5);config->append_len=5;
    }
    if(mode("strip")) { memcpy(config->strip_name,"X-Remove",8);config->strip_len=8; }
    if(mode("lf")) { config->naked_lf=1; }
    if(!strncmp(state()->mode,"obfuscate",9)) { config->obfuscate_te=atoi(state()->mode+9); }
}

/* Every bounded output keeps its canary and is a prefix of the full rewrite. */
static void http_rewrite(const char *input,size_t capacity)
{
    unsigned char output[4096];memset(output,0xa5,sizeof(output));assert(capacity<sizeof(output));
    fp_http_cfg config={0};fp_http_stats stats={0};int applied=-1;http_config(&config);
    size_t n=fp_http_rewrite((const unsigned char *)input,strlen(input),output,capacity,&config,&stats,&applied);
    assert(n<=capacity && output[capacity]==0xa5);
    printf("%d %d %lu %lu %lu %lu\n",applied,fp_http_active(&config),
        (unsigned long)stats.msgs,(unsigned long)stats.headers_added,
        (unsigned long)stats.te_obf,(unsigned long)stats.appended);
    for(size_t i=0;i<n;i++) { printf("%02x",output[i]); }
    putchar('\n');
}

static void holding(const char *input,long threshold,int partial)
{
    fp_http_cfg config={0};size_t release=9999;
    int body=mode("body"),rc;
    config.hold_thresh=threshold;config.body_hold_thresh=threshold;
    config.hold_partial=partial;config.body_hold_partial=partial;
    assert(fp_http_hold_active(&config)==(threshold>0));
    assert(fp_http_body_hold_active(&config)==(threshold>0));
    if(body) { rc=fp_http_body_hold_decide(&config,(const unsigned char *)input,strlen(input),&release); }
    else { rc=fp_http_hold_decide(&config,(const unsigned char *)input,strlen(input),&release); }
    printf("%d %zu\n",rc,release);
}

int main(int argc,char **argv)
{
    assert(argc>=3);fixture f={.mode=argv[2]};char pointer[32];
    snprintf(pointer,sizeof(pointer),"%llx",(unsigned long long)(uintptr_t)&f);
    assert(!setenv("BRIX_FAULT_DATA_TEST_STATE",pointer,1));clear_all();
    if(!strcmp(argv[1],"forward")) { forwarding(); }
    else if(!strcmp(argv[1],"pace")) { pacing(); }
    else if(!strcmp(argv[1],"replay")) { replaying(); }
    else if(!strcmp(argv[1],"http")) { assert(argc==5);http_rewrite(argv[3],strtoul(argv[4],NULL,10)); }
    else { assert(argc==6 && !strcmp(argv[1],"hold"));holding(argv[3],strtol(argv[4],NULL,10),atoi(argv[5])); }
    return 0;
}

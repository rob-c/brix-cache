/* Real remote/S3 staging, signing and multipart paths with a scripted origin. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "core/compat/crypto.h"
#include "native_alloc_fail.h"

typedef struct {
    const char *mode, *fail_phase, *identity;
    int status, create, part, complete, put, aborted, freed, failed;
} fixture;

static int phase(fixture *f, const char *method, const char *path, const char **name) {
    if (strstr(path, "?uploads")) { *name="create"; return ++f->create; }
    if (strstr(path, "?partNumber=")) { *name="part"; return ++f->part; }
    if (strcmp(method,"DELETE") == 0) { *name="abort"; return ++f->aborted; }
    if (strcmp(method,"POST") == 0) { *name="complete"; return ++f->complete; }
    *name="put"; return ++f->put;
}
static int request(void *context, const char *host, int port, int tls,
    const char *method, const char *path, const char *headers, const void *body,
    size_t length, int timeout, brix_s3_resp_t *response, char *error, size_t capacity) {
    fixture *f=context; const char *name;
    (void) timeout; (void) error; (void) capacity;
    assert(strcmp(host,"origin.test") == 0 && port == 443 && tls);
    assert(strncmp(path,"/bucket/object",14) == 0);
    int call=phase(f,method,path,&name);
    printf("REQUEST %s %s bytes=%zu\n%s",method,path,length,headers);
    const char *access=strcmp(f->identity,"user") == 0 ? "Credential=caller/" : "Credential=service/";
    assert(strstr(headers,access));
    if (strcmp(f->identity,"user") == 0) { assert(strstr(headers,"x-amz-security-token: session")); }
    if (strcmp(name,"complete") == 0) {
        assert(length && strstr(body,"<ETag>\"part-tag\"</ETag>"));
    }
    if (strcmp(name,f->fail_phase) == 0
        && !(strcmp(f->mode,"lost-once") == 0 && call > 1)) {
        if (f->status < 0) { f->failed++; return -1; }
        response->status=f->status;
    } else { response->status=200; }
    response->opaque=f;
    return 0;
}
static int header(const brix_s3_resp_t *response, const char *name, char *out, size_t cap) {
    fixture *f=response->opaque; assert(strcmp(name,"ETag") == 0);
    if (strcmp(f->mode,"no-etag") == 0) { return -1; }
    snprintf(out,cap,"\"part-tag\""); return 0;
}
static const void *response_body(const brix_s3_resp_t *response, size_t *length) {
    fixture *f=response->opaque;
    const char *body="<UploadId>fixture-upload</UploadId>";
    if (strcmp(f->mode,"xml-empty") == 0) { body="<UploadId></UploadId>"; }
    if (strcmp(f->mode,"xml-unclosed") == 0) { body="<UploadId>broken"; }
    if (strcmp(f->mode,"xml-missing") == 0) { body="<Other>no-id</Other>"; }
    if (strcmp(f->mode,"xml-null") == 0) { *length=0; return NULL; }
    *length=strlen(body); return body;
}
static void release(brix_s3_resp_t *response) {
    fixture *f=response->opaque; f->freed++;
}
static brix_sd_staged_t *open_handle(brix_sd_instance_t *inst, const char *identity,
    off_t declared, int *error) {
    brix_sd_cred_t cred={0};
    char access[]="caller", secret[]="caller-secret", region[]="region", session[]="session";
    cred.fallback_deny=strcmp(identity,"deny") == 0;
    if (strcmp(identity,"user") == 0) {
        cred.s3_ak=access; cred.s3_sk=secret; cred.s3_region=region; cred.s3_session=session;
    }
    brix_sd_staged_t *h=strcmp(identity,"service") == 0
        ? inst->driver->staged_open(inst,"/object",0644,declared,error)
        : inst->driver->staged_open_cred(inst,"/object",0644,declared,&cred,error);
    memset(access,'x',sizeof(access)-1); memset(secret,'x',sizeof(secret)-1);
    memset(region,'x',sizeof(region)-1); memset(session,'x',sizeof(session)-1);
    return h;
}
static void arm(const char *selection, const char *stage) {
    size_t len=strlen(stage);
    if (strncmp(selection,stage,len) != 0 || selection[len] != ':') { return; }
    char kind[20]; unsigned skip;
    assert(sscanf(selection+len+1,"%19[^:]:%u",kind,&skip) == 2);
    native_alloc_arm(kind,skip);
}
static int exercise(brix_sd_instance_t *inst, char **argv) {
    int expected=atoi(argv[9]), error=0;
    arm(argv[8],"open");
    brix_sd_staged_t *h=open_handle(inst,argv[4],strtoll(argv[5],NULL,10),&error);
    native_alloc_disarm();
    if (!h) { assert(error == expected); return -1; }
    size_t size=(size_t) strtoul(argv[6],NULL,10);
    char *payload=calloc(1,size+1); assert(payload);
    arm(argv[8],"write");
    ssize_t written=inst->driver->staged_write(h,payload,size,
                         strcmp(argv[1],"offset") == 0 ? 1 : 0);
    native_alloc_disarm(); free(payload);
    if (written < 0) {
        assert(errno == expected); inst->driver->staged_abort(h); return -1;
    }
    assert(written == (ssize_t) size);
    brix_sd_precond_t pre={0};
    pre.kind=atoi(argv[7]); pre.etag="\"original\""; pre.etag_len=strlen(pre.etag);
    if (strcmp(argv[1],"etag-empty") == 0) { pre.etag_len=0; }
    if (strcmp(argv[1],"etag-long") == 0) { pre.etag_len=200; }
    if (strcmp(argv[1],"etag-null") == 0) { pre.etag=NULL; }
    arm(argv[8],"commit"); errno=0;
    int rc=inst->driver->staged_commit(h,&pre);
    int saved=errno; native_alloc_disarm();
    if (rc != 0) { assert(saved == expected); inst->driver->staged_abort(h); }
    else { assert(expected == 0); }
    printf("VERDICT %d atomic=%d\n",rc,pre.atomic);
    return rc;
}
int main(int argc, char **argv) {
    assert(argc == 10); ngx_os_argv=argv;
    assert(brix_crypto_init());
    fixture f={.mode=argv[1],.fail_phase=argv[2],.status=atoi(argv[3]),.identity=argv[4]};
    brix_s3_transport_t transport={.request=request,.resp_header=header,.resp_body=response_body,.resp_free=release};
    brix_sd_remote_cfg_t cfg={.scheme=BRIX_SD_REMOTE_S3,.port=443,.tls=1,
        .timeout_ms=1000,.put_checksum=1,.transport=&transport,.tctx=&f};
    strcpy(cfg.host,"origin.test"); strcpy(cfg.bucket,"bucket");
    strcpy(cfg.access_key,"service"); strcpy(cfg.secret_key,"service-secret"); strcpy(cfg.region,"region");
    brix_sd_instance_t *inst=brix_sd_remote_create(&cfg,NULL); assert(inst);
    int rc=exercise(inst,argv); assert((rc == 0) == (atoi(argv[9]) == 0));
    printf("COUNTS create=%d part=%d complete=%d put=%d abort=%d freed=%d failed=%d\n",
           f.create,f.part,f.complete,f.put,f.aborted,f.freed,f.failed);
    brix_sd_remote_destroy(inst); brix_crypto_cleanup(); return 0;
}

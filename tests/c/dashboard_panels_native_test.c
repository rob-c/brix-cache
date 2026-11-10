/* Dashboard JSON serialization from finite metric/registry snapshots. */
#include "observability/dashboard/dashboard_api_internal.h"
#include "fs/vfs/vfs_backend_registry.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_shm_zone_t zone;
    ngx_brix_metrics_t metrics;
    const char *mode;
    unsigned allocation, fail_at, armed;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }
json_t *__real_json_object(void);
json_t *__real_json_array(void);
/* WHAT: Inject a single JSON allocation failure. WHY: Exercise best-effort output without privacy bypass. HOW: Count only armed object/array creation. */
static int fail_allocation(void)
{ return state()->armed && ++state()->allocation==state()->fail_at; }
json_t *__wrap_json_object(void) { return fail_allocation()?NULL:__real_json_object(); }
json_t *__wrap_json_array(void) { return fail_allocation()?NULL:__real_json_array(); }
ngx_shm_zone_t *__wrap_brix_metrics_get_shm_zone(void)
{
    if(mode("absent")) { return NULL; }
    state()->zone.data=mode("null")?NULL:mode("sentinel")?(void *)1:&state()->metrics;
    return &state()->zone;
}
ngx_int_t __wrap_brix_fs_usage_stat(const char *path,brix_fs_usage_t *out)
{
    assert(path && strstr(path,"private"));
    if(mode("stat-failed")) { return NGX_ERROR; }
    *out=(brix_fs_usage_t){.total_bytes=1000,.available_bytes=250,
        .occupancy_bytes=750,.occupancy_ppm=750000};return NGX_OK;
}
ngx_uint_t __wrap_brix_vfs_backend_export_count(void) { return 3; }
ngx_int_t __wrap_brix_vfs_backend_export_info(ngx_uint_t i,brix_vfs_backend_info_t *out)
{
    if(i==2) { return NGX_ERROR; }
    *out=(brix_vfs_backend_info_t){.root_canon="/private-export",.backend=i?"xroot":"posix",
        .host=i?"private-origin.invalid":"",.port=1094,.staging=i!=0};return NGX_OK;
}
ngx_uint_t __wrap_brix_srv_snapshot(brix_srv_snapshot_entry_t *out,ngx_uint_t capacity,ngx_msec_t now)
{
    assert(capacity>=2 && now==1000);
    memset(out,0,2*sizeof(*out));
    for(unsigned i=0;i<2;i++) {
        strcpy(out[i].host,"private-node.invalid");strcpy(out[i].paths,"/private-export");
        strcpy(out[i].vnid,"private-network");out[i].port=1094+i;out[i].stage=i;
        out[i].last_seen=i?1200:100;out[i].free_mb=100+i;out[i].util_pct=20+i;
        out[i].load_pct=30+i;out[i].min_free_mb=10;out[i].space_blocked=i;
        out[i].blacklisted_until=i?2000:0;
    }
    return 2;
}
/* WHAT: Populate nontrivial counters and duplicates. WHY: Pin sums, filtering and claim-race deduplication. HOW: Seed caller-owned snapshots. */
static void populate(ngx_brix_metrics_t *metrics)
{
    for(unsigned i=0;i<3;i++) {
        ngx_brix_srv_metrics_t *slot=&metrics->servers[i];
        slot->in_use=i<2;slot->cache_enabled=i!=1;slot->port=1094+i;
        strcpy(slot->auth,"token");strcpy(slot->cache_root,"/private-cache");
        slot->cache_eviction_threshold=900000;slot->cache_evictions_total=11;
        slot->cache_evicted_bytes_total=123;slot->cache_eviction_errors_total=2;
        slot->wt_dirty_handles=i+1;slot->wt_flush_pending=2;
        slot->wt_flush_success_total=4;slot->wt_flush_error_total=1;slot->wt_flush_bytes_total=100;
    }
    metrics->unified.io_bytes_read_backend[1]=128;
    metrics->unified.io_bytes_written_backend[1]=64;
    metrics->cvmfs.requests_total[0]=17;metrics->cvmfs.origin_bytes_total=123;
    for(unsigned i=0;i<3;i++) {
        ngx_brix_cvmfs_repo_metrics_t *repo=&metrics->cvmfs.repos[i];
        ngx_brix_cvmfs_upstream_metrics_t *up=&metrics->cvmfs.upstreams[i];
        repo->state=i<2?BRIX_CVMFS_REPO_READY:0;
        up->state=repo->state;
        strcpy(repo->name,"private-repo.example");strcpy(up->name,"private-upstream.invalid");
        repo->requests_total[0]=17+i;repo->files_accessed_total=12;repo->cache_hits_total=8;
        up->requests_total=20+i;up->fills_total=7;up->fill_failures_total=3;
        up->failovers_total=2;up->origin_bytes_total=123;up->dur_sum_ms=700;up->dur_count=7;
    }
}
/* WHAT: Serialize a detailed transfer. WHY: Verify private fields and per-operation counters. HOW: Use one complete finite transfer slot. */
static json_t *transfer(ngx_uint_t redact)
{
    brix_transfer_slot_t slot={0};ngx_http_brix_dashboard_loc_conf_t conf={0};
    slot.serial=42;slot.direction=BRIX_XFER_DIR_TPC;slot.proto=BRIX_XFER_PROTO_ROOT;
    slot.start_ms=100;slot.last_ms=800;slot.bytes=900;slot.expected_bytes=1800;
    slot.last_sample_ms=800;slot.instant_bps=1200;slot.worker_pid=123;
    slot.read_ops=3;slot.write_ops=4;slot.sync_ops=5;slot.close_ops=6;
    memset(slot.sessid,0xa5,sizeof(slot.sessid));
    strcpy(slot.client_ip,"private-client");strcpy(slot.identity,"private-user");
    strcpy(slot.path,"/private-path");strcpy(slot.vo,"private-vo");strcpy(slot.op,"read");
    strcpy(slot.last_error,"private-error");strcpy(slot.tpc_remote_host,"private-remote.invalid");
    strcpy(slot.tpc_remote_path_hint,"/private-remote-path");
    slot.tpc_remote_status=206;slot.tpc_curl_exit=0;
    return dashboard_build_transfer_object(&conf,&slot,1000,1,1,redact);
}
/* WHAT: Execute one panel builder. WHY: Preserve production JSON ownership. HOW: Arm failure only after allocating the root object. */
int main(int argc,char **argv)
{
    assert(argc==5);fixture *f=calloc(1,sizeof(*f));assert(f);ngx_cycle=&f->cycle;
    f->mode=argv[2];f->fail_at=(unsigned)atoi(argv[4]);populate(&f->metrics);
    ngx_open_file_t file={.fd=STDERR_FILENO};ngx_log_t log={.log_level=NGX_LOG_ERR,.file=&file};
    f->cycle.log=&log;ngx_time_init();ngx_pool_t *pool=ngx_create_pool(16384,&log);assert(pool);
    ngx_uint_t redact=(ngx_uint_t)atoi(argv[3]);
    json_t *result=json_object();assert(result);f->armed=1;
    if(!strcmp(argv[1],"cache")) { dashboard_fill_cache(result,redact); }
    else if(!strcmp(argv[1],"storage")) { dashboard_fill_storage(result,redact); }
    else if(!strcmp(argv[1],"cvmfs")) { dashboard_fill_cvmfs(result,redact); }
    else if(!strcmp(argv[1],"cluster")) {
        ngx_http_brix_dashboard_loc_conf_t conf={.cluster_stale_after_ms=500};
        dashboard_fill_cluster(result,pool,1000,&conf,redact);
    } else { json_decref(result);result=transfer(redact); }
    f->armed=0;
    char *text=json_dumps(result?result:json_null(),JSON_COMPACT|JSON_ENCODE_ANY);assert(text);
    puts(text);free(text);json_decref(result);ngx_destroy_pool(pool);free(f);return 0;
}

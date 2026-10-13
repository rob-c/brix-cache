/* Internal contract for the split xrd conform command implementation. */
#pragma once

#include "xrd_internal.h"
#include "conform/model.h"
#include "conform/report.h"
#include "conform/run.h"

#define XRDC_CONFORM_ERROR_FIXTURE_MAX 64
#define XRDC_CONFORM_READONLY_FIXTURE_MAX 4
#define XRDC_CONFORM_AUTH_FIXTURE_MAX 8
#define XRDC_CONFORM_DENIED_FIXTURE_MAX 3
#define XRDC_CONFORM_OPEN_FIXTURE_MAX 3
#define XRDC_CONFORM_LOCATE_FIXTURE_MAX 2
#define XRDC_CONFORM_TOKEN_FIXTURE_MAX 4
#define XRDC_CONFORM_ADV_REPRO_MAX 10
#define XRDC_CONFORM_ADV_WIRE_MAX (XRDC_PATH_MAX + 88)
#define XRDC_CONFORM_TLS_FIXTURE_MAX 5
#define XRDC_CONFORM_NEGATIVE_VERIFY_MAX 64
#define XRDC_CONFORM_CHUNKED_SIZE 16777217U

typedef struct {
    char        errno_name[24];
    const char *target;
    int         is_http;
} xrd_conform_error_fixture;

typedef struct {
    char        plane[12];
    const char *target;
} xrd_conform_readonly_fixture;

typedef struct {
    char        protocol[8];
    const char *target;
} xrd_conform_auth_fixture;

typedef struct {
    char        plane[8];
    const char *target;
} xrd_conform_denied_fixture;

typedef xrd_conform_denied_fixture xrd_conform_mutation_fixture;

typedef struct {
    char        kind[24];
    const char *target;
} xrd_conform_open_fixture;

typedef struct {
    char        kind[8];
    const char *target;
} xrd_conform_locate_fixture;

typedef struct {
    char        kind[20];
    const char *target;
} xrd_conform_token_fixture;

typedef struct {
    char        request_class[8];
    const char *target;
} xrd_conform_tls_fixture;

typedef struct {
    uint8_t  wire[XRDC_CONFORM_ADV_WIRE_MAX];
    uint32_t wire_length;
    uint16_t sid;
    uint16_t code;
} xrd_conform_adv_reproducer;

typedef struct {
    brix_conform_run_config config;
    brix_opts               opts;
    brix_conform_key        key;
    char                    key_hex[BRIX_CONFORM_KEY_SIZE * 2U + 1U];
    char                    profiles[128];
    const char             *also[8];
    size_t                  also_count;
    const char             *quota_target;
    const char             *capacity_target;
    const char             *webdav_outside_target;
    const char             *move_fixture_target;
    const char             *cache_fixture_kind;
    const char             *tpc_fixture_kind;
    const char             *adv_observer;
    const char             *adv_fixture_kind;
    const char             *negative_verify[XRDC_CONFORM_NEGATIVE_VERIFY_MAX];
    size_t                  negative_verify_count;
    xrd_conform_tls_fixture tls_fixtures[XRDC_CONFORM_TLS_FIXTURE_MAX];
    size_t                  tls_fixture_count;
    unsigned                http_request_line_limit;
    xrd_conform_error_fixture error_fixtures[XRDC_CONFORM_ERROR_FIXTURE_MAX];
    size_t                  error_fixture_count;
    xrd_conform_readonly_fixture
                              readonly_fixtures[XRDC_CONFORM_READONLY_FIXTURE_MAX];
    size_t                    readonly_fixture_count;
    xrd_conform_auth_fixture  auth_fixtures[XRDC_CONFORM_AUTH_FIXTURE_MAX];
    size_t                    auth_fixture_count;
    xrd_conform_denied_fixture
                              denied_fixtures[XRDC_CONFORM_DENIED_FIXTURE_MAX];
    size_t                    denied_fixture_count;
    xrd_conform_mutation_fixture
                              mutation_fixtures[XRDC_CONFORM_DENIED_FIXTURE_MAX];
    size_t                    mutation_fixture_count;
    xrd_conform_open_fixture  open_fixtures[XRDC_CONFORM_OPEN_FIXTURE_MAX];
    size_t                    open_fixture_count;
    xrd_conform_locate_fixture
                              locate_fixtures[XRDC_CONFORM_LOCATE_FIXTURE_MAX];
    size_t                    locate_fixture_count;
    xrd_conform_token_fixture token_fixtures[XRDC_CONFORM_TOKEN_FIXTURE_MAX];
    size_t                    token_fixture_count;
    int                     profile_explicit;
} xrd_conform_run;

typedef struct {
    xrd_conform_run         *run;
    brix_conform_run_results results;
    unsigned                 requests;
    unsigned long long       bytes;
    time_t                    started;
    const char               *target;
    uint64_t                  root_size;
    uint64_t                  http_size;
    uint64_t                  s3_size;
    uint64_t                  ftp_size;
    uint64_t                  oci_size;
    char                      root_digest[65];
    char                      http_digest[65];
    char                      s3_digest[65];
    char                      ftp_digest[65];
    char                      oci_digest[65];
    char                      root_clear_digest[65];
    char                      root_tls_digest[65];
    char                      root_checksum[65];
    char                      http_checksum[65];
    char                      s3_checksum[65];
    char                      root_namespace[65];
    char                      http_namespace[65];
    char                      s3_namespace[65];
    int                       have_root;
    int                       have_http;
    int                       have_s3;
    int                       have_ftp;
    int                       have_oci;
    int                       have_root_clear;
    int                       have_root_tls;
    int                       root_checksum_state;
    int                       http_checksum_state;
    int                       s3_checksum_state;
    int                       root_traversal_state;
    int                       http_traversal_state;
    int                       s3_traversal_state;
    int                       root_case_state;
    int                       http_case_state;
    int                       s3_case_state;
    int                       root_namespace_state;
    int                       http_namespace_state;
    int                       s3_namespace_state;
    int                       root_filename_state[3];
    int                       http_filename_state[3];
    int                       s3_filename_state[3];
    int                       http_missing_state;
    int                       s3_missing_state;
    int                       root_tls_active_seen;
    int                       root_tls_goto_seen;
    int                       root_tls_auth_seen;
    int                       root_tls13_seen;
    uint32_t                  root_tls_required_seen;
    uint32_t                  root_tls_cleartext_tested;
    uint32_t                  root_tls_cleartext_refused;
    int                       root_tls_fixture_attempted;
    int                       gpfile_state;
    int                       s3_bearer_state;
    int                       http_sigv4_state;
    int                       root_readonly_state;
    int                       s3_readonly_state;
    int                       query_checksum_claim_state;
    int                       tpc_claim_behavior_state;
    char                      cms_manager_holder_set[2048];
    size_t                    cms_manager_count;
    int                       cms_manager_sets_consistent;
    xrd_conform_adv_reproducer
                              adv_reproducers[XRDC_CONFORM_ADV_REPRO_MAX];
    size_t                    adv_reproducer_count;
} xrd_conform_execution;

/* Mutation probes receive this builder-produced capability, never a raw path. */
typedef struct {
    char path[XRDC_PATH_MAX];
} xrd_conform_scratch_object;

typedef struct {
    const char *method;
    const char *target;
    const char *fields;
    const void *body;
    size_t      body_length;
    size_t      expected_bytes;
    int         finish_write;
} xrd_conform_raw_http;

int xrd_conform_parse_run(int argc, char **argv, xrd_conform_run *run);
int xrd_conform_run_defaults(const char *shape, xrd_conform_run *run);
int xrd_conform_parse_denied_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run);
int xrd_conform_parse_mutation_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run);
int xrd_conform_parse_special_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run);
int xrd_conform_parse_open_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run);
int xrd_conform_parse_locate_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run);
int xrd_conform_parse_token_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run);
int xrd_conform_parse_security_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run);
int xrd_conform_execute(xrd_conform_run *run);
void xrd_conform_grade_cross_plane(xrd_conform_execution *execution);
int xrd_conform_credential_safe(const char *token);
int xrd_conform_s3_auth_headers(const brix_weburl *url, const char *method,
    char authentication[2048]);
int xrd_conform_s3_credentials(const char **access, const char **secret,
    const char **region);
int xrd_conform_s3_wire_path(const brix_weburl *url, char *out,
    size_t out_size);
int xrd_conform_run_root(xrd_conform_execution *execution);
int xrd_conform_plant_object(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object,
    uint64_t size, brix_status *status);
uint8_t *xrd_conform_read_baseline(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, uint64_t size,
    brix_status *status);
void xrd_conform_grade_read(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size, const char *id, int64_t offset, size_t length);
int xrd_conform_probe_standard_corpus(xrd_conform_execution *execution,
    brix_conn *connection);
int xrd_conform_standard_corpus_needed(
    const xrd_conform_execution *execution);
int xrd_conform_large_offset_needed(const xrd_conform_execution *execution);
int xrd_conform_write_only_needed(const xrd_conform_execution *execution);
int xrd_conform_run_http(xrd_conform_execution *execution);
int xrd_conform_run_ftp(xrd_conform_execution *execution);
int xrd_conform_run_oci(xrd_conform_execution *execution);
char *xrd_conform_http_headers(const brix_weburl *url, const char *method,
    const char *token, const char *fields, const char **failure);
int xrd_conform_http_request_fields(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *token,
    const char *fields, size_t expected_bytes, brix_http_resp *response,
    brix_status *status);
int xrd_conform_http_request(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *token,
    const char *range, size_t expected_bytes, brix_http_resp *response,
    brix_status *status);
void xrd_conform_probe_http_boundaries(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *get_response);
int xrd_conform_http_content_length(const brix_http_resp *response,
    uint64_t *length);
int xrd_conform_http_request_body(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *token,
    const char *fields, const void *body, size_t body_length,
    size_t expected_bytes, brix_http_resp *response, brix_status *status);
int xrd_conform_http_request_custom(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *headers,
    const void *body, size_t body_length, size_t expected_bytes,
    brix_http_resp *response, brix_status *status);
int xrd_conform_http_raw_request(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const xrd_conform_raw_http *request, brix_http_resp *response,
    brix_status *status);
void xrd_conform_probe_http_validators(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline);
void xrd_conform_probe_http_semantics(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline);
void xrd_conform_probe_http_errors(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline);
void xrd_conform_probe_webdav(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline);
void xrd_conform_probe_webdav_multistatus(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
size_t xrd_conform_webdav_xml_count(const char *body, const char *name);
int xrd_conform_webdav_scratch_url(xrd_conform_execution *execution,
    const brix_weburl *base, const char *leaf, brix_weburl *scratch);
int xrd_conform_webdav_mutation(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *token,
    const char *fields, int *http_status);
void xrd_conform_webdav_cleanup(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
int xrd_conform_webdav_destination_fields(const brix_weburl *url,
    char *fields, size_t capacity);
int xrd_conform_webdav_put_fixture(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token, const char *body);
void xrd_conform_probe_webdav_delete(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
void xrd_conform_probe_webdav_outside(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
void xrd_conform_probe_http_create(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
void xrd_conform_probe_s3_range_agreement(xrd_conform_execution *execution,
    const brix_weburl *url);
void xrd_conform_probe_s3_missing_codes(xrd_conform_execution *execution,
    const brix_weburl *url);
void xrd_conform_probe_s3_listing(xrd_conform_execution *execution,
    const brix_weburl *url);
void xrd_conform_probe_s3_special_keys(xrd_conform_execution *execution,
    const brix_weburl *url);
void xrd_conform_probe_s3_multipart(xrd_conform_execution *execution,
    const brix_weburl *url);
void xrd_conform_probe_s3_auth(xrd_conform_execution *execution,
    const brix_weburl *url);
void xrd_conform_finalize_s3_auth(xrd_conform_execution *execution);
void xrd_conform_probe_s3_readonly(xrd_conform_execution *execution,
    const brix_weburl *url);
void xrd_conform_finalize_s3_readonly(xrd_conform_execution *execution);
void xrd_conform_probe_stat(xrd_conform_execution *execution,
    brix_conn *connection, const brix_file *file, const char *path,
    uint64_t size);
void xrd_conform_probe_readv(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size);
void xrd_conform_probe_readv_limits(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size);
void xrd_conform_probe_readv_chunked(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    size_t size);
void xrd_conform_probe_read_raw(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
int xrd_conform_root_raw_read(xrd_conform_execution *execution,
    brix_conn *connection, const uint8_t handle[XRDC_FHANDLE_LEN],
    int64_t offset, int32_t length, const void *args, uint32_t args_length,
    size_t expected_bytes, uint16_t *wire_status, uint8_t **body,
    uint32_t *body_length, brix_status *status);
void xrd_conform_probe_cache_pair(xrd_conform_execution *execution);
void xrd_conform_probe_cache_evict(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin);
void xrd_conform_probe_cache_fixture(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin, const brix_url *cache_url,
    const brix_url *origin_url);
void xrd_conform_probe_tpc_pair(xrd_conform_execution *execution);
int xrd_conform_tpc_exact_selected(const xrd_conform_execution *execution);
void xrd_conform_probe_tpc_webdav(xrd_conform_execution *execution,
    const uint8_t *native_bytes, size_t native_length, int native_exact);
void xrd_conform_probe_tpc_scoped(xrd_conform_execution *execution);
int xrd_conform_tpc_root_url(const brix_url *endpoint, const char *path,
    char *out, size_t out_size);
int xrd_conform_tpc_destination_absent(brix_conn *destination,
    const char *path);
int xrd_conform_tpc_destination_exact(brix_conn *connection, const char *path,
    const uint8_t *expected, size_t expected_length, brix_status *status);
void xrd_conform_probe_pgread(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
void xrd_conform_probe_pgread_standard(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
void xrd_conform_probe_chunked_reads(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    size_t size);
int xrd_conform_probe_large_offset(xrd_conform_execution *execution,
    brix_conn *connection);
int xrd_conform_probe_write_only(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_read_substreams(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
void xrd_conform_probe_read_partitions(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
void xrd_conform_probe_root_basic(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path);
void xrd_conform_basic_grade(xrd_conform_execution *execution,
    const char *id, int pass, const char *pass_reason,
    const brix_status *status);
int xrd_conform_basic_reserve(xrd_conform_execution *execution,
    char reason[64]);
void xrd_conform_probe_root_locate_query(xrd_conform_execution *execution,
    brix_conn *connection, const char *path);
void xrd_conform_probe_root_open(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size);
void xrd_conform_probe_open_mutations(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_open_refresh(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_checkpoints(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_prepare(xrd_conform_execution *execution,
    brix_conn *connection, const char *path);
void xrd_conform_probe_root_control(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path);
void xrd_conform_probe_query_claims(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size);
void xrd_conform_probe_claim_audit(xrd_conform_execution *execution,
    const brix_url *url, brix_conn *connection);
void xrd_conform_finalize_claim_audit(xrd_conform_execution *execution);
void xrd_conform_probe_bind(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
void xrd_conform_probe_env_flow(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
void xrd_conform_probe_namespace_mutations(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_cross_export_move(xrd_conform_execution *execution);
void xrd_conform_probe_large_dir(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_dir_10000(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_dir_checksums(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *base);
void xrd_conform_probe_write_mutations(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_concurrent_write(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object);
void xrd_conform_probe_truncated_write(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object);
void xrd_conform_probe_oversized_write(xrd_conform_execution *execution);
void xrd_conform_probe_write_capacity(xrd_conform_execution *execution);
void xrd_conform_probe_writev_limits(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object);
void xrd_conform_probe_pgwrite_cse(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object);
void xrd_conform_probe_fattr_mutations(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object);
void xrd_conform_probe_fattr_readonly(xrd_conform_execution *execution,
    brix_conn *connection);
int xrd_conform_readonly_exact_selected(const xrd_conform_execution *execution);
void xrd_conform_probe_readonly_exact(xrd_conform_execution *execution,
    brix_conn *connection);
void xrd_conform_probe_fattr_support(xrd_conform_execution *execution,
    brix_conn *connection, const char *path);
void xrd_conform_probe_locate_endpoint(xrd_conform_execution *execution,
    brix_conn *primary, const char *reply, const char *path);
int xrd_conform_first_data_endpoint(const char *reply, char *endpoint,
    size_t endpoint_size);
void xrd_conform_probe_preferred_name(xrd_conform_execution *execution,
    brix_conn *primary, const char *path, const char *plain_endpoint);
int xrd_conform_canonical_holder_set(const char *reply, char *canonical,
    size_t canonical_size);
void xrd_conform_probe_cms_map(xrd_conform_execution *execution,
    const char *locate_reply);
void xrd_conform_probe_cms_manager(xrd_conform_execution *execution,
    brix_conn *manager, const char *path);
int xrd_conform_cms_outage_exact_selected(
    const xrd_conform_execution *execution);
void xrd_conform_probe_protocol_claims(xrd_conform_execution *execution,
    const brix_url *url, brix_conn *connection);
void xrd_conform_probe_handshake_negatives(xrd_conform_execution *execution,
    const brix_url *url);
void xrd_conform_probe_framing(xrd_conform_execution *execution,
    const brix_url *url);
void xrd_conform_probe_framing_hostile(xrd_conform_execution *execution,
    const brix_url *url);
void xrd_conform_probe_login(xrd_conform_execution *execution,
    const brix_url *url, const brix_conn *primary);
void xrd_conform_probe_login_auth_negatives(xrd_conform_execution *execution,
    const brix_url *url);
void xrd_conform_probe_login_abilities(xrd_conform_execution *execution,
    const brix_url *url);
void xrd_conform_probe_sigver_active(xrd_conform_execution *execution,
    const brix_url *url);
void xrd_conform_probe_sigver_bound(xrd_conform_execution *execution,
    const brix_url *url);
void xrd_conform_probe_sigver_unencrypted(xrd_conform_execution *execution,
    const brix_url *url);
void xrd_conform_probe_tls(xrd_conform_execution *execution,
    const brix_url *url, const brix_conn *connection, int object_observed);
void xrd_conform_probe_tls_fixtures(xrd_conform_execution *execution);
void xrd_conform_probe_adversarial(xrd_conform_execution *execution,
    const brix_url *url, brix_conn *baseline, const char *path);
void xrd_conform_finalize_tls(xrd_conform_execution *execution);
void xrd_conform_probe_flow(xrd_conform_execution *execution,
    const brix_url *url);
int xrd_conform_error_fixture_name_valid(const char *name, size_t length);
int xrd_conform_error_fixture_exact_selected(
    const xrd_conform_execution *execution);
void xrd_conform_probe_error_fixtures(xrd_conform_execution *execution);
int xrd_conform_observe_root_error(xrd_conform_execution *execution,
    const char *target, uint16_t *code, char message[128]);
void xrd_conform_probe_http_error_fixtures(xrd_conform_execution *execution);
void xrd_conform_probe_readonly_fixtures(xrd_conform_execution *execution);
void xrd_conform_probe_auth_fixtures(xrd_conform_execution *execution);
void xrd_conform_probe_token_fixtures(xrd_conform_execution *execution);
int xrd_conform_auth_fixtures_cover(const xrd_conform_run *run,
    const char *security);
void xrd_conform_probe_denied_fixtures(xrd_conform_execution *execution);
void xrd_conform_probe_mutation_fixtures(xrd_conform_execution *execution);
void xrd_conform_probe_open_fixtures(xrd_conform_execution *execution);
void xrd_conform_finalize_fixture_gates(xrd_conform_execution *execution);
void xrd_conform_observe_root_checksum(xrd_conform_execution *execution,
    const char *claimed, int valid);
void xrd_conform_observe_http_checksum(xrd_conform_execution *execution,
    const brix_http_resp *baseline, int valid);
void xrd_conform_probe_s3_checksum(xrd_conform_execution *execution,
    const brix_weburl *url, const brix_http_resp *baseline);
void xrd_conform_finalize_checksums(xrd_conform_execution *execution);
void xrd_conform_probe_root_traversal(xrd_conform_execution *execution,
    brix_conn *connection, const char *path);
void xrd_conform_probe_web_traversal(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
void xrd_conform_finalize_traversal(xrd_conform_execution *execution);
void xrd_conform_probe_root_case(xrd_conform_execution *execution,
    brix_conn *connection, const char *path);
void xrd_conform_probe_web_case(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
void xrd_conform_finalize_case(xrd_conform_execution *execution);
void xrd_conform_probe_root_filenames(xrd_conform_execution *execution,
    brix_conn *connection, const char *path);
void xrd_conform_probe_web_filenames(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
void xrd_conform_finalize_filenames(xrd_conform_execution *execution);
void xrd_conform_probe_root_namespace(xrd_conform_execution *execution,
    brix_conn *connection, const char *path);
void xrd_conform_probe_web_namespace(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token);
void xrd_conform_finalize_namespace(xrd_conform_execution *execution);
brix_conform_result *xrd_conform_result_find(xrd_conform_execution *execution,
    const char *id);
int xrd_conform_family_active(xrd_conform_execution *execution,
    const char *family);
int xrd_conform_root_object_needed(xrd_conform_execution *execution);
void xrd_conform_run_rd(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
void xrd_conform_run_pgr(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size);
int xrd_conform_probe_selected_object(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size);
void xrd_conform_result_set(xrd_conform_execution *execution, const char *id,
    brix_conform_verdict verdict, const char *reason, const char *expected,
    const char *received);
int xrd_conform_reserve(xrd_conform_execution *execution, size_t bytes,
    char *reason, size_t reason_size);

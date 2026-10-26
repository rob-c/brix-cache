/* Macaroon parser and duplicate-discharge security regressions.
 *
 * WHAT: Exercises canonical path caveats, explicit expiry presence, bounded
 * version-one caveat locations, and order-independent duplicate-cid bundles.
 * WHY: These edge cases cross authenticated parsing and authorization state;
 * source-only assertions would miss HMAC-chain and bundle lifecycle mistakes.
 * HOW: Reuse the native fixture primitives without its main, build exact signed
 * packets, and invoke the production parser/bundle validator for each case.
 */

#define BRIX_MACAROON_FIXTURE_LIBRARY 1
#include "macaroon_signature_test.c"

#define FOLLOWUP_TOKEN_CAPACITY 4096
#define FOLLOWUP_BUNDLE_CAPACITY 12288

/* WHAT: Seed a fixture builder with an arbitrary root key.
 * WHY: Same-identifier discharges must be signed by different caveat keys.
 * HOW: Emit the identifier and calculate its initial HMAC with the supplied key.
 */
static void
followup_builder_begin_key(fixture_builder_t *builder, u_char *binary,
    size_t capacity, const char *identifier, const u_char *key, size_t key_len)
{
    unsigned int signature_len = 0;

    memset(builder, 0, sizeof(*builder));
    builder->data = binary;
    builder->capacity = capacity;
    fixture_append_packet(builder, "identifier", (const u_char *)identifier,
                          strlen(identifier), 1);
    assert(HMAC(EVP_sha256(), key, key_len,
                (const u_char *)identifier, strlen(identifier),
                builder->signature, &signature_len) != NULL);
    assert(signature_len == sizeof(builder->signature));
}

/* WHAT: Encode one fixture binary into a checked base64url token.
 * WHY: Bundle validation accepts only its public encoded representation.
 * HOW: Prove worst-case capacity, encode, and require a nonempty result.
 */
static void
followup_encode(const u_char *binary, size_t binary_len,
    char token[FOLLOWUP_TOKEN_CAPACITY])
{
    assert(binary_len <= (FOLLOWUP_TOKEN_CAPACITY - 1) / 4 * 3);
    b64url_encode((const char *)binary, binary_len, token,
                  FOLLOWUP_TOKEN_CAPACITY);
    assert(token[0] != '\0');
}

/* WHAT: Append one encoded token to a bounded space-separated bundle.
 * WHY: Public validation must see candidate order exactly as a client sent it.
 * HOW: Add one separator after the first token, copy bytes, and terminate.
 */
static void
followup_bundle_append(char *bundle, size_t capacity, size_t *length,
    const char *token)
{
    size_t token_len = strlen(token);
    size_t separator_len = *length > 0 ? 1 : 0;

    assert(separator_len + token_len < capacity - *length);
    if (separator_len != 0) {
        bundle[(*length)++] = ' ';
    }
    memcpy(bundle + *length, token, token_len);
    *length += token_len;
    bundle[*length] = '\0';
}

/* WHAT: Build one signed discharge with a shared identifier.
 * WHY: Duplicate-cid selection needs individually valid candidates under
 * different recovered keys.
 * HOW: Seed with the supplied key, add a live deadline, and emit the signature.
 */
static size_t
followup_build_discharge(u_char *binary, size_t capacity, const u_char key[32])
{
    fixture_builder_t builder;

    followup_builder_begin_key(&builder, binary, capacity, "duplicate-cid",
                               key, 32);
    fixture_builder_cid(&builder, "before:2030-01-01T00:00:00Z");
    return fixture_builder_finish(&builder);
}

/* WHAT: Append one duplicate-id third-party caveat with a unique key.
 * WHY: The root must bind each same-text cid to its own encrypted discharge key.
 * HOW: Encrypt the key under the pre-cid signature, then HMAC cid and vid.
 */
static void
followup_add_third_party(fixture_builder_t *builder, const u_char key[32])
{
    u_char vid[BRIX_MACAROON_VID_LEN];

    fixture_encrypt_vid(builder->signature, key, vid);
    fixture_builder_cid(builder, "duplicate-cid");
    fixture_builder_vid(builder, vid, sizeof(vid));
}

/* WHAT: Build a root with two same-identifier third-party caveats.
 * WHY: Candidate ordering is observable only when cids collide but keys differ.
 * HOW: Add live first-party restrictions, two encrypted keys, and a signature.
 */
static size_t
followup_build_duplicate_root(u_char *binary, size_t capacity,
    const u_char first_key[32], const u_char second_key[32])
{
    fixture_builder_t builder;

    followup_builder_begin_key(&builder, binary, capacity, "root-subject",
        (const u_char *)FIXTURE_ROOT_KEY, sizeof(FIXTURE_ROOT_KEY) - 1);
    fixture_builder_cid(&builder, "activity:DOWNLOAD");
    fixture_builder_cid(&builder, "before:2030-01-01T00:00:00Z");
    followup_add_third_party(&builder, first_key);
    followup_add_third_party(&builder, second_key);
    return fixture_builder_finish(&builder);
}

/* WHAT: Verify duplicate-cid selection is cryptographic and order-independent.
 * WHY: Marking the first textual match used lets a wrong-key candidate block
 * the correct discharge and makes legitimate bundles depend on token order.
 * HOW: Accept reversed and direct orders, then reject two copies of one key.
 */
static void
run_duplicate_cid_case(ngx_log_t *log, const char *case_name)
{
    u_char first_key[32];
    u_char second_key[32];
    u_char root_binary[1024];
    u_char first_binary[512];
    u_char second_binary[512];
    char root_token[FOLLOWUP_TOKEN_CAPACITY];
    char first_token[FOLLOWUP_TOKEN_CAPACITY];
    char second_token[FOLLOWUP_TOKEN_CAPACITY];
    char bundle[FOLLOWUP_BUNDLE_CAPACITY] = {0};
    size_t bundle_len = 0;
    brix_token_claims_t claims;

    memset(first_key, 0x31, sizeof(first_key));
    memset(second_key, 0x72, sizeof(second_key));
    followup_encode(root_binary, followup_build_duplicate_root(root_binary,
        sizeof(root_binary), first_key, second_key), root_token);
    followup_encode(first_binary, followup_build_discharge(first_binary,
        sizeof(first_binary), first_key), first_token);
    followup_encode(second_binary, followup_build_discharge(second_binary,
        sizeof(second_binary), second_key), second_token);
    followup_bundle_append(bundle, sizeof(bundle), &bundle_len, root_token);
    if (strcmp(case_name, "duplicate-cid-direct") == 0) {
        followup_bundle_append(bundle, sizeof(bundle), &bundle_len, first_token);
        followup_bundle_append(bundle, sizeof(bundle), &bundle_len, second_token);
    } else {
        followup_bundle_append(bundle, sizeof(bundle), &bundle_len, second_token);
        followup_bundle_append(bundle, sizeof(bundle), &bundle_len,
                               strcmp(case_name, "duplicate-cid-reversed") == 0
                               ? first_token : second_token);
    }
    if (strcmp(case_name, "duplicate-cid-missing-key") == 0) {
        assert(brix_macaroon_validate_bundle(log, bundle, bundle_len,
            (const u_char *)FIXTURE_ROOT_KEY, sizeof(FIXTURE_ROOT_KEY) - 1,
            &claims) == -1);
        return;
    }
    assert(brix_macaroon_validate_bundle(log, bundle, bundle_len,
        (const u_char *)FIXTURE_ROOT_KEY, sizeof(FIXTURE_ROOT_KEY) - 1,
        &claims) == 0);
    assert(claims.scope_count == 1 && claims.scopes[0].read);
}

/* WHAT: Verify canonical path spelling while retaining directory slashes.
 * WHY: Raw dot/repeated segments can escape a textual prefix after VFS
 * canonicalization, while one trailing slash is a documented scope form.
 * HOW: Sign each path caveat and require only the canonical control to parse.
 */
static void
run_path_case(ngx_log_t *log, const char *case_name)
{
    const char *caveats[2] = {"activity:DOWNLOAD", "path:/export/data/"};
    brix_token_claims_t claims;
    u_char binary[BRIX_MACAROON_ISSUE_OUT_MAX];
    size_t length;

    if (strcmp(case_name, "path-dot") == 0) {
        caveats[1] = "path:/export/./data";
    } else if (strcmp(case_name, "path-dotdot") == 0) {
        caveats[1] = "path:/export/../private";
    } else if (strcmp(case_name, "path-repeat") == 0) {
        caveats[1] = "path:/export//data";
    }
    length = build_custom_fixture(binary, sizeof(binary), caveats, 2, 0);
    if (strcmp(case_name, "path-trailing-control") != 0) {
        assert(validate_fixture(log, binary, length, &claims) == -1);
        return;
    }
    assert(validate_fixture(log, binary, length, &claims) == 0);
    assert(claims.scope_count == 1);
    assert(strcmp(claims.scopes[0].path, "/export/data/") == 0);
    assert(brix_token_check_read(claims.scopes, claims.scope_count,
                                 "/export/data/file"));
}

/* WHAT: Verify seen deadlines never regain an unset interpretation.
 * WHY: Epoch-zero followed by a future caveat previously widened to the future,
 * and negative discharge deadlines were silently ignored.
 * HOW: Require root/discharge rejection and retain a no-deadline discharge.
 */
static void
run_expiry_presence_case(ngx_log_t *log, const char *case_name)
{
    const char *epoch_caveats[] = {
        "activity:DOWNLOAD", "before:1970-01-01T00:00:00Z",
        "before:2031-01-01T00:00:00Z"
    };
    const char *pre_epoch_caveats[] = {
        "activity:DOWNLOAD", "before:1969-12-31T23:59:58Z"
    };
    const char **caveats = epoch_caveats;
    size_t caveat_count = 3;
    brix_token_claims_t claims;
    u_char binary[BRIX_MACAROON_ISSUE_OUT_MAX];
    size_t length;

    if (strcmp(case_name, "before-pre-epoch") == 0) {
        caveats = pre_epoch_caveats;
        caveat_count = 2;
    }
    if (strcmp(case_name, "discharge-no-before-control") == 0) {
        fixture_builder_t builder;

        fixture_builder_begin(&builder, binary, sizeof(binary), "discharge");
        fixture_builder_cid(&builder, "activity:DOWNLOAD");
        length = fixture_builder_finish(&builder);
        assert(validate_discharge_fixture(log, binary, length, &claims) == 0);
        return;
    }
    length = build_custom_fixture(binary, sizeof(binary), caveats,
                                  caveat_count, 0);
    if (strcmp(case_name, "discharge-epoch") == 0) {
        assert(validate_discharge_fixture(log, binary, length, &claims) == -1);
    } else {
        assert(validate_fixture(log, binary, length, &claims) == -1);
    }
}

/* WHAT: Verify a v1 caveat location is accepted only beside its vid.
 * WHY: Ignoring `cl` breaks valid v1 tokens, while accepting it elsewhere
 * creates ambiguous unsigned metadata.
 * HOW: Vary placement/count/size around one valid cid+vid pair and parse root.
 */
static void
run_caveat_location_case(ngx_log_t *log, const char *case_name)
{
    fixture_builder_t builder;
    brix_token_claims_t claims;
    u_char binary[BRIX_MACAROON_ISSUE_OUT_MAX];
    u_char vid[BRIX_MACAROON_VID_LEN];
    u_char oversized[BRIX_MACAROON_MAX_CL_LEN];
    size_t length;

    memset(vid, 0x45, sizeof(vid));
    memset(oversized, 'x', sizeof(oversized));
    fixture_builder_begin(&builder, binary, sizeof(binary), "cl-subject");
    fixture_builder_cid(&builder, "activity:DOWNLOAD");
    if (strcmp(case_name, "cl-orphan") == 0) {
        fixture_append_packet(&builder, "cl", (const u_char *)"https://one",
                              sizeof("https://one") - 1, 1);
    } else {
        fixture_builder_cid(&builder, "discharge-id");
        fixture_builder_vid(&builder, vid, sizeof(vid));
        if (strcmp(case_name, "cl-misplaced") == 0) {
            fixture_builder_cid(&builder, "before:2030-01-01T00:00:00Z");
        }
        fixture_append_packet(&builder, "cl",
            strcmp(case_name, "cl-overlong") == 0
                ? oversized : (const u_char *)"https://third.example",
            strcmp(case_name, "cl-overlong") == 0
                ? sizeof(oversized) : sizeof("https://third.example") - 1, 1);
        if (strcmp(case_name, "cl-duplicate") == 0) {
            fixture_append_packet(&builder, "cl", (const u_char *)"https://two",
                                  sizeof("https://two") - 1, 1);
        }
    }
    fixture_builder_cid(&builder, "before:2030-01-01T00:00:00Z");
    length = fixture_builder_finish(&builder);
    if (strcmp(case_name, "cl-control") == 0) {
        assert(validate_fixture(log, binary, length, &claims) == 0);
    } else {
        assert(validate_fixture(log, binary, length, &claims) == -1);
    }
}

/* WHAT: Dispatch one focused follow-up regression by name.
 * WHY: Per-case processes keep sanitizer failures and assertion evidence exact.
 * HOW: Select the bounded family from the required command-line argument.
 */
int
main(int argc, char **argv)
{
    ngx_log_t log = {.log_level = NGX_LOG_INFO};

    /* The included fixture library retains these legacy family runners for its
     * own binary; taking their addresses keeps this focused binary warning-clean. */
    (void)run_issued_case;
    (void)run_activity_case;
    (void)run_grammar_case;
    (void)run_caveat_case;
    assert(argc == 2);
    if (strncmp(argv[1], "duplicate-cid-", 14) == 0) {
        run_duplicate_cid_case(&log, argv[1]);
    } else if (strncmp(argv[1], "path-", 5) == 0) {
        run_path_case(&log, argv[1]);
    } else if (strncmp(argv[1], "before-", 7) == 0
               || strncmp(argv[1], "discharge-", 10) == 0) {
        run_expiry_presence_case(&log, argv[1]);
    } else {
        run_caveat_location_case(&log, argv[1]);
    }
    return 0;
}

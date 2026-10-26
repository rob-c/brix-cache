/* Actual issuer/parser round trips with a fixture-only key and fixed clock.
 * No token is printed, persisted, or sent to an authentication endpoint. */
#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "auth/token/b64url.h"
#include "auth/token/macaroon.h"
#include "auth/token/macaroon_frame.h"
#include "auth/token/macaroon_internal.h"
#include "auth/token/macaroon_issue.h"

#define FIXTURE_ROOT_KEY "native-roundtrip-key"
#define FIXTURE_NOW ((time_t) 1789357971)
#define FIXTURE_EXPIRY (FIXTURE_NOW + 86400)

typedef struct {
    u_char *data;
    size_t capacity;
    size_t length;
    u_char signature[32];
} fixture_builder_t;

/* WHAT: Encode one packet length nibble. WHY: Adversarial fixtures need exact
 * framing without depending on a second macaroon implementation.
 * HOW: Index the lowercase hexadecimal alphabet after a four-bit mask. */
static u_char
fixture_hex(size_t value)
{
    static const u_char digits[] = "0123456789abcdef";
    return digits[value & 0x0f];
}

/* WHAT: Append one exact text/binary macaroon packet and return its new end.
 * WHY: Security cases must retain valid framing while varying packet grammar.
 * HOW: Bounds-check 16-bit framing, write four hex digits, label/value bytes,
 * and the requested text newline. */
static void
fixture_append_packet(fixture_builder_t *builder, const char *label,
    const u_char *value, size_t value_len, int newline)
{
    size_t label_len = strlen(label);
    size_t packet_len = 4 + label_len + 1 + value_len + (newline ? 1 : 0);
    u_char *packet;

    assert(packet_len <= 0xffff);
    assert(packet_len <= builder->capacity - builder->length);
    packet = builder->data + builder->length;
    packet[0] = fixture_hex(packet_len >> 12);
    packet[1] = fixture_hex(packet_len >> 8);
    packet[2] = fixture_hex(packet_len >> 4);
    packet[3] = fixture_hex(packet_len);
    memcpy(packet + 4, label, label_len);
    packet[4 + label_len] = ' ';
    memcpy(packet + 5 + label_len, value, value_len);
    if (newline) {
        packet[5 + label_len + value_len] = '\n';
    }
    builder->length += packet_len;
}

/* WHAT: Start a fixture with its one identifier and initial signature.
 * WHY: Later malformed cases should still have an otherwise valid HMAC chain.
 * HOW: Clear builder state, emit identifier, and compute HMAC(root,id). */
static void
fixture_builder_begin(fixture_builder_t *builder, u_char *binary,
    size_t capacity, const char *identifier)
{
    unsigned int signature_len = 0;

    memset(builder, 0, sizeof(*builder));
    builder->data = binary;
    builder->capacity = capacity;
    fixture_append_packet(builder, "identifier", (const u_char *)identifier,
                          strlen(identifier), 1);
    assert(HMAC(EVP_sha256(), FIXTURE_ROOT_KEY, sizeof(FIXTURE_ROOT_KEY) - 1,
                (const u_char *)identifier, strlen(identifier),
                builder->signature, &signature_len) != NULL);
    assert(signature_len == sizeof(builder->signature));
}

/* WHAT: Append one cid and extend the valid fixture signature chain.
 * WHY: Caveat parser negatives must fail semantics, not an unrelated HMAC.
 * HOW: Emit the text packet then HMAC its exact caveat value. */
static void
fixture_builder_cid(fixture_builder_t *builder, const char *caveat)
{
    u_char next[32];
    unsigned int next_len = 0;
    size_t caveat_len = strlen(caveat);

    fixture_append_packet(builder, "cid", (const u_char *)caveat,
                          caveat_len, 1);
    assert(HMAC(EVP_sha256(), builder->signature, 32,
                (const u_char *)caveat, caveat_len, next, &next_len) != NULL);
    assert(next_len == sizeof(next));
    memcpy(builder->signature, next, sizeof(next));
}

/* WHAT: Append one vid of caller-selected length and extend the valid chain.
 * WHY: Exact-length and overlong encrypted-key records need ASan coverage.
 * HOW: Emit binary bytes followed by its packet delimiter, then HMAC the bytes. */
static void
fixture_builder_vid(fixture_builder_t *builder, const u_char *vid,
    size_t vid_len)
{
    u_char next[32];
    unsigned int next_len = 0;

    fixture_append_packet(builder, "vid", vid, vid_len, 1);
    assert(HMAC(EVP_sha256(), builder->signature, 32, vid, vid_len, next,
                &next_len) != NULL);
    assert(next_len == sizeof(next));
    memcpy(builder->signature, next, sizeof(next));
}

/* WHAT: Finish a fixture with the exact raw 32-byte terminal signature.
 * WHY: Packet-order tests require a cryptographically valid signature boundary.
 * HOW: Emit signature without a text newline and return total binary length. */
static size_t
fixture_builder_finish(fixture_builder_t *builder)
{
    fixture_append_packet(builder, "signature", builder->signature,
                          sizeof(builder->signature), 0);
    return builder->length;
}

/* WHAT: Produce one exact interoperable vid for the crypto success control.
 * WHY: Length hardening must retain valid 16-byte-IV plus 32-byte-key records.
 * HOW: AES-256-CBC encrypt two blocks with padding disabled and prefix the IV. */
static void
fixture_encrypt_vid(const u_char *key, const u_char *plain,
    u_char vid[BRIX_MACAROON_VID_LEN])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int output_len = 0;
    int final_len = 0;

    assert(ctx != NULL);
    memset(vid, 0x37, 16);
    assert(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, vid) == 1);
    assert(EVP_CIPHER_CTX_set_padding(ctx, 0) == 1);
    assert(EVP_EncryptUpdate(ctx, vid + 16, &output_len, plain, 32) == 1);
    assert(EVP_EncryptFinal_ex(ctx, vid + 16 + output_len, &final_len) == 1);
    assert(output_len + final_len == 32);
    EVP_CIPHER_CTX_free(ctx);
}

/* WHAT: Own the isolated clock. WHY: Expiry tests must not depend on wall time.
 * HOW: 1. Start at a fixed epoch. 2. Let the expired case advance this value. */
static time_t *
fixture_clock(void)
{
    static time_t now = FIXTURE_NOW;
    return &now;
}

/* WHAT: Replace the parser's time call. WHY: Exercise actual expiry handling.
 * HOW: 1. Read the fixture clock. 2. Preserve time(2)'s optional output value. */
time_t
__wrap_time(time_t *result)
{
    time_t now = *fixture_clock();
    if (result != NULL) {
        *result = now;
    }
    return now;
}

/* WHAT: Accept parser diagnostics. WHY: Expected errors need a valid log sink.
 * HOW: 1. Assert nginx supplied a log and format; no token data is emitted. */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{
    assert(log != NULL && format != NULL);
    (void) level;
    (void) error;
}

/* WHAT: Issue and decode one valid fixture token. WHY: Reuse the real encoder.
 * HOW: 1. Issue scoped credentials. 2. Decode with the production b64 helper. */
static size_t
issue_fixture(ngx_log_t *log, const char *subject, u_char *binary, size_t capacity)
{
    char token[BRIX_MACAROON_ISSUE_OUT_MAX];
    ssize_t length;

    assert(brix_macaroon_issue(log, (const u_char *) FIXTURE_ROOT_KEY,
        sizeof(FIXTURE_ROOT_KEY) - 1, "fixture-origin", subject,
        "DOWNLOAD", "/", FIXTURE_EXPIRY, token, sizeof(token)) == NGX_OK);
    length = b64url_decode(token, strlen(token), binary, capacity);
    assert(length > 46);
    assert(brix_macaroon_packet_len(binary + length - 46) == 46);
    return (size_t) length;
}

/* WHAT: Validate one root token. WHY: Root expiry and signature checks must run.
 * HOW: 1. Supply empty claims and capture storage. 2. Call the actual parser. */
static int
validate_fixture(ngx_log_t *log, const u_char *binary, size_t length,
    brix_token_claims_t *claims)
{
    brix_macaroon_tp_t caveats[1];
    int count = 0;
    macaroon_parse_input_t input = {
        .log = log,
        .key = (const u_char *) FIXTURE_ROOT_KEY,
        .key_len = sizeof(FIXTURE_ROOT_KEY) - 1,
        .claims = claims,
        .tp_arr = caveats,
        .n_tp = &count,
        .max_tp = 1
    };

    memset(claims, 0, sizeof(*claims));
    return macaroon_parse_core(&input, binary, length);
}

/* WHAT: Validate bytes in discharge mode with no nested capture allowance.
 * WHY: A discharge carrying cid+vid must be rejected, not silently flattened.
 * HOW: Supply the fixture key and claims while leaving capture fields absent. */
static int
validate_discharge_fixture(ngx_log_t *log, const u_char *binary, size_t length,
    brix_token_claims_t *claims)
{
    macaroon_parse_input_t input = {
        .log = log,
        .key = (const u_char *)FIXTURE_ROOT_KEY,
        .key_len = sizeof(FIXTURE_ROOT_KEY) - 1,
        .claims = claims,
    };

    memset(claims, 0, sizeof(*claims));
    return macaroon_parse_core(&input, binary, length);
}

/* WHAT: Build a valid custom caveat sequence and optionally append a vid.
 * WHY: Grammar and attenuation cases must keep framing/HMAC otherwise valid.
 * HOW: Begin with one id, append supplied cids, optional cid+vid, expiry, sig. */
static size_t
build_custom_fixture(u_char *binary, size_t capacity, const char **caveats,
    size_t caveat_count, size_t vid_len)
{
    fixture_builder_t builder;
    u_char vid[BRIX_MACAROON_VID_LEN + 32];
    size_t caveat_index;

    assert(vid_len <= sizeof(vid));
    memset(vid, 0x5a, sizeof(vid));
    fixture_builder_begin(&builder, binary, capacity, "custom-subject");
    for (caveat_index = 0; caveat_index < caveat_count; caveat_index++) {
        fixture_builder_cid(&builder, caveats[caveat_index]);
    }
    if (vid_len > 0) {
        fixture_builder_cid(&builder, "discharge-id");
        fixture_builder_vid(&builder, vid, vid_len);
    }
    fixture_builder_cid(&builder, "before:2030-01-01T00:00:00Z");
    return fixture_builder_finish(&builder);
}

/* WHAT: Check trusted claims. WHY: Accepting the signature must retain scope.
 * HOW: 1. Check attribution and expiry. 2. Require the requested read-only scope. */
static void
assert_fixture_claims(const brix_token_claims_t *claims, const char *subject)
{
    assert(strcmp(claims->sub, subject) == 0);
    assert(strcmp(claims->iss, "fixture-origin") == 0);
    assert(claims->exp == FIXTURE_EXPIRY && claims->groups[0] == '\0');
    assert(claims->scope_count == 1);
    assert(strcmp(claims->scopes[0].path, "/") == 0);
    assert(claims->scopes[0].read && !claims->scopes[0].write);
    assert(!claims->scopes[0].create && !claims->scopes[0].modify);
}

/* WHAT: Run the production issuer round-trip and its basic signature negatives.
 * WHY: Strict grammar must retain byte-exact compatibility with valid tokens.
 * HOW: Issue/decode, validate claims, then tamper, truncate, or expire by case. */
static void
run_issued_case(ngx_log_t *log, const char *case_name)
{
    brix_token_claims_t claims;
    u_char binary[BRIX_MACAROON_ISSUE_OUT_MAX];
    const char *subject;
    size_t length;

    subject = strcmp(case_name, "normal") == 0
              ? "roundtrip-0" : "roundtrip-72";
    length = issue_fixture(log, subject, binary, sizeof(binary));
    assert(binary[length - 1] == (strcmp(case_name, "normal") == 0
                                  ? 0xaa : 0x0a));
    assert(validate_fixture(log, binary, length, &claims) == 0);
    assert_fixture_claims(&claims, subject);

    if (strcmp(case_name, "tampered") == 0) {
        binary[length - 1] ^= 1;
        assert(validate_fixture(log, binary, length, &claims) == -1);
    } else if (strcmp(case_name, "truncated") == 0) {
        assert(validate_fixture(log, binary, length - 1, &claims) == -1);
    } else if (strcmp(case_name, "expired") == 0) {
        *fixture_clock() = FIXTURE_EXPIRY + 1;
        assert(validate_fixture(log, binary, length, &claims) == -1);
    }
}

/* WHAT: Verify repeated activity caveats use OR-within and AND-between rules.
 * WHY: Appending UPLOAD to a DOWNLOAD-only token must not add write authority.
 * HOW: Build valid signed caveats and assert union control or intersection. */
static void
run_activity_case(ngx_log_t *log, const char *case_name)
{
    const char *union_caveats[] = {"activity:DOWNLOAD,UPLOAD"};
    const char *narrow_caveats[] = {
        "activity:DOWNLOAD,UPLOAD", "activity:DOWNLOAD"
    };
    const char *disjoint_caveats[] = {
        "activity:DOWNLOAD", "activity:UPLOAD"
    };
    const char **caveats = union_caveats;
    size_t caveat_count = 1;
    brix_token_claims_t claims;
    u_char binary[BRIX_MACAROON_ISSUE_OUT_MAX];
    size_t length;

    if (strcmp(case_name, "repeated-activity-read") == 0) {
        caveats = narrow_caveats;
        caveat_count = 2;
    } else if (strcmp(case_name, "repeated-activity-disjoint") == 0) {
        caveats = disjoint_caveats;
        caveat_count = 2;
    }
    length = build_custom_fixture(binary, sizeof(binary), caveats,
                                  caveat_count, 0);
    assert(validate_fixture(log, binary, length, &claims) == 0);
    if (strcmp(case_name, "activity-union-control") == 0) {
        assert(claims.scope_count == 2);
        assert(brix_token_check_read(claims.scopes, claims.scope_count, "/x"));
        assert(brix_token_check_write(claims.scopes, claims.scope_count, "/x"));
    } else if (strcmp(case_name, "repeated-activity-read") == 0) {
        assert(claims.scope_count == 1 && claims.scopes[0].read);
        assert(!brix_token_check_write(claims.scopes, claims.scope_count, "/x"));
    } else {
        assert(claims.scope_count == 0);
        assert(!brix_token_check_read(claims.scopes, claims.scope_count, "/x"));
        assert(!brix_token_check_write(claims.scopes, claims.scope_count, "/x"));
    }
}

/* WHAT: Exercise strict packet order, terminal signature, and exact vid bounds.
 * WHY: Ambiguous/trailing packets and truncated encrypted keys bypass caveats.
 * HOW: Keep framing/HMAC valid where relevant and require parser rejection. */
static void
run_grammar_case(ngx_log_t *log, const char *case_name)
{
    brix_token_claims_t claims;
    fixture_builder_t builder;
    u_char binary[BRIX_MACAROON_ISSUE_OUT_MAX];
    u_char vid[BRIX_MACAROON_VID_LEN];
    u_char long_vid[BRIX_MACAROON_VID_LEN + 1];
    size_t length;

    memset(vid, 0x41, sizeof(vid));
    memset(long_vid, 0x42, sizeof(long_vid));
    if (strcmp(case_name, "leading-zero-signature") == 0) {
        u_char issued[BRIX_MACAROON_ISSUE_OUT_MAX];
        u_char zeros[32] = {0};
        size_t issued_len = issue_fixture(log, "roundtrip-0", issued,
                                          sizeof(issued));
        memset(&builder, 0, sizeof(builder));
        builder.data = binary;
        builder.capacity = sizeof(binary);
        fixture_append_packet(&builder, "signature", zeros, sizeof(zeros), 0);
        assert(issued_len <= builder.capacity - builder.length);
        memcpy(binary + builder.length, issued, issued_len);
        assert(validate_fixture(log, binary, builder.length + issued_len,
                                &claims) == -1);
        return;
    }
    if (strcmp(case_name, "signature-not-terminal") == 0
        || strcmp(case_name, "duplicate-signature") == 0
        || strcmp(case_name, "trailing-residue") == 0) {
        length = issue_fixture(log, "roundtrip-0", binary, sizeof(binary));
        if (strcmp(case_name, "signature-not-terminal") == 0) {
            memset(&builder, 0, sizeof(builder));
            builder.data = binary;
            builder.capacity = sizeof(binary);
            builder.length = length;
            fixture_append_packet(&builder, "location",
                (const u_char *)"late", 4, 1);
            length = builder.length;
        } else if (strcmp(case_name, "duplicate-signature") == 0) {
            assert(length >= 46 && length + 46 <= sizeof(binary));
            memcpy(binary + length, binary + length - 46, 46);
            length += 46;
        } else {
            memcpy(binary + length, "xyz", 3);
            length += 3;
        }
        assert(validate_fixture(log, binary, length, &claims) == -1);
        return;
    }

    fixture_builder_begin(&builder, binary, sizeof(binary), "grammar-subject");
    if (strcmp(case_name, "duplicate-identifier") == 0) {
        fixture_append_packet(&builder, "identifier",
            (const u_char *)"second", 6, 1);
    } else if (strcmp(case_name, "unknown-packet") == 0) {
        fixture_append_packet(&builder, "mystery",
            (const u_char *)"condition", 9, 1);
    } else if (strcmp(case_name, "orphan-vid") == 0) {
        fixture_builder_vid(&builder, vid, sizeof(vid));
    } else if (strcmp(case_name, "overlong-vid") == 0) {
        fixture_builder_cid(&builder, "discharge-id");
        fixture_builder_vid(&builder, long_vid, sizeof(long_vid));
    } else if (strcmp(case_name, "excess-caveats") == 0) {
        fixture_builder_cid(&builder, "discharge-one");
        fixture_builder_vid(&builder, vid, sizeof(vid));
        fixture_builder_cid(&builder, "discharge-two");
        fixture_builder_vid(&builder, vid, sizeof(vid));
    } else if (strcmp(case_name, "nested-third-party") == 0) {
        fixture_builder_cid(&builder, "discharge-id");
        fixture_builder_vid(&builder, vid, sizeof(vid));
    } else if (strcmp(case_name, "exact-vid-control") == 0) {
        fixture_builder_cid(&builder, "discharge-id");
        fixture_builder_vid(&builder, vid, sizeof(vid));
    }
    fixture_builder_cid(&builder, "before:2030-01-01T00:00:00Z");
    length = fixture_builder_finish(&builder);
    if (strcmp(case_name, "exact-vid-control") == 0) {
        assert(validate_fixture(log, binary, length, &claims) == 0);
    } else if (strcmp(case_name, "nested-third-party") == 0) {
        assert(validate_discharge_fixture(log, binary, length, &claims) == -1);
    } else {
        assert(validate_fixture(log, binary, length, &claims) == -1);
    }
}

/* WHAT: Check malformed caveats, discharge attenuation, and bounded bundles.
 * WHY: Signed-but-unsupported conditions and extra discharges must fail closed.
 * HOW: Use valid HMAC fixtures and direct structured-scope intersection checks. */
static void
run_caveat_case(ngx_log_t *log, const char *case_name)
{
    brix_token_claims_t claims;
    brix_token_claims_t restriction;
    u_char binary[BRIX_MACAROON_ISSUE_OUT_MAX];
    const char *caveat;
    size_t length;

    if (strcmp(case_name, "discharge-attenuation") == 0) {
        memset(&claims, 0, sizeof(claims));
        memset(&restriction, 0, sizeof(restriction));
        memcpy(claims.scope_raw, "storage.read:/ storage.write:/",
               sizeof("storage.read:/ storage.write:/"));
        claims.scope_count = brix_token_parse_scopes(
            claims.scope_raw, claims.scopes, BRIX_MAX_TOKEN_SCOPES);
        memcpy(restriction.scope_raw, "storage.read:/restricted",
               sizeof("storage.read:/restricted"));
        restriction.scope_count = brix_token_parse_scopes(
            restriction.scope_raw, restriction.scopes, BRIX_MAX_TOKEN_SCOPES);
        assert(macaroon_intersect_claim_scopes(log, &claims, &restriction)
               == NGX_OK);
        assert(claims.scope_count == 1 && claims.scopes[0].read);
        assert(!claims.scopes[0].write);
        assert(strcmp(claims.scopes[0].path, "/restricted") == 0);
        return;
    }
    if (strcmp(case_name, "excess-discharges") == 0) {
        const char *bundle = "AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA";
        assert(brix_macaroon_validate_bundle(log, bundle, strlen(bundle),
            (const u_char *)FIXTURE_ROOT_KEY, sizeof(FIXTURE_ROOT_KEY) - 1,
            &claims) == -1);
        return;
    }
    if (strcmp(case_name, "excess-path-caveats") == 0) {
        const char *paths[] = {
            "path:/one", "path:/one/two", "path:/one/two/three",
            "path:/one/two/three/four", "path:/one/two/three/four/five",
            "path:/one/two/three/four/five/six",
            "path:/one/two/three/four/five/six/seven",
            "path:/one/two/three/four/five/six/seven/eight",
            "path:/one/two/three/four/five/six/seven/eight/nine",
        };
        length = build_custom_fixture(binary, sizeof(binary), paths, 9, 0);
        assert(validate_fixture(log, binary, length, &claims) == -1);
        return;
    }
    if (strcmp(case_name, "unknown-caveat") == 0) {
        caveat = "role:administrator";
    } else if (strcmp(case_name, "malformed-activity") == 0) {
        caveat = "activity:DOWNLOAD,";
    } else {
        caveat = "before:2030-02-31T00:00:00Z";
    }
    length = build_custom_fixture(binary, sizeof(binary), &caveat, 1, 0);
    assert(validate_fixture(log, binary, length, &claims) == -1);
}

#ifndef BRIX_MACAROON_FIXTURE_LIBRARY
/* WHAT: Drive one named native security regression. WHY: Each pytest case gets
 * an isolated process and deterministic assertion output. HOW: Dispatch the
 * bounded case families after checking the single required argument. */
int
main(int argc, char **argv)
{
    ngx_log_t log = {.log_level = NGX_LOG_INFO};
    const char *case_name;

    assert(argc == 2);
    case_name = argv[1];
    if (strcmp(case_name, "normal") == 0
        || strcmp(case_name, "signature-newline") == 0
        || strcmp(case_name, "tampered") == 0
        || strcmp(case_name, "truncated") == 0
        || strcmp(case_name, "expired") == 0) {
        run_issued_case(&log, case_name);
    } else if (strcmp(case_name, "unknown-caveat") == 0
               || strcmp(case_name, "malformed-activity") == 0
               || strcmp(case_name, "malformed-before") == 0
               || strcmp(case_name, "excess-path-caveats") == 0
               || strcmp(case_name, "discharge-attenuation") == 0
               || strcmp(case_name, "excess-discharges") == 0) {
        run_caveat_case(&log, case_name);
    } else if (strstr(case_name, "activity") != NULL) {
        run_activity_case(&log, case_name);
    } else if (strcmp(case_name, "decrypt-exact-control") == 0) {
        u_char vid[BRIX_MACAROON_VID_LEN];
        u_char key[32] = {0};
        u_char plain[32];
        u_char output[32] = {0};
        memset(plain, 0xa5, sizeof(plain));
        fixture_encrypt_vid(key, plain, vid);
        assert(macaroon_decrypt_vid(vid, sizeof(vid), key, output) == 0);
        assert(memcmp(output, plain, sizeof(plain)) == 0);
    } else if (strcmp(case_name, "decrypt-overlong") == 0) {
        u_char vid[256] = {0};
        u_char key[32] = {0};
        u_char output[32] = {0};
        assert(macaroon_decrypt_vid(vid, sizeof(vid), key, output) == -1);
    } else {
        run_grammar_case(&log, case_name);
    }
    return 0;
}
#endif

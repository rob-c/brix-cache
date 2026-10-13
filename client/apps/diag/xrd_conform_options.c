/*
 * xrd conform remote-run option parser.
 *
 * WHAT: Parses the common accept/full/watch option contract into typed state.
 * WHY: Keeping parsing separate leaves execution and safety review tractable.
 * HOW: Seed secure defaults, consume common client flags, then phase flags.
 */
#include "xrd_conform_internal.h"

#include <openssl/rand.h>

/* ---- Consume a required option value ----
 *
 * WHAT: Returns the next argv value and advances index, or NULL when absent.
 * WHY: Every valued option needs identical bounds checking.
 * HOW: Test argc, increment the shared cursor once, return that slot.
 */
static const char *
option_value(int argc, char **argv, int *index)
{
    if (*index + 1 >= argc) return NULL;
    (*index)++;
    return argv[*index];
}

/* ---- Parse a positive unsigned ceiling ----
 *
 * WHAT: Returns zero and fills output, or -1 for malformed/zero/overflow input.
 * WHY: Resource ceilings must not silently become unlimited after bad input.
 * HOW: strtoul with full-string, errno and unsigned-range validation.
 */
static int
parse_unsigned(const char *value, unsigned *out)
{
    char *end = NULL;
    unsigned long parsed;

    if (value == NULL || value[0] == '\0') return -1;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0
        || parsed > UINT_MAX) return -1;
    *out = (unsigned) parsed;
    return 0;
}

/* ---- Parse the reference mode ----
 *
 * WHAT: Returns zero for strict/ecosystem/both and fills the typed enum.
 * WHY: The report may never silently choose among competing authorities.
 * HOW: Perform exact string matches and refuse every other spelling.
 */
static int
parse_reference(const char *value, brix_conform_reference_mode *out)
{
    if (strcmp(value, "ecosystem") == 0) {
        *out = BRIX_CONFORM_REFERENCE_ECOSYSTEM;
        return 0;
    }
    if (strcmp(value, "strict") == 0) {
        *out = BRIX_CONFORM_REFERENCE_STRICT;
        return 0;
    }
    if (strcmp(value, "both") == 0) {
        *out = BRIX_CONFORM_REFERENCE_BOTH;
        return 0;
    }
    return -1;
}

/* ---- Parse the inconclusive exit policy ----
 *
 * WHAT: Returns zero for divergent/inconclusive/any and fills the enum.
 * WHY: CI must explicitly choose whether uncertainty fails its gate.
 * HOW: Exact string matching; unknown policy is a usage error.
 */
static int
parse_fail_mode(const char *value, brix_conform_fail_mode *out)
{
    if (strcmp(value, "divergent") == 0) {
        *out = BRIX_CONFORM_FAIL_DIVERGENT;
        return 0;
    }
    if (strcmp(value, "inconclusive") == 0) {
        *out = BRIX_CONFORM_FAIL_INCONCLUSIVE;
        return 0;
    }
    if (strcmp(value, "any") == 0) {
        *out = BRIX_CONFORM_FAIL_ANY;
        return 0;
    }
    return -1;
}

/* ---- Validate a role profile ----
 *
 * WHAT: Returns one only for a profile named by Phase 118 section 31.1.
 * WHY: An unknown profile must not silently exclude every catalogue row.
 * HOW: Compare against the frozen role vocabulary.
 */
static int
profile_valid(const char *value)
{
    static const char *const profiles[] = {
        "data", "manager", "cache", "proxy", "tape", "s3", "http",
        "tls", "tpc", "full"
    };
    size_t index;

    for (index = 0; index < sizeof(profiles) / sizeof(profiles[0]); index++) {
        if (strcmp(value, profiles[index]) == 0) return 1;
    }
    return 0;
}

/* WHAT: Add one validated role to the repeatable profile selector. WHY: The
 * Phase-118 CLI permits a deployment to compose roles. HOW: Append one exact
 * token into owned bounded storage, rejecting overflow and duplicates. */
static int
profile_add(xrd_conform_run *run, const char *value)
{
    size_t used;
    size_t needed;

    if (strstr(run->profiles, value) != NULL) return 0;
    used = strlen(run->profiles);
    needed = strlen(value) + (used == 0 ? 1U : 2U);
    if (needed > sizeof(run->profiles) - used) return -1;
    if (used != 0) run->profiles[used++] = ',';
    snprintf(run->profiles + used, sizeof(run->profiles) - used, "%s", value);
    run->config.profile = run->profiles;
    return 0;
}

/* WHAT: Parse profile/reference/budget/failure policy options. WHY: Policies
 * must be typed before network work. HOW: Validate each exact vocabulary. */
static int
parse_policy_option(int argc, char **argv, int *index, xrd_conform_run *run)
{
    const char *flag = argv[*index];
    const char *value;

    if (strcmp(flag, "--profile") == 0) {
        value = option_value(argc, argv, index);
        if (value == NULL || !profile_valid(value)) return -1;
        if (profile_add(run, value) != 0) return -1;
        run->profile_explicit = 1;
        return 1;
    }
    if (strcmp(flag, "--reference") == 0) {
        value = option_value(argc, argv, index);
        return value != NULL && parse_reference(value,
            &run->config.reference_mode) == 0 ? 1 : -1;
    }
    if (strcmp(flag, "--budget") == 0) {
        value = option_value(argc, argv, index);
        return value != NULL && brix_conform_budget_parse(value,
            &run->config.budget) == 0 ? 1 : -1;
    }
    if (strcmp(flag, "--fail-on") == 0) {
        value = option_value(argc, argv, index);
        return value != NULL && parse_fail_mode(value,
            &run->config.fail_mode) == 0 ? 1 : -1;
    }
    return 0;
}

static int parse_valued(int argc, char **argv, int *index,
    xrd_conform_run *run);

/* ---- Consume the complete option vector ----
 *
 * WHAT: Returns zero or usage code 4 after applying all command options.
 * WHY: Separating iteration from final validation keeps both auditable.
 * HOW: Offer common flags, booleans, then valued Phase-118 flags.
 */
static int
parse_options(int argc, char **argv, xrd_conform_run *run)
{
    int index;

    for (index = 4; index < argc; index++) {
        int parsed;
        const char *flag = argv[index];

        if (brix_opts_parse_arg(&run->opts, argc, argv, &index)) continue;
        if (strcmp(flag, "--allow-mutate") == 0) {
            run->config.allow_mutate = 1;
            continue;
        }
        if (strcmp(flag, "--allow-disrupt") == 0) {
            run->config.allow_disrupt = 1;
            continue;
        }
        parsed = parse_valued(argc, argv, &index, run);
        if (parsed == 1) continue;
        BRIX_CLIENT_LOG("ERROR", "xrd conform: invalid option '%s'\n", flag);
        return 4;
    }
    return 0;
}

/* ---- Prepare the reproducibility key ----
 *
 * WHAT: Parses a supplied key or creates a cryptographically random one.
 * WHY: Every generated case and planted byte must be reproducible by key.
 * HOW: Use the shared strict parser or RAND_bytes, then format canonical hex.
 */
static int
prepare_run_key(xrd_conform_run *run)
{
    if (run->config.run_key != NULL) {
        if (brix_conform_key_parse(run->config.run_key, &run->key) != 0) {
            BRIX_CLIENT_LOG("ERROR",
                "xrd conform: --run-key requires 32 hex characters\n");
            return 4;
        }
    } else if (RAND_bytes(run->key.bytes, sizeof(run->key.bytes)) != 1) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: random run-key generation failed\n");
        return 3;
    }
    brix_conform_key_format(&run->key, run->key_hex);
    run->config.run_key = run->key_hex;
    return 0;
}

/* ---- Validate cross-option safety authority ----
 *
 * WHAT: Returns zero only when capture/mutate/disrupt authority is complete.
 * WHY: No network operation may begin from an ambiguous safety configuration.
 * HOW: Refuse raw capture, unbound mutation, or mismatched disruption target.
 */
static int
validate_authority(const xrd_conform_run *run)
{
    const char *adv_owner = NULL;
    size_t verify_index;
    int adv_verified = 0;

    if (run->opts.capture != NULL) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: --capture is managed internally; use --out for scrubbed artifacts\n");
        return 4;
    }
    if (run->config.allow_mutate && run->config.scratch == NULL) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: --allow-mutate requires --scratch\n");
        return 4;
    }
    if (run->config.allow_disrupt
        && (run->config.confirm_target == NULL
            || strcmp(run->config.confirm_target, run->config.target) != 0)) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: --allow-disrupt requires --confirm-target exactly matching the target\n");
        return 4;
    }
    if ((run->quota_target == NULL) != (run->capacity_target == NULL)) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: --quota-target and --capacity-target must be supplied together\n");
        return 4;
    }
    if (run->webdav_outside_target != NULL && !run->config.allow_mutate) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: --webdav-outside-fixture requires --allow-mutate and --scratch\n");
        return 4;
    }
    if (run->move_fixture_target != NULL && !run->config.allow_mutate) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: --move-fixture requires --allow-mutate and --scratch\n");
        return 4;
    }
    if (run->adv_fixture_kind != NULL) {
        if (strcmp(run->adv_fixture_kind, "generator-gap") == 0)
            adv_owner = "ADV-007";
        else if (strcmp(run->adv_fixture_kind, "nondeterministic") == 0)
            adv_owner = "ADV-009";
        else if (strcmp(run->adv_fixture_kind, "authority-bypass") == 0)
            adv_owner = "ADV-010";
        for (verify_index = 0;
                adv_owner != NULL
                && verify_index < run->negative_verify_count;
                verify_index++)
            if (strcmp(run->negative_verify[verify_index], adv_owner) == 0)
                adv_verified = 1;
        if (!adv_verified) {
            BRIX_CLIENT_LOG("ERROR",
                "xrd conform: --adv-fixture requires its matching --verify-negative clause\n");
            return 4;
        }
    }
    return 0;
}

/* WHAT: Parse path/filter/report valued options. WHY: Keep parser branches
 * reviewable under the native complexity gate. HOW: Exact flag-to-field map. */
static int
parse_selector_option(int argc, char **argv, int *index, xrd_conform_run *run)
{
    const char *flag = argv[*index];

    if (strcmp(flag, "--scratch") == 0) {
        run->config.scratch = option_value(argc, argv, index);
        return run->config.scratch != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--families") == 0) {
        run->config.families = option_value(argc, argv, index);
        return run->config.families != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--exclude") == 0) {
        run->config.exclude = option_value(argc, argv, index);
        return run->config.exclude != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--only") == 0) {
        run->config.only = option_value(argc, argv, index);
        return run->config.only != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--verify-negative") == 0) {
        const brix_conform_clause *clause;
        const char *value = option_value(argc, argv, index);
        size_t verify_index;

        if (value == NULL
            || run->negative_verify_count >= XRDC_CONFORM_NEGATIVE_VERIFY_MAX)
            return -1;
        clause = brix_conform_clause_find(value);
        if (clause == NULL || strncmp(clause->negative_fixture,
                "not-applicable/", 15) == 0) return -1;
        for (verify_index = 0; verify_index < run->negative_verify_count;
                verify_index++)
            if (strcmp(run->negative_verify[verify_index], value) == 0)
                return -1;
        run->negative_verify[run->negative_verify_count++] = value;
        return 1;
    }
    if (strcmp(flag, "--out") == 0) {
        run->config.out_dir = option_value(argc, argv, index);
        return run->config.out_dir != NULL ? 1 : -1;
    }
    return 0;
}

/* WHAT: Parse reproduction and multi-plane valued options. WHY: These values
 * govern artifact identity rather than family selection. HOW: Exact field map. */
static int
parse_reproduction_option(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    const char *flag = argv[*index];

    if (strcmp(flag, "--baseline") == 0) {
        run->config.baseline = option_value(argc, argv, index);
        return run->config.baseline != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--run-key") == 0) {
        run->config.run_key = option_value(argc, argv, index);
        return run->config.run_key != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--confirm-target") == 0) {
        run->config.confirm_target = option_value(argc, argv, index);
        return run->config.confirm_target != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--adv-observer") == 0) {
        run->adv_observer = option_value(argc, argv, index);
        return run->adv_observer != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--adv-fixture") == 0) {
        const char *value = option_value(argc, argv, index);

        if (value == NULL || run->adv_fixture_kind != NULL
            || (strcmp(value, "generator-gap") != 0
                && strcmp(value, "nondeterministic") != 0
                && strcmp(value, "authority-bypass") != 0)) return -1;
        run->adv_fixture_kind = value;
        return 1;
    }
    if (strcmp(flag, "--also") == 0) {
        const char *value = option_value(argc, argv, index);

        if (value == NULL || run->also_count >= 8) return -1;
        run->also[run->also_count++] = value;
        return 1;
    }
    {
        int parsed = xrd_conform_parse_special_fixture(argc, argv, index, run);
        if (parsed != 0) return parsed;
    }
    if (strcmp(flag, "--error-fixture") == 0) {
        const char *value = option_value(argc, argv, index);
        const char *equals;
        size_t name_length;
        size_t fixture_index;
        int is_http = 0;
        xrd_conform_error_fixture *fixture;

        if (value == NULL
            || run->error_fixture_count >= XRDC_CONFORM_ERROR_FIXTURE_MAX)
            return -1;
        equals = strchr(value, '=');
        if (equals == NULL || equals == value || equals[1] == '\0') return -1;
        name_length = (size_t) (equals - value);
        if (name_length > 5
            && memcmp(value + name_length - 5, "@http", 5) == 0) {
            name_length -= 5;
            is_http = 1;
        }
        if (name_length >= sizeof(run->error_fixtures[0].errno_name)
            || !xrd_conform_error_fixture_name_valid(value, name_length))
            return -1;
        for (fixture_index = 0; fixture_index < run->error_fixture_count;
                fixture_index++)
            if (run->error_fixtures[fixture_index].is_http == is_http
                && strlen(run->error_fixtures[fixture_index].errno_name)
                    == name_length
                && memcmp(run->error_fixtures[fixture_index].errno_name,
                    value, name_length) == 0) return -1;
        fixture = &run->error_fixtures[run->error_fixture_count++];
        memcpy(fixture->errno_name, value, name_length);
        fixture->errno_name[name_length] = '\0';
        fixture->target = equals + 1;
        fixture->is_http = is_http;
        return 1;
    }
    {
        int parsed = xrd_conform_parse_security_fixture(argc, argv, index, run);

        if (parsed != 0) return parsed;
    }
    {
        int parsed = xrd_conform_parse_denied_fixture(argc, argv, index, run);

        if (parsed != 0) return parsed;
    }
    {
        int parsed = xrd_conform_parse_mutation_fixture(argc, argv, index, run);

        if (parsed != 0) return parsed;
    }
    {
        int parsed = xrd_conform_parse_open_fixture(argc, argv, index, run);

        if (parsed != 0) return parsed;
    }
    {
        int parsed = xrd_conform_parse_locate_fixture(argc, argv, index, run);

        if (parsed != 0) return parsed;
    }
    {
        int parsed = xrd_conform_parse_token_fixture(argc, argv, index, run);

        if (parsed != 0) return parsed;
    }
    if (strcmp(flag, "--quota-target") == 0) {
        run->quota_target = option_value(argc, argv, index);
        return run->quota_target != NULL ? 1 : -1;
    }
    if (strcmp(flag, "--capacity-target") == 0) {
        run->capacity_target = option_value(argc, argv, index);
        return run->capacity_target != NULL ? 1 : -1;
    }
    return 0;
}

/* WHAT: Parse numeric ceilings. WHY: Bad numbers must never become unlimited.
 * HOW: Reuse the positive-unsigned parser for all three knobs. */
static int
parse_ceiling_option(int argc, char **argv, int *index, xrd_conform_run *run)
{
    const char *flag = argv[*index];
    const char *value;
    unsigned parsed;

    if (strcmp(flag, "--wall-seconds") == 0) {
        value = option_value(argc, argv, index);
        return value != NULL && parse_unsigned(value,
            &run->config.wall_seconds) == 0 ? 1 : -1;
    }
    if (strcmp(flag, "--request-limit") == 0) {
        value = option_value(argc, argv, index);
        return value != NULL && parse_unsigned(value,
            &run->config.request_limit) == 0 ? 1 : -1;
    }
    if (strcmp(flag, "--byte-limit") == 0) {
        value = option_value(argc, argv, index);
        if (value == NULL || parse_unsigned(value, &parsed) != 0) return -1;
        run->config.byte_limit = parsed;
        return 1;
    }
    if (strcmp(flag, "--http-request-line-limit") == 0) {
        value = option_value(argc, argv, index);
        if (value == NULL || parse_unsigned(value, &parsed) != 0
            || parsed <= 15) return -1;
        run->http_request_line_limit = parsed;
        return 1;
    }
    return 0;
}

/* WHAT: Parse watch sampling controls. WHY: Watch-only knobs must not inflate
 * the common ceiling parser. HOW: Reuse positive bounded integers. */
static int
parse_watch_option(int argc, char **argv, int *index, xrd_conform_run *run)
{
    const char *flag = argv[*index];
    const char *value;

    if (strcmp(flag, "--watch-interval-seconds") == 0) {
        value = option_value(argc, argv, index);
        return value != NULL && parse_unsigned(value,
            &run->config.watch_interval_seconds) == 0 ? 1 : -1;
    }
    if (strcmp(flag, "--watch-cycles") == 0) {
        value = option_value(argc, argv, index);
        return value != NULL && parse_unsigned(value,
            &run->config.watch_cycles) == 0 ? 1 : -1;
    }
    return 0;
}

/* ---- Parse one Phase-118 valued option ----
 *
 * WHAT: Returns 1 consumed, 0 unrecognized, or -1 invalid/missing value.
 * WHY: Independent option groups keep parsing flat and auditable.
 * HOW: Offer the flag to policy, selector and ceiling parsers in order.
 */
static int
parse_valued(int argc, char **argv, int *index, xrd_conform_run *run)
{
    int parsed = parse_policy_option(argc, argv, index, run);

    if (parsed != 0) return parsed;
    parsed = parse_selector_option(argc, argv, index, run);
    if (parsed != 0) return parsed;
    parsed = parse_reproduction_option(argc, argv, index, run);
    if (parsed != 0) return parsed;
    parsed = parse_ceiling_option(argc, argv, index, run);
    return parsed != 0 ? parsed : parse_watch_option(argc, argv, index, run);
}

/* ---- Parse and validate a complete remote conformance run ----
 *
 * WHAT: Returns zero with run state or Phase-118 usage code 4.
 * WHY: Invalid safety/profile/key input must stop before any network request.
 * HOW: Seed defaults, consume target/options, validate key and authority pairs.
 */
int
xrd_conform_parse_run(int argc, char **argv, xrd_conform_run *run)
{
    int rc;

    if (argc < 4 || xrd_conform_run_defaults(argv[2], run) != 0) return 4;
    run->config.target = argv[3];
    rc = parse_options(argc, argv, run);
    if (rc != 0) return rc;
    if (run->config.shape != BRIX_CONFORM_RUN_WATCH
        && (run->config.watch_interval_seconds != 0
            || run->config.watch_cycles != 0)) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: watch options require watch mode\n");
        return 4;
    }
    rc = prepare_run_key(run);
    return rc != 0 ? rc : validate_authority(run);
}

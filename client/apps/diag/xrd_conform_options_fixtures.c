/* Phase-118 cross-plane fixture option parsing. */
#include "xrd_conform_internal.h"

static int
named_target(const char *value, const char *const *names, size_t name_count,
    char *name_out, size_t name_capacity, const char **target_out)
{
    const char *equals = strchr(value, '=');
    size_t name_length;
    size_t index;

    if (equals == NULL || equals == value || equals[1] == '\0') return -1;
    name_length = (size_t) (equals - value);
    if (name_length >= name_capacity) return -1;
    for (index = 0; index < name_count; index++)
        if (strlen(names[index]) == name_length
            && memcmp(value, names[index], name_length) == 0) {
            memcpy(name_out, value, name_length);
            name_out[name_length] = '\0';
            *target_out = equals + 1;
            return 0;
        }
    return -1;
}

static int
parse_readonly_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    static const char *const planes[] = { "webdav", "s3", "oci", "gridftp" };
    xrd_conform_readonly_fixture *fixture;
    size_t fixture_index;

    if (*index + 1 >= argc || run->readonly_fixture_count
            >= XRDC_CONFORM_READONLY_FIXTURE_MAX) return -1;
    fixture = &run->readonly_fixtures[run->readonly_fixture_count];
    if (named_target(argv[++(*index)], planes,
            sizeof(planes) / sizeof(planes[0]), fixture->plane,
            sizeof(fixture->plane), &fixture->target) != 0) return -1;
    for (fixture_index = 0; fixture_index < run->readonly_fixture_count;
            fixture_index++)
        if (strcmp(run->readonly_fixtures[fixture_index].plane,
                fixture->plane) == 0) return -1;
    run->readonly_fixture_count++;
    return 1;
}

static int
parse_auth_fixture(int argc, char **argv, int *index, xrd_conform_run *run)
{
    static const char *const protocols[] = {
        "gsi", "ztn", "krb5", "sss", "unix", "host", "pwd"
    };
    xrd_conform_auth_fixture *fixture;
    size_t fixture_index;

    if (*index + 1 >= argc || run->auth_fixture_count
            >= XRDC_CONFORM_AUTH_FIXTURE_MAX) return -1;
    fixture = &run->auth_fixtures[run->auth_fixture_count];
    if (named_target(argv[++(*index)], protocols,
            sizeof(protocols) / sizeof(protocols[0]), fixture->protocol,
            sizeof(fixture->protocol), &fixture->target) != 0) return -1;
    for (fixture_index = 0; fixture_index < run->auth_fixture_count;
            fixture_index++)
        if (strcmp(run->auth_fixtures[fixture_index].protocol,
                fixture->protocol) == 0) return -1;
    run->auth_fixture_count++;
    return 1;
}

static int
parse_tls_fixture(int argc, char **argv, int *index, xrd_conform_run *run)
{
    static const char *const classes[] = {
        "login", "data", "gpf", "session", "tpc"
    };
    xrd_conform_tls_fixture *fixture;
    size_t fixture_index;

    if (*index + 1 >= argc || run->tls_fixture_count
            >= XRDC_CONFORM_TLS_FIXTURE_MAX) return -1;
    fixture = &run->tls_fixtures[run->tls_fixture_count];
    if (named_target(argv[++(*index)], classes,
            sizeof(classes) / sizeof(classes[0]), fixture->request_class,
            sizeof(fixture->request_class), &fixture->target) != 0) return -1;
    for (fixture_index = 0; fixture_index < run->tls_fixture_count;
            fixture_index++)
        if (strcmp(run->tls_fixtures[fixture_index].request_class,
                fixture->request_class) == 0) return -1;
    run->tls_fixture_count++;
    return 1;
}

int
xrd_conform_parse_security_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    const char *flag = argv[*index];

    if (strcmp(flag, "--readonly-fixture") == 0) {
        return parse_readonly_fixture(argc, argv, index, run);
    }
    if (strcmp(flag, "--auth-fixture") == 0) {
        return parse_auth_fixture(argc, argv, index, run);
    }
    if (strcmp(flag, "--tls-cleartext-fixture") == 0) {
        return parse_tls_fixture(argc, argv, index, run);
    }
    return 0;
}

static int
parse_single_fixture_target(int argc, char **argv, int *index,
    const char **target)
{
    if (*index + 1 >= argc || *target != NULL) return -1;
    *target = argv[++(*index)];
    return 1;
}

static int
parse_fixture_kind(int argc, char **argv, int *index, const char **selected,
    const char *const *kinds, size_t kind_count)
{
    const char *value;
    size_t kind_index;

    if (*index + 1 >= argc || *selected != NULL) return -1;
    value = argv[++(*index)];
    for (kind_index = 0; kind_index < kind_count; kind_index++) {
        if (strcmp(value, kinds[kind_index]) == 0) {
            *selected = value;
            return 1;
        }
    }
    return -1;
}

int
xrd_conform_parse_special_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    static const char *const cache_kinds[] = {
        "partial", "filling", "capacity", "corrupt"
    };
    static const char *const tpc_kinds[] = {
        "source-denied", "destination-abort", "egress-blocked",
        "native-and-webdav", "scoped-delegation"
    };
    const char *flag = argv[*index];

    if (strcmp(flag, "--webdav-outside-fixture") == 0) {
        return parse_single_fixture_target(argc, argv, index,
            &run->webdav_outside_target);
    }
    if (strcmp(flag, "--move-fixture") == 0) {
        return parse_single_fixture_target(argc, argv, index,
            &run->move_fixture_target);
    }
    if (strcmp(flag, "--cache-fixture") == 0) {
        return parse_fixture_kind(argc, argv, index, &run->cache_fixture_kind,
            cache_kinds, sizeof(cache_kinds) / sizeof(cache_kinds[0]));
    }
    if (strcmp(flag, "--tpc-fixture") == 0) {
        return parse_fixture_kind(argc, argv, index, &run->tpc_fixture_kind,
            tpc_kinds, sizeof(tpc_kinds) / sizeof(tpc_kinds[0]));
    }
    return 0;
}

/* WHAT: Parse one denied/mutation plane fixture into a typed destination.
 * WHY: Both option families have identical vocabulary and duplicate rules.
 * HOW: Parse through named_target, reject duplicate planes, then publish once.
 */
static int
parse_plane_fixture(int argc, char **argv, int *index, const char *option,
    xrd_conform_denied_fixture *fixtures, size_t *count)
{
    static const char *const planes[] = { "root", "http", "s3" };
    xrd_conform_denied_fixture candidate;
    size_t fixture_index;

    if (strcmp(argv[*index], option) != 0) {
        return 0;
    }
    if (*index + 1 >= argc || *count >= XRDC_CONFORM_DENIED_FIXTURE_MAX) {
        return -1;
    }
    if (named_target(argv[++(*index)], planes, sizeof(planes) / sizeof(planes[0]),
            candidate.plane, sizeof(candidate.plane), &candidate.target) != 0) {
        return -1;
    }
    for (fixture_index = 0; fixture_index < *count; fixture_index++) {
        if (strcmp(fixtures[fixture_index].plane, candidate.plane) == 0) {
            return -1;
        }
    }
    fixtures[(*count)++] = candidate;
    return 1;
}

/* WHAT: Parse a denied-fixture option. WHY: Share the plane contract.
 * HOW: Bind its own destination array and count to the common parser. */
int
xrd_conform_parse_denied_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    return parse_plane_fixture(argc, argv, index, "--denied-fixture",
        run->denied_fixtures, &run->denied_fixture_count);
}

/* WHAT: Parse a mutation-fixture option. WHY: Share the plane contract.
 * HOW: Bind its own destination array and count to the common parser. */
int
xrd_conform_parse_mutation_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    return parse_plane_fixture(argc, argv, index, "--mutation-fixture",
        run->mutation_fixtures, &run->mutation_fixture_count);
}

/* WHAT: Parse one externally asserted OPEN lifecycle topology.
 * WHY: Read-only ordering, offline-nowait, and idle-handle survival cannot be
 *      inferred from an ordinary online object.
 * HOW: Accept each closed-vocabulary kind once and retain its exact ROOT URL. */
int
xrd_conform_parse_open_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    static const char *const kinds[] = {
        "readonly", "staged-nowait", "idle"
    };
    const char *value;
    size_t fixture_index;
    xrd_conform_open_fixture candidate;

    if (strcmp(argv[*index], "--open-fixture") != 0) return 0;
    if (*index + 1 >= argc
        || run->open_fixture_count >= XRDC_CONFORM_OPEN_FIXTURE_MAX) return -1;
    value = argv[++(*index)];
    if (named_target(value, kinds, sizeof(kinds) / sizeof(kinds[0]),
            candidate.kind, sizeof(candidate.kind), &candidate.target) != 0) return -1;
    for (fixture_index = 0; fixture_index < run->open_fixture_count;
            fixture_index++)
        if (strcmp(run->open_fixtures[fixture_index].kind, candidate.kind) == 0) return -1;
    run->open_fixtures[run->open_fixture_count++] = candidate;
    return 1;
}

/* WHAT: Parse one externally asserted locate cache or latency topology.
 * WHY: Refresh freshness and nowait latency cannot be inferred from a normal
 *      endpoint whose cache state and slow members are unknown.
 * HOW: Accept each closed-vocabulary fixture kind once with its ROOT URL. */
int
xrd_conform_parse_locate_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    static const char *const kinds[] = { "refresh", "slow" };
    xrd_conform_locate_fixture *fixture;
    const char *value;
    size_t fixture_index;

    if (strcmp(argv[*index], "--locate-fixture") != 0) return 0;
    if (*index + 1 >= argc
        || run->locate_fixture_count >= XRDC_CONFORM_LOCATE_FIXTURE_MAX)
        return -1;
    value = argv[++(*index)];
    fixture = &run->locate_fixtures[run->locate_fixture_count];
    if (named_target(value, kinds, sizeof(kinds) / sizeof(kinds[0]),
            fixture->kind, sizeof(fixture->kind), &fixture->target) != 0)
        return -1;
    for (fixture_index = 0; fixture_index < run->locate_fixture_count;
            fixture_index++)
        if (strcmp(run->locate_fixtures[fixture_index].kind,
                fixture->kind) == 0) return -1;
    run->locate_fixture_count++;
    return 1;
}

int
xrd_conform_parse_token_fixture(int argc, char **argv, int *index,
    xrd_conform_run *run)
{
    static const char *const kinds[] = {
        "audience", "expired", "not-yet-valid", "issuer"
    };
    xrd_conform_token_fixture *fixture;
    const char *value;
    size_t fixture_index;

    if (strcmp(argv[*index], "--token-fixture") != 0) return 0;
    if (*index + 1 >= argc
        || run->token_fixture_count >= XRDC_CONFORM_TOKEN_FIXTURE_MAX) return -1;
    value = argv[++(*index)];
    fixture = &run->token_fixtures[run->token_fixture_count];
    if (named_target(value, kinds, sizeof(kinds) / sizeof(kinds[0]),
            fixture->kind, sizeof(fixture->kind), &fixture->target) != 0)
        return -1;
    for (fixture_index = 0; fixture_index < run->token_fixture_count;
            fixture_index++)
        if (strcmp(run->token_fixtures[fixture_index].kind,
                fixture->kind) == 0) return -1;
    run->token_fixture_count++;
    return 1;
}

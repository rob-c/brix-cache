/* Phase-118 multi-frame ROOT directory-listing probe. */
#include "xrd_conform_internal.h"

#define LARGE_DIR_ENTRIES 276U
#define LARGE_DIR_NAME_LEN 240U
#define EXACT_DIR_ENTRIES 10000U

static int large_dir_reserve(xrd_conform_execution *execution,
    brix_status *status);

static int
dir_row_active(xrd_conform_execution *execution, const char *id)
{
    brix_conform_result *result = xrd_conform_result_find(execution, id);

    return result != NULL
        && result->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static const brix_dirent *
find_entry(const brix_dirent *entries, size_t count, const char *name)
{
    size_t index;

    for (index = 0; index < count; index++)
        if (strcmp(entries[index].name, name) == 0) return &entries[index];
    return NULL;
}

/* WHAT: Compare dcksm tokens to independent Qcksum answers.
 * WHY: Presence alone does not establish that a directory checksum is true.
 * HOW: Use the two byte-identical planted files, require a token for each, and
 *      compare its hex half with a separate typed checksum query. */
void
xrd_conform_probe_dir_checksums(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *base)
{
    static const char *const names[] = { "alpha", "beta" };
    brix_dirent *entries = NULL;
    brix_status status;
    size_t count = 0;
    size_t index;
    int pass = 1;

    if (!dir_row_active(execution, "DIR-008")) return;
    brix_status_clear(&status);
    if (!large_dir_reserve(execution, &status)
        || brix_dirlist_cksum(connection, base->path, "adler32", &entries,
            &count, &status) != 0) pass = 0;
    for (index = 0; pass && index < sizeof(names) / sizeof(names[0]); index++) {
        xrd_conform_scratch_object object;
        const brix_dirent *entry = find_entry(entries, count, names[index]);
        char leaf[64];
        char expected[129];
        char token[144];
        int length;

        length = snprintf(leaf, sizeof(leaf), "brix-conform-dir/%s",
            names[index]);
        if (length < 0 || (size_t) length >= sizeof(leaf)
            || brix_conform_scratch_path(execution->run->config.scratch, leaf,
                object.path, sizeof(object.path)) != 0
            || entry == NULL || entry->checksum[0] == '\0'
            || !large_dir_reserve(execution, &status)
            || brix_query_cksum(connection, object.path, "adler32", expected,
                sizeof(expected), &status) != 0) {
            pass = 0;
            break;
        }
        length = snprintf(token, sizeof(token), "adler32:%s", expected);
        if (length < 0 || (size_t) length >= sizeof(token)
            || strcmp(entry->checksum, token) != 0) pass = 0;
    }
    xrd_conform_result_set(execution, "DIR-008",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "dcksm-matches-independent-Qcksum"
             : "dcksm-Qcksum-mismatch",
        "adler32 token equals kXR_Qcksum for alpha and beta",
        status.msg);
    free(entries);
}

static int
large_dir_path(xrd_conform_execution *execution, size_t index,
    xrd_conform_scratch_object *object, char name[XRDC_NAME_MAX])
{
    char leaf[XRDC_PATH_MAX];
    int written;

    written = snprintf(name, XRDC_NAME_MAX, "%03zu-", index);
    if (written < 0 || (size_t) written >= LARGE_DIR_NAME_LEN) return -1;
    memset(name + written, 'x', LARGE_DIR_NAME_LEN - (size_t) written);
    name[LARGE_DIR_NAME_LEN] = '\0';
    written = snprintf(leaf, sizeof(leaf), "brix-conform-dir-large/%s", name);
    if (written < 0 || (size_t) written >= sizeof(leaf)) return -1;
    return brix_conform_scratch_path(execution->run->config.scratch, leaf,
        object->path, sizeof(object->path));
}

static int
large_dir_entry_index(const char *name, size_t *index)
{
    size_t value;
    size_t pos;

    if (name == NULL || strlen(name) != LARGE_DIR_NAME_LEN
        || name[3] != '-' || name[0] < '0' || name[0] > '9'
        || name[1] < '0' || name[1] > '9'
        || name[2] < '0' || name[2] > '9') return 0;
    value = (size_t) (name[0] - '0') * 100U
        + (size_t) (name[1] - '0') * 10U + (size_t) (name[2] - '0');
    if (value >= LARGE_DIR_ENTRIES) return 0;
    for (pos = 4; pos < LARGE_DIR_NAME_LEN; pos++)
        if (name[pos] != 'x') return 0;
    *index = value;
    return 1;
}

static int
large_dir_reserve(xrd_conform_execution *execution, brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

static void
large_dir_result(xrd_conform_execution *execution, int pass,
    const char *failure, const brix_status *status)
{
    xrd_conform_result_set(execution, "DIR-007",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "oksofar-listing-reassembled-exactly" : failure,
        "one-or-more kXR_oksofar frames; 276 exact unique names",
        status == NULL ? NULL : status->msg);
}

/* WHAT: Force a plain listing beyond one 64 KiB response frame.
 * WHY: A successful small listing does not exercise continuation framing.
 * HOW: Create 276 scratch-confined long-name directories, observe the client's
 *      kXR_oksofar count, validate the exact set, then remove every fixture. */
void
xrd_conform_probe_large_dir(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object base;
    xrd_conform_scratch_object child;
    brix_dirent *entries = NULL;
    unsigned char seen[LARGE_DIR_ENTRIES] = { 0 };
    brix_status status;
    char name[XRDC_NAME_MAX];
    size_t continuations = 0;
    size_t created = 0;
    size_t count = 0;
    size_t index;
    int exact = 1;
    int listed = 0;

    if (!dir_row_active(execution, "DIR-007")) return;
    if (execution->requests > execution->run->config.request_limit
        || execution->run->config.request_limit - execution->requests
            < LARGE_DIR_ENTRIES * 2U + 3U) {
        xrd_conform_result_set(execution, "DIR-007",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "ceiling:request-limit-needs-555", NULL, NULL);
        return;
    }
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-dir-large", base.path, sizeof(base.path)) != 0)
        return;
    brix_status_clear(&status);
    if (!large_dir_reserve(execution, &status)
        || brix_mkdir(connection, base.path, 0755, 1, &status) != 0) {
        large_dir_result(execution, 0, "large-directory-create-failed",
            &status);
        return;
    }
    for (index = 0; index < LARGE_DIR_ENTRIES; index++) {
        if (large_dir_path(execution, index, &child, name) != 0
            || !large_dir_reserve(execution, &status)
            || brix_mkdir(connection, child.path, 0755, 0, &status) != 0)
            break;
        created++;
    }
    if (created == LARGE_DIR_ENTRIES
        && large_dir_reserve(execution, &status)
        && brix_dirlist_observe(connection, base.path, 0, &entries, &count,
            &continuations, &status) == 0) listed = 1;
    if (listed && count == LARGE_DIR_ENTRIES) {
        for (index = 0; index < count; index++) {
            size_t entry_index;

            if (!large_dir_entry_index(entries[index].name, &entry_index)
                || seen[entry_index]) {
                exact = 0;
                break;
            }
            seen[entry_index] = 1;
        }
        for (index = 0; exact && index < LARGE_DIR_ENTRIES; index++)
            exact = seen[index] != 0;
    } else {
        exact = 0;
    }
    free(entries);
    for (index = created; index > 0; index--) {
        if (large_dir_path(execution, index - 1U, &child, name) == 0
            && large_dir_reserve(execution, &status))
            brix_rmdir(connection, child.path, &status);
    }
    if (large_dir_reserve(execution, &status))
        brix_rmdir(connection, base.path, &status);
    large_dir_result(execution,
        listed && continuations > 0 && exact,
        listed && continuations == 0 ? "large-listing-was-not-continued"
            : "continued-listing-name-set-mismatch", &status);
}

static int
exact_dir_name(const char *name, size_t *entry_index)
{
    size_t index;
    size_t value = 0;

    if (name == NULL || strlen(name) != 5U) return 0;
    for (index = 0; index < 5U; index++) {
        if (name[index] < '0' || name[index] > '9') return 0;
        value = value * 10U + (size_t) (name[index] - '0');
    }
    if (value >= EXACT_DIR_ENTRIES) return 0;
    *entry_index = value;
    return 1;
}

static int
exact_dir_listing(const brix_dirent *entries, size_t count)
{
    unsigned char seen[EXACT_DIR_ENTRIES] = { 0 };
    size_t index;

    if (count != EXACT_DIR_ENTRIES) return 0;
    for (index = 0; index < count; index++) {
        size_t entry_index;

        if (!exact_dir_name(entries[index].name, &entry_index)
            || seen[entry_index]) return 0;
        seen[entry_index] = 1;
    }
    for (index = 0; index < EXACT_DIR_ENTRIES; index++)
        if (!seen[index]) return 0;
    return 1;
}

/* WHAT: Validate the dedicated 10,000-entry directory twice.
 * WHY: The continuation probe is large enough to cross a frame boundary but
 *      cannot establish completeness at realistic high entry counts.
 * HOW: Read an externally planted, scratch-confined deterministic fixture
 *      twice and require the exact five-digit name set on both passes. */
void
xrd_conform_probe_dir_10000(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object fixture;
    brix_dirent *first = NULL;
    brix_dirent *second = NULL;
    brix_status status;
    size_t first_count = 0;
    size_t second_count = 0;
    int first_ok;
    int second_ok;

    if (!dir_row_active(execution, "DIR-010")) return;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-dir-10000", fixture.path,
            sizeof(fixture.path)) != 0) return;
    brix_status_clear(&status);
    if (!large_dir_reserve(execution, &status)) {
        xrd_conform_result_set(execution, "DIR-010",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "ceiling:before-first-listing",
            "two requests available for the dedicated fixture", status.msg);
        return;
    }
    if (brix_dirlist(connection, fixture.path, 0, &first, &first_count,
            &status) != 0) {
        xrd_conform_result_set(execution, "DIR-010",
            status.kxr == kXR_NotFound ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                                      : BRIX_CONFORM_VERDICT_DIVERGENT,
            status.kxr == kXR_NotFound ? "fixture-missing:dir-10000"
                                       : "first-listing-failed",
            "externally planted names 00000 through 09999", status.msg);
        free(first);
        return;
    }
    first_ok = exact_dir_listing(first, first_count);
    if (!large_dir_reserve(execution, &status)) {
        xrd_conform_result_set(execution, "DIR-010",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "ceiling:before-second-listing",
            "two requests available for the dedicated fixture", status.msg);
        free(first);
        return;
    }
    if (brix_dirlist(connection, fixture.path, 0, &second, &second_count,
            &status) != 0) {
        xrd_conform_result_set(execution, "DIR-010",
            BRIX_CONFORM_VERDICT_DIVERGENT, "second-listing-failed",
            "two complete identical 10,000-entry listings", status.msg);
        free(first);
        free(second);
        return;
    }
    second_ok = exact_dir_listing(second, second_count);
    xrd_conform_result_set(execution, "DIR-010",
        first_ok && second_ok && first_count == second_count
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        first_ok && second_ok && first_count == second_count
            ? "two-exact-10000-entry-listings"
            : "10000-entry-listing-mismatch",
        "both listings contain exactly names 00000 through 09999", NULL);
    free(first);
    free(second);
}

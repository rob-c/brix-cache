/* Phase-118 scratch-confined ROOT namespace mutation probes. */
#include "xrd_conform_probe_helpers.h"


static int
scratch_path(xrd_conform_execution *execution, const char *leaf,
    xrd_conform_scratch_object *object)
{
    return brix_conform_scratch_path(execution->run->config.scratch, leaf,
        object->path, sizeof(object->path));
}


static int
create_file(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const void *data, size_t length,
    brix_status *status)
{
    brix_file file;
    int rc;

    brix_status_clear(status);
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    if (brix_file_open_write(connection, object->path, 1, 0, &file,
            status) != 0) return -1;
    rc = xrd_conform_reserve_status(execution, length, status)
        ? brix_file_write(connection, &file, 0, data, length, status) : -1;
    if (!xrd_conform_reserve_status(execution, 0, status)
        || brix_file_close(connection, &file, status) != 0) rc = -1;
    return rc;
}

static int
mkdir_object(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, int mode, int parents,
    brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_mkdir(connection, object->path, mode, parents, status);
}

static int
remove_object(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_rm(connection, object->path, status);
}

static int
rmdir_object(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_rmdir(connection, object->path, status);
}

static int
move_objects(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object,
    const xrd_conform_scratch_object *scratch_object, brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_mv(connection, object->path, scratch_object->path, status);
}

static int
chmod_object(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, int mode, brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_chmod(connection, object->path, mode, status);
}

static int
is_directory(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_statinfo *info,
    brix_status *status)
{
    brix_status_clear(status);
    if (!xrd_conform_reserve_status(execution, 0, status)) return 0;
    return brix_stat(connection, object->path, info, status) == 0
        && (info->flags & kXR_isDir) != 0;
}

static void
probe_mkdir(xrd_conform_execution *execution, brix_conn *connection,
    xrd_conform_scratch_object *base,
    xrd_conform_scratch_object *nested)
{
    brix_statinfo info;
    brix_status status;
    int rc;

    memset(&info, 0, sizeof(info));
    brix_status_clear(&status);
    rc = mkdir_object(execution, connection, base, 0750, 0, &status);
    xrd_conform_grade_status(execution, "MKD-001", rc == 0
        && is_directory(execution, connection, base, &info, &status),
        "mkdir-created-directory", "mkdir-did-not-create-directory", &status);
    xrd_conform_grade_status(execution, "MKD-006", info.have_ext == 0
        || (info.mode & 0777U) == 0750U,
        "created-mode-contained-defined-bits", "created-mode-mismatch", &status);

    brix_status_clear(&status);
    rc = mkdir_object(execution, connection, base, 0750, 0, &status);
    xrd_conform_grade_status(execution, "MKD-004", rc != 0 && status.kxr == kXR_ItExists,
        "existing-path-refused", "existing-path-not-ItExists", &status);

    brix_status_clear(&status);
    rc = mkdir_object(execution, connection, nested, 0755, 0, &status);
    xrd_conform_grade_status(execution, "MKD-003", rc != 0 && status.kxr == kXR_NotFound,
        "missing-parent-refused", "missing-parent-not-NotFound", &status);
    brix_status_clear(&status);
    rc = mkdir_object(execution, connection, nested, 0755, 1, &status);
    xrd_conform_grade_status(execution, "MKD-002", rc == 0
        && is_directory(execution, connection, nested, &info, &status),
        "mkdirpath-created-parents", "mkdirpath-failed", &status);
}

static int
move_overwrite_consistent(int first, int second, int first_kxr,
    int second_kxr)
{
    if (first == 0) return second == 0;
    return second != 0 && first_kxr == second_kxr;
}

static void
probe_move(xrd_conform_execution *execution, brix_conn *connection,
    xrd_conform_scratch_object *source, xrd_conform_scratch_object *target,
    xrd_conform_scratch_object *missing)
{
    static const uint8_t payload[] = "phase118-move";
    brix_statinfo info;
    brix_status status;
    int old_missing;
    int target_ok;
    int rc;
    int overwrite_first;
    int overwrite_second;
    int first_kxr;

    create_file(execution, connection, source, payload, sizeof(payload), &status);
    brix_status_clear(&status);
    rc = move_objects(execution, connection, source, target, &status);
    brix_status_clear(&status);
    old_missing = xrd_conform_reserve_status(execution, 0, &status)
        && brix_stat(connection, source->path, &info, &status) != 0
        && status.kxr == kXR_NotFound;
    brix_status_clear(&status);
    target_ok = xrd_conform_reserve_status(execution, 0, &status)
        && brix_stat(connection, target->path, &info, &status) == 0
        && info.size == (int64_t) sizeof(payload);
    xrd_conform_grade_status(execution, "MV-001", rc == 0 && old_missing && target_ok,
        "rename-preserved-object", "rename-state-mismatch", &status);
    xrd_conform_grade_status(execution, "MV-002", rc == 0 && target_ok,
        "deployed-move-framing-accepted", "move-framing-refused", &status);

    create_file(execution, connection, source, payload, sizeof(payload),
        &status);
    brix_status_clear(&status);
    overwrite_first = move_objects(execution, connection, source, target,
        &status);
    first_kxr = status.kxr;
    create_file(execution, connection, source, payload, sizeof(payload),
        &status);
    brix_status_clear(&status);
    overwrite_second = move_objects(execution, connection, source, target,
        &status);
    xrd_conform_grade_status(execution, "MV-003",
        move_overwrite_consistent(overwrite_first, overwrite_second,
                                  first_kxr, status.kxr),
        overwrite_first == 0 ? "existing-target-replaced-consistently"
                             : "existing-target-refused-consistently",
        "existing-target-policy-inconsistent", &status);
    if (overwrite_second != 0)
        remove_object(execution, connection, source, &status);

    brix_status_clear(&status);
    rc = move_objects(execution, connection, missing, source, &status);
    xrd_conform_grade_status(execution, "MV-004", rc != 0 && status.kxr == kXR_NotFound,
        "missing-source-refused", "missing-source-not-NotFound", &status);

    brix_status_clear(&status);
    rc = xrd_conform_reserve_status(execution, 0, &status)
        ? brix_mv(connection, target->path, "", &status) : -1;
    xrd_conform_grade_status(execution, "MV-007", rc != 0 && status.kxr == kXR_ArgMissing,
        "empty-move-path-refused", "empty-move-path-wrong-answer", &status);
}

static void
probe_remove(xrd_conform_execution *execution, brix_conn *connection,
    xrd_conform_scratch_object *file, xrd_conform_scratch_object *empty,
    xrd_conform_scratch_object *nonempty, xrd_conform_scratch_object *child,
    xrd_conform_scratch_object *missing)
{
    static const uint8_t byte = 0x5a;
    brix_status status;
    int rc;

    create_file(execution, connection, file, &byte, 1, &status);
    brix_status_clear(&status);
    rc = remove_object(execution, connection, file, &status);
    xrd_conform_grade_status(execution, "RM-001", rc == 0, "file-removed", "file-remove-failed",
        &status);

    mkdir_object(execution, connection, empty, 0755, 1, &status);
    brix_status_clear(&status);
    rc = rmdir_object(execution, connection, empty, &status);
    xrd_conform_grade_status(execution, "RM-002", rc == 0, "empty-directory-removed",
        "empty-directory-remove-failed", &status);

    mkdir_object(execution, connection, nonempty, 0755, 1, &status);
    create_file(execution, connection, child, &byte, 1, &status);
    brix_status_clear(&status);
    rc = rmdir_object(execution, connection, nonempty, &status);
    xrd_conform_grade_status(execution, "RM-003", rc != 0 && status.kxr == kXR_ItExists,
        "nonempty-directory-ItExists", "nonempty-directory-wrong-error", &status);
    brix_status_clear(&status);
    mkdir_object(execution, connection, empty, 0755, 1, &status);
    brix_status_clear(&status);
    rc = remove_object(execution, connection, empty, &status);
    xrd_conform_grade_status(execution, "RM-004", rc == 0 || status.kxr == kXR_isDirectory,
        rc == 0 ? "rm-removed-empty-directory"
                : "rm-empty-directory-refused-as-directory",
        "rm-empty-directory-wrong-error", &status);
    brix_status_clear(&status);
    rc = rmdir_object(execution, connection, child, &status);
    xrd_conform_grade_status(execution, "RM-005", rc != 0, "rmdir-file-refused",
        "rmdir-file-unlinked", &status);
    brix_status_clear(&status);
    rc = remove_object(execution, connection, missing, &status);
    xrd_conform_grade_status(execution, "RM-006", rc != 0 && status.kxr == kXR_NotFound,
        "missing-remove-NotFound", "missing-remove-wrong-error", &status);
    remove_object(execution, connection, child, &status);
    rmdir_object(execution, connection, nonempty, &status);
    rmdir_object(execution, connection, empty, &status);
}

static void
probe_chmod(xrd_conform_execution *execution, brix_conn *connection,
    xrd_conform_scratch_object *object)
{
    static const uint8_t byte = 0x43;
    brix_statinfo info;
    brix_status status;
    int rc;
    int restored;

    create_file(execution, connection, object, &byte, 1, &status);
    memset(&info, 0, sizeof(info));
    brix_status_clear(&status);
    rc = chmod_object(execution, connection, object, 0640, &status);
    brix_status_clear(&status);
    if (rc == 0) {
        if (xrd_conform_reserve_status(execution, 0, &status))
            rc = brix_stat(connection, object->path, &info, &status);
        else
            rc = -1;
    }
    xrd_conform_grade_status(execution, "CHM-001", rc == 0
        && (info.have_ext == 0 || (info.mode & 0777U) == 0640U),
        "chmod-reflected-by-stat", "chmod-mode-mismatch", &status);
    xrd_conform_grade_status(execution, "CHM-002", rc == 0 && (info.mode & ~0777U) == 0,
        "mode-contained-defined-bits", "undefined-mode-bits-visible", &status);

    brix_status_clear(&status);
    rc = chmod_object(execution, connection, object, 0000, &status);
    brix_status_clear(&status);
    restored = chmod_object(execution, connection, object, 0644, &status) == 0;
    xrd_conform_grade_status(execution, "CHM-004", rc != 0 || restored,
        "unreadable-mode-refused-or-reversible",
        "unreadable-mode-not-reversible", &status);
    remove_object(execution, connection, object, &status);
}

static int
has_exact_dir_names(const brix_dirent *entries, size_t count)
{
    int alpha = 0;
    int beta = 0;
    int empty = 0;
    size_t index;

    if (count != 3) return 0;
    for (index = 0; index < count; index++) {
        if (strcmp(entries[index].name, "alpha") == 0) alpha++;
        else if (strcmp(entries[index].name, "beta") == 0) beta++;
        else if (strcmp(entries[index].name, "empty") == 0) empty++;
        else return 0;
    }
    return alpha == 1 && beta == 1 && empty == 1;
}

static int
same_dir_names(const brix_dirent *left, size_t left_count,
    const brix_dirent *right, size_t right_count)
{
    size_t left_index;

    if (left_count != right_count) return 0;
    for (left_index = 0; left_index < left_count; left_index++) {
        size_t right_index;
        int found = 0;

        for (right_index = 0; right_index < right_count; right_index++) {
            if (strcmp(left[left_index].name, right[right_index].name) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) return 0;
    }
    return 1;
}

static void
describe_dir_names(char *out, size_t out_size, const brix_dirent *entries,
    size_t count)
{
    size_t index;
    size_t used = 0;

    if (out_size == 0) return;
    out[0] = '\0';
    for (index = 0; index < count && used + 1 < out_size; index++) {
        int written = snprintf(out + used, out_size - used, "%s%s",
            index == 0 ? "" : ",", entries[index].name);

        if (written < 0 || (size_t) written >= out_size - used) {
            out[out_size - 1] = '\0';
            return;
        }
        used += (size_t) written;
    }
}

/* WHAT: Plant control-byte names and compare plain/dStat listing treatment.
 * WHY: Newline framing must never split one stored name into phantom entries.
 * HOW: Create three scratch leaves, accept a defined storage refusal or require
 *      the two listing forms to expose exactly the same escaped/skipped set. */
static void
probe_directory_controls(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *base)
{
    static const uint8_t byte = 0x43;
    static const struct {
        const char *leaf;
        unsigned char control;
    } cases[] = {
        { "brix-conform-dir/control\nname", '\n' },
        { "brix-conform-dir/control\tname", '\t' },
        { "brix-conform-dir/control\177name", 0x7f },
    };
    xrd_conform_scratch_object objects[3];
    brix_dirent *plain = NULL;
    brix_dirent *dstat = NULL;
    brix_status status;
    size_t plain_count = 0;
    size_t dstat_count = 0;
    size_t index;
    size_t object_count = 0;
    int safe = 1;
    int created = 0;
    int plain_rc = 0;
    int dstat_rc = 0;
    char failure[256];
    char plain_names[80];
    char dstat_names[80];

    for (index = 0; index < sizeof(objects) / sizeof(objects[0]); index++) {
        int rc;

        if (brix_conform_scratch_control_path(
                execution->run->config.scratch, cases[index].leaf,
                cases[index].control,
                objects[index].path, sizeof(objects[index].path)) != 0) {
            safe = 0;
            break;
        }
        object_count++;
        rc = create_file(execution, connection, &objects[index], &byte, 1,
            &status);
        if (rc == 0) created++;
    }
    if (safe && created > 0 && xrd_conform_reserve_status(execution, 0, &status)) {
        plain_rc = brix_dirlist(connection, base->path, 0, &plain,
            &plain_count, &status);
        safe = plain_rc == 0;
    }
    if (safe && created > 0 && xrd_conform_reserve_status(execution, 0, &status)) {
        dstat_rc = brix_dirlist(connection, base->path, 1, &dstat,
            &dstat_count, &status);
        safe = dstat_rc == 0
            && same_dir_names(plain, plain_count, dstat, dstat_count);
    }
    describe_dir_names(plain_names, sizeof(plain_names), plain, plain_count);
    describe_dir_names(dstat_names, sizeof(dstat_names), dstat, dstat_count);
    snprintf(failure, sizeof(failure),
        "control-name-listing-inconsistent plain=%d/%zu[%s] "
        "dstat=%d/%zu[%s] kxr=%d",
        plain_rc, plain_count, plain_names, dstat_rc, dstat_count, dstat_names,
        status.kxr);
    xrd_conform_grade_status(execution, "DIR-004", safe,
        created > 0 ? "control-names-consistent-across-list-forms"
                    : "control-names-defined-refusal",
        failure, &status);
    free(plain);
    free(dstat);
    for (index = 0; index < object_count; index++)
        remove_object(execution, connection, &objects[index], &status);
}

static void
probe_directory_fixtures(xrd_conform_execution *execution,
    brix_conn *connection)
{
    static const uint8_t byte = 0x44;
    xrd_conform_scratch_object base, alpha, beta, empty;
    brix_dirent *entries = NULL;
    brix_status status;
    size_t count = 0;
    int listed = 0;
    int empty_listed = 0;

    if (scratch_path(execution, "brix-conform-dir", &base) != 0
        || scratch_path(execution, "brix-conform-dir/alpha", &alpha) != 0
        || scratch_path(execution, "brix-conform-dir/beta", &beta) != 0
        || scratch_path(execution, "brix-conform-dir/empty", &empty) != 0)
        return;
    brix_status_clear(&status);
    if (mkdir_object(execution, connection, &base, 0755, 1, &status) == 0
        && create_file(execution, connection, &alpha, &byte, 1, &status) == 0
        && create_file(execution, connection, &beta, &byte, 1, &status) == 0
        && mkdir_object(execution, connection, &empty, 0755, 0, &status) == 0
        && xrd_conform_reserve_status(execution, 0, &status)
        && brix_dirlist(connection, base.path, 0, &entries, &count,
            &status) == 0)
        listed = has_exact_dir_names(entries, count);
    xrd_conform_grade_status(execution, "DIR-001", listed, "exclusive-directory-exact-names",
        "exclusive-directory-name-set-mismatch", &status);
    free(entries);
    entries = NULL;
    count = 0;
    if (xrd_conform_reserve_status(execution, 0, &status)
        && brix_dirlist(connection, empty.path, 0, &entries, &count,
            &status) == 0)
        empty_listed = count == 0;
    xrd_conform_grade_status(execution, "DIR-005", empty_listed,
        "empty-directory-success-zero-entries",
        "empty-directory-listing-mismatch", &status);
    free(entries);
    probe_directory_controls(execution, connection, &base);
    xrd_conform_probe_dir_checksums(execution, connection, &base);
    remove_object(execution, connection, &alpha, &status);
    remove_object(execution, connection, &beta, &status);
    rmdir_object(execution, connection, &empty, &status);
    rmdir_object(execution, connection, &base, &status);
}

static int
namespace_mutation_active(xrd_conform_execution *execution)
{
    return xrd_conform_family_active(execution, "MKD")
        || xrd_conform_family_active(execution, "MV")
        || xrd_conform_family_active(execution, "RM")
        || xrd_conform_family_active(execution, "CHM");
}

static int
init_namespace_paths(xrd_conform_execution *execution,
    xrd_conform_scratch_object *objects)
{
    static const char *const leaves[] = {
        "brix-conform-ns", "brix-conform-ns/missing/child",
        "brix-conform-ns/source", "brix-conform-ns/target",
        "brix-conform-ns/absent", "brix-conform-ns/rm-file",
        "brix-conform-ns/empty", "brix-conform-ns/nonempty",
        "brix-conform-ns/nonempty/child", "brix-conform-ns/chmod"
    };
    size_t index;

    for (index = 0; index < sizeof(leaves) / sizeof(leaves[0]); index++) {
        if (scratch_path(execution, leaves[index], &objects[index]) != 0)
            return -1;
    }
    return 0;
}

void
xrd_conform_probe_namespace_mutations(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object objects[10];
    brix_status status;

    if (!namespace_mutation_active(execution)
        && !xrd_conform_family_active(execution, "DIR")) return;
    if (execution->run->config.only != NULL
        && strcmp(execution->run->config.only, "MV-005") == 0) return;
    if (xrd_conform_family_active(execution, "DIR"))
        probe_directory_fixtures(execution, connection);
    if (xrd_conform_family_active(execution, "DIR"))
        xrd_conform_probe_large_dir(execution, connection);
    if (xrd_conform_family_active(execution, "DIR"))
        xrd_conform_probe_dir_10000(execution, connection);
    if (!namespace_mutation_active(execution)) return;
    if (init_namespace_paths(execution, objects) != 0) return;
    probe_mkdir(execution, connection, &objects[0], &objects[1]);
    probe_move(execution, connection, &objects[2], &objects[3], &objects[4]);
    probe_remove(execution, connection, &objects[5], &objects[6], &objects[7],
        &objects[8], &objects[4]);
    probe_chmod(execution, connection, &objects[9]);
    brix_status_clear(&status);
    remove_object(execution, connection, &objects[3], &status);
    rmdir_object(execution, connection, &objects[1], &status);
    if (scratch_path(execution, "brix-conform-ns/missing", &objects[1]) == 0)
        rmdir_object(execution, connection, &objects[1], &status);
    rmdir_object(execution, connection, &objects[0], &status);
}

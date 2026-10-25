/*
 * Phase-118 secure artifact-bundle writer.
 *
 * WHAT: Creates all six canonical report files under one directory fd.
 * WHY: Reports may contain operational evidence and must not follow symlinks.
 * HOW: Open/create a private directory, use O_NOFOLLOW openat, then render.
 */
#include "conform/report_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

void brix_conform_report_markdown(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results);

typedef void (*report_writer)(FILE *, const brix_conform_report_meta *,
    const brix_conform_run_results *);

#define BRIX_CONFORM_BUNDLE_MARKER "report.complete.json"

/* ---- Render the generation-bound bundle completion record ----
 *
 * WHAT: Emits the schema, timestamp and tool version that commit one bundle.
 * WHY: Consumers must reject a JSON report whose later renderers did not finish.
 * HOW: Bind the marker to immutable metadata already present in report.json.
 */
static void
report_bundle_marker(FILE *out, const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    (void) results;
    fputs("{\"schema\":\"brix.conform.bundle.v1\",\"timestamp\":", out);
    brix_conform_json_string(out, meta->timestamp);
    fputs(",\"tool_version\":", out);
    brix_conform_json_string(out, meta->tool_version);
    fputs("}\n", out);
}

/* ---- Remove any prior completion record ----
 *
 * WHAT: Returns zero after removing the marker or finding it absent.
 * WHY: A failed rewrite must never inherit a successful older generation.
 * HOW: Unlink only the fixed marker name beneath the already-open directory.
 */
static int
report_bundle_marker_remove(int dirfd)
{
    if (unlinkat(dirfd, BRIX_CONFORM_BUNDLE_MARKER, 0) == 0) return 0;
    return errno == ENOENT ? 0 : -1;
}

/* ---- Open one private report file beneath a trusted directory fd ----
 *
 * WHAT: Returns an fdopen stream or NULL without following a final symlink.
 * WHY: An attacker must not redirect a report write onto another file.
 * HOW: openat with create/truncate, nofollow and mode 0600, then fdopen.
 */
static FILE *
report_file_open(int dirfd, const char *name)
{
    int fd = openat(dirfd, name,
        O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);

    if (fd < 0) return NULL;
    return fdopen(fd, "w");
}

/* ---- Render and durably close one report file ----
 *
 * WHAT: Returns zero only when opening, rendering, flushing and close succeed.
 * WHY: A partial artifact must make the overall run report failure explicit.
 * HOW: Open securely, invoke the pure writer, fflush, fsync, fclose.
 */
static int
report_one(int dirfd, const char *name, report_writer writer,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    FILE *stream = report_file_open(dirfd, name);
    int fd;
    int failed = 0;

    if (stream == NULL) return -1;
    writer(stream, meta, results);
    fd = fileno(stream);
    if (fflush(stream) != 0) failed = 1;
    if (!failed && fsync(fd) != 0) failed = 1;
    if (fclose(stream) != 0) failed = 1;
    return failed ? -1 : 0;
}

/* ---- Render every bundle member ----
 *
 * WHAT: Returns zero only when all six canonical formats are durable.
 * WHY: Sequential early returns keep failure provenance and complexity clear.
 * HOW: Invoke report_one for each frozen filename in artifact order.
 */
static int
report_all(int dirfd, const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    if (report_one(dirfd, "report.json", brix_conform_report_json, meta,
            results) != 0) return -1;
    if (report_one(dirfd, "report.md", brix_conform_report_markdown, meta,
            results) != 0) return -1;
    if (report_one(dirfd, "report.html", brix_conform_report_html, meta,
            results) != 0) return -1;
    if (report_one(dirfd, "report.sarif", brix_conform_report_sarif, meta,
            results) != 0) return -1;
    if (report_one(dirfd, "report.ecs.jsonl", brix_conform_report_ecs, meta,
            results) != 0) return -1;
    return report_one(dirfd, "report.diff.json", brix_conform_report_diff_json,
        meta, results);
}

/* ---- Open/create the private report directory ----
 *
 * WHAT: Returns a no-follow directory fd or -1 with a bounded diagnostic.
 * WHY: Directory setup and argument validation are one reusable failure seam.
 * HOW: Validate pointers, mkdir 0700, then open as a directory without links.
 */
static int
report_directory_open(const char *out_dir,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results, char *error, size_t error_size)
{
    int dirfd;

    if (out_dir == NULL || meta == NULL || results == NULL) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "invalid report arguments");
        return -1;
    }
    if (mkdir(out_dir, 0700) != 0 && errno != EEXIST) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "cannot create report directory: %s",
                strerror(errno));
        return -1;
    }
    dirfd = open(out_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0 && error != NULL && error_size > 0)
        snprintf(error, error_size, "cannot open report directory: %s",
            strerror(errno));
    return dirfd;
}

static int
report_bundle_fail(int dirfd, int remove_marker, const char *message,
    char *error, size_t error_size)
{
    int saved = errno;

    if (remove_marker) {
        (void) report_bundle_marker_remove(dirfd);
    }
    close(dirfd);
    if (error != NULL && error_size > 0) {
        snprintf(error, error_size, "%s: %s", message, strerror(saved));
    }
    errno = saved;
    return -1;
}

/* ---- Write the complete report artifact bundle ----
 *
 * WHAT: Returns zero after six durable artifacts and their commit marker.
 * WHY: CI and site review consumers require consistent simultaneous formats.
 * HOW: Create/open private dir without symlink following, render six files.
 */
int
brix_conform_report_bundle(const char *out_dir,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results, char *error, size_t error_size)
{
    int dirfd;

    dirfd = report_directory_open(out_dir, meta, results, error, error_size);
    if (dirfd < 0) return -1;
    if (report_bundle_marker_remove(dirfd) != 0) {
        return report_bundle_fail(dirfd, 0,
            "cannot clear report completion marker", error, error_size);
    }
    if (report_all(dirfd, meta, results) != 0) {
        return report_bundle_fail(dirfd, 0, "cannot write report bundle",
                                  error, error_size);
    }
    if (report_one(dirfd, BRIX_CONFORM_BUNDLE_MARKER, report_bundle_marker,
            meta, results) != 0) {
        return report_bundle_fail(dirfd, 1, "cannot commit report bundle",
                                  error, error_size);
    }
    if (fsync(dirfd) != 0) {
        return report_bundle_fail(dirfd, 1, "cannot sync report directory",
                                  error, error_size);
    }
    close(dirfd);
    if (error != NULL && error_size > 0) error[0] = '\0';
    return 0;
}

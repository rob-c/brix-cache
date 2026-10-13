/* Phase-118 bounded canonical-report baseline comparison. */
#include "conform/run.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define BASELINE_MAX (32U * 1024U * 1024U)

/* WHAT: Load a regular no-follow baseline under a hard size bound. WHY: A user
 * supplied baseline cannot cause unbounded allocation or device reads.
 * HOW: open/fstat/read exact bytes and append one private NUL terminator. */
static char *
baseline_load(const char *path, char *error, size_t error_size)
{
    struct stat info;
    char *body;
    size_t done = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);

    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_size < 0 || (uint64_t) info.st_size > BASELINE_MAX) {
        if (fd >= 0) close(fd);
        snprintf(error, error_size, "not a bounded regular report file");
        return NULL;
    }
    body = malloc((size_t) info.st_size + 1U);
    if (body == NULL) {
        close(fd);
        snprintf(error, error_size, "baseline allocation failed");
        return NULL;
    }
    while (done < (size_t) info.st_size) {
        ssize_t count = read(fd, body + done, (size_t) info.st_size - done);

        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            free(body); close(fd);
            snprintf(error, error_size, "baseline read failed");
            return NULL;
        }
        done += (size_t) count;
    }
    close(fd);
    body[done] = '\0';
    return body;
}

/* WHAT: Find one canonical result's verdict. WHY: Baselines compare stable ids,
 * never array positions. HOW: Locate generated id key then bounded verdict key. */
static const char *
baseline_verdict(const char *body, const char *id, char out[24])
{
    char needle[64];
    const char *row;
    const char *end;
    const char *value;
    size_t length;

    if ((size_t) snprintf(needle, sizeof(needle), "\"id\":\"%s\"", id)
        >= sizeof(needle)) return NULL;
    row = strstr(body, needle);
    if (row == NULL) return NULL;
    end = strchr(row, '}');
    value = strstr(row, "\"verdict\":\"");
    if (end == NULL || value == NULL || value >= end) return NULL;
    value += strlen("\"verdict\":\"");
    length = strcspn(value, "\"");
    if (length == 0 || length >= 24 || value + length > end) return NULL;
    memcpy(out, value, length); out[length] = '\0';
    return out;
}

/* WHAT: Mark results changed relative to one canonical prior report. WHY:
 * --baseline must expose transitions without hiding the full current ledger.
 * HOW: Validate schema, compare verdict strings by clause id, count later. */
int
brix_conform_apply_baseline(const char *path, brix_conform_run_results *results,
    char *error, size_t error_size)
{
    char *body;
    size_t index;

    if (path == NULL || results == NULL || error == NULL || error_size == 0)
        return -1;
    body = baseline_load(path, error, error_size);
    if (body == NULL) return -1;
    if (strstr(body, "\"schema\":\"brix.conform.v1\"") == NULL) {
        free(body);
        snprintf(error, error_size, "unsupported baseline schema");
        return -1;
    }
    for (index = 0; index < results->count; index++) {
        brix_conform_result *result = &results->results[index];
        const char *prior = baseline_verdict(body, result->clause->id,
            result->baseline_verdict);

        result->changed = prior == NULL || strcmp(prior,
            brix_conform_verdict_name(result->verdict)) != 0;
    }
    results->baseline_applied = 1;
    free(body);
    error[0] = '\0';
    return 0;
}

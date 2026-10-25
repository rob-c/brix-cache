/* Phase-118 CMS-007 independent xrdmapc/locate agreement probe. */
#include "xrd_conform_internal.h"
#include "core/compat/host_split.h"
#include "core/progname.h"
#include "platform/platform.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#define CMS_MAP_OUTPUT_MAX 8192
#define CMS_MAP_ARG_MAX 24
#define CONFORM_LOCATE_URL_MAX 512

static int
endpoint_is_numeric(const char *endpoint)
{
    char url_text[CONFORM_LOCATE_URL_MAX];
    struct in_addr ipv4;
    struct in6_addr ipv6;
    brix_url url;
    brix_status status;

    if ((size_t) snprintf(url_text, sizeof(url_text), "root://%s/", endpoint)
        >= sizeof(url_text)) return 0;
    brix_status_clear(&status);
    if (brix_url_parse(url_text, &url, &status) != 0) return 0;
    return inet_pton(AF_INET, url.host, &ipv4) == 1
        || inet_pton(AF_INET6, url.host, &ipv6) == 1;
}

/* WHAT: Compare ordinary and preferred-name locate endpoint forms.
 * WHY: LOC-007 requires the option to change address spelling, not routing.
 * HOW: Request kXR_prefname and compare numeric/hostname classifications. */
void
xrd_conform_probe_preferred_name(xrd_conform_execution *execution,
    brix_conn *primary, const char *path, const char *plain_endpoint)
{
    char reply[2048];
    char named_endpoint[320];
    char reason[64];
    brix_status status;
    int ok;

    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    ok = brix_locate_opts(primary, path, kXR_prefname, reply, sizeof(reply),
        &status) == 0
        && xrd_conform_first_data_endpoint(reply, named_endpoint,
            sizeof(named_endpoint)) == 0;
    xrd_conform_result_set(execution, "LOC-007",
        ok && endpoint_is_numeric(plain_endpoint)
            && !endpoint_is_numeric(named_endpoint)
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok && endpoint_is_numeric(plain_endpoint)
            && !endpoint_is_numeric(named_endpoint)
            ? "prefname-hostname-plain-address"
            : "prefname-address-family-mismatch",
        "plain locate address; kXR_prefname hostname", ok ? reply : status.msg);
}

static int
map_tool_path(char *path, size_t path_size)
{
    char self[PATH_MAX];
    const char *base;
    const char *prefix;
    char *slash;

    if (brix_plat_self_exe(self, sizeof(self)) != 0) return -1;
    slash = strrchr(self, '/');
    if (slash == NULL) return -1;
    base = slash + 1;
    prefix = brix_prog_prefix(base);
    *slash = '\0';
    if ((size_t) snprintf(path, path_size, "%s/%sxrdmapc", self, prefix)
        >= path_size || access(path, X_OK) != 0) return -1;
    return 0;
}

static void
add_flag(char **args, size_t *count, char *flag)
{
    if (*count < CMS_MAP_ARG_MAX - 1) args[(*count)++] = flag;
}

static void
add_value(char **args, size_t *count, char *flag, const char *value)
{
    if (value == NULL || *count >= CMS_MAP_ARG_MAX - 2) return;
    args[(*count)++] = flag;
    args[(*count)++] = (char *) value;
}

/* WHAT: Recreate the connection-relevant assessor options for the sibling.
 * WHY: CMS-007 must compare the same authenticated/TLS view of the manager.
 * HOW: Emit only public xrdmapc options; diagnostics and captures stay local. */
static void
map_tool_args(const xrd_conform_execution *execution, char *tool,
    char *stall, size_t stall_size, char **args)
{
    const brix_opts *opts = &execution->run->opts;
    size_t count = 0;

    args[count++] = tool;
    args[count++] = (char *) "--machine";
    if (opts->want_tls) add_flag(args, &count, (char *) "--tls");
    if (opts->notlsok) add_flag(args, &count, (char *) "--notlsok");
    if (!opts->verify_host)
        add_flag(args, &count, (char *) "--noverifyhost");
    add_value(args, &count, (char *) "--auth", opts->auth_force);
    add_value(args, &count, (char *) "--sss-vorg", opts->sss_vorg);
    add_value(args, &count, (char *) "--sss-role", opts->sss_role);
    add_value(args, &count, (char *) "--sss-endorse", opts->sss_endorse);
    add_value(args, &count, (char *) "--sss-creds-file",
        opts->sss_creds_file);
    if (opts->sss_sndlid)
        add_flag(args, &count, (char *) "--sss-sndlid");
    if (opts->no_retry) {
        add_flag(args, &count, (char *) "--no-retry");
    } else if (opts->max_stall_ms > 0) {
        snprintf(stall, stall_size, "%d", opts->max_stall_ms);
        add_value(args, &count, (char *) "--max-stall", stall);
    }
    args[count++] = (char *) execution->target;
    args[count] = NULL;
}

static int
map_tool_read_all(int fd, char *output, size_t output_size, int *overflow)
{
    size_t used = 0;

    while (used + 1 < output_size) {
        ssize_t got = read(fd, output + used, output_size - used - 1);

        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        used += (size_t) got;
    }
    *overflow = used + 1 == output_size;
    output[used] = '\0';
    return 0;
}

static pid_t
map_tool_wait(pid_t child, int *status)
{
    pid_t waited;

    do {
        waited = waitpid(child, status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited;
}

/* WHAT: Execute the exact co-installed xrdmapc and capture bounded stdout.
 * WHY: Calling a parser in-process would make CMS-007 circular and could not
 *      detect packaging or CLI transformation drift.
 * HOW: Resolve the sibling from this executable, fork/execv without a shell,
 *      cap output, and accept only a clean zero exit. */
static int
run_map_tool(const xrd_conform_execution *execution, char *output,
    size_t output_size)
{
    char tool[PATH_MAX];
    char stall[32];
    char *args[CMS_MAP_ARG_MAX];
    int fds[2];
    int status = 0;
    int overflow = 0;
    pid_t child;
    pid_t waited;

    if (map_tool_path(tool, sizeof(tool)) != 0) return -2;
    map_tool_args(execution, tool, stall, sizeof(stall), args);
    if (pipe(fds) != 0) return -1;
    child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (child == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(126);
        close(fds[1]);
        execv(tool, args);
        _exit(127);
    }
    close(fds[1]);
    (void) map_tool_read_all(fds[0], output, output_size, &overflow);
    close(fds[0]);
    waited = map_tool_wait(child, &status);
    if (overflow || waited != child) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int
machine_holder_set(const char *output, char *canonical,
    size_t canonical_size)
{
    char locate[CMS_MAP_OUTPUT_MAX];
    char copy[CMS_MAP_OUTPUT_MAX];
    char *line;
    char *save;
    size_t used = 0;
    size_t count = 0;

    if ((size_t) snprintf(copy, sizeof(copy), "%s", output) >= sizeof(copy))
        return -1;
    for (line = strtok_r(copy, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        char host[256];
        int port;
        size_t length = strlen(line);
        int written;

        if (length > 0 && line[length - 1] == '\r') line[--length] = '\0';
        if (length == 0 || strpbrk(line, " \t") != NULL
            || brix_split_host_port(line, host, sizeof(host), &port, 0) != 0
            || ++count > 32) return -1;
        written = snprintf(locate + used, sizeof(locate) - used,
            "%sS=%s", used == 0 ? "" : " ", line);
        if (written < 0 || (size_t) written >= sizeof(locate) - used)
            return -1;
        used += (size_t) written;
    }
    if (count == 0) return -1;
    return xrd_conform_canonical_holder_set(locate, canonical,
        canonical_size);
}

void
xrd_conform_probe_cms_map(xrd_conform_execution *execution,
    const char *locate_reply)
{
    char expected[2048];
    char received[2048];
    char output[CMS_MAP_OUTPUT_MAX];
    char reason[64];
    int rc;
    int agree;

    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        xrd_conform_result_set(execution, "CMS-007",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        return;
    }
    if (xrd_conform_canonical_holder_set(locate_reply, expected,
            sizeof(expected)) != 0) {
        xrd_conform_result_set(execution, "CMS-007",
            BRIX_CONFORM_VERDICT_DIVERGENT, "locate-holder-set-invalid",
            "bounded non-empty locate holder set", locate_reply);
        return;
    }
    rc = run_map_tool(execution, output, sizeof(output));
    if (rc != 0) {
        xrd_conform_result_set(execution, "CMS-007",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            rc == -2 ? "xrdmapc-sibling-unavailable" : "xrdmapc-map-failed",
            "co-installed xrdmapc --machine exits zero", NULL);
        return;
    }
    if (machine_holder_set(output, received, sizeof(received)) != 0) {
        xrd_conform_result_set(execution, "CMS-007",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "xrdmapc-machine-output-invalid",
            "one valid holder authority per line", output);
        return;
    }
    agree = strcmp(expected, received) == 0;
    xrd_conform_result_set(execution, "CMS-007",
        agree ? BRIX_CONFORM_VERDICT_CONFORMANT
              : BRIX_CONFORM_VERDICT_DIVERGENT,
        agree ? "xrdmapc-locate-holder-sets-agree"
              : "xrdmapc-locate-holder-set-mismatch",
        expected, received);
}

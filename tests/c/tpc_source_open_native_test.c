/* Real source-open wire negotiation with finite clock and transport failures. */
#include "tpc/engine/tpc_internal.h"
#include "tpc/outbound/source_internal.h"
#include <assert.h>
#include <signal.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    unsigned sends, sleeps, clocks, allocations;
    int armed;
} fixture_t;
static fixture_t *state(void) { return (fixture_t *)ngx_cycle; }
static int mode(const char *s) { return state() && state()->armed && !strcmp(state()->mode, s); }
int __real_tpc_send_all(brix_tpc_pull_t *, int, const void *, size_t);
int __wrap_tpc_send_all(brix_tpc_pull_t *t, int fd, const void *p, size_t n)
{
    state()->sends++;
    if (mode("send") || (mode("resend") && state()->sends == 2)) { errno = EPIPE; return -1; }
    return __real_tpc_send_all(t, fd, p, n);
}
unsigned __wrap_sleep(unsigned n)
{ assert(n <= TPC_OPEN_WAIT_RETRY_SEC); state()->sleeps++; return 0; }
time_t __real_time(time_t *);
time_t __wrap_time(time_t *out)
{
    if (mode("deadline")) {
        time_t now = 1000 + state()->clocks++ * (TPC_OPEN_RESOLVE_MAX_SEC + 1);
        if (out) { *out = now; } return now;
    }
    return __real_time(out);
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n)
{
    if (mode("allocation") && ++state()->allocations == 2) { errno = ENOMEM; return NULL; }
    return __real_malloc(n);
}

int main(int argc, char **argv)
{
    assert(argc == 5); signal(SIGPIPE, SIG_IGN); ngx_time_init();
    fixture_t f = {0}; f.mode = argv[3]; ngx_cycle = &f.cycle;
    brix_tpc_pull_t *t = calloc(1, sizeof(*t)); assert(t);
    t->primary_fd = atoi(argv[1]); strcpy(t->src_path, "/source");
    if (strstr(argv[2], "key")) { strcpy(t->tpc_key, "grant"); }
    if (strstr(argv[2], "org")) { strcpy(t->tpc_org, "alice@origin"); }
    if (strstr(argv[2], "cap")) { strcpy(t->redir_opaque, "cap.sym=opaque&cap.msg=proof"); }
    if (strstr(argv[2], "deleg")) { t->deleg_cred_pem = (u_char *)"fixture"; t->deleg_cred_len = 7; }
    u_char handle[4] = {0}; f.armed = 1;
    int rc;
    if (!strcmp(argv[2], "remote")) {
        tpc_open_spec_t spec = {.path = argv[4], .opaque = "", .options = kXR_open_read};
        rc = tpc_open_remote(t, t->primary_fd, &spec, handle);
    } else { rc = tpc_open_source(t, t->primary_fd, handle); }
    f.armed = 0;
    struct timeval tv; socklen_t len = sizeof(tv);
    assert(!getsockopt(t->primary_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &len));
    printf("rc=%d\nerror=%u\nmessage=%s\nsends=%u\nsleeps=%u\ntimeout=%ld\n"
        "handle=%02x%02x%02x%02x\nhost=%s\nport=%u\nopaque=%s\npending=%u\n",
        rc, (unsigned)t->xrd_error, t->err_msg, f.sends, f.sleeps, (long)tv.tv_sec,
        handle[0], handle[1], handle[2], handle[3], t->redir_host, t->redir_port,
        t->redir_opaque, t->redirect_pending);
    close(t->primary_fd); free(t); ngx_cycle = NULL; return 0;
}

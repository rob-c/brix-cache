/* Exercise the real fault command dispatcher with finite, observable jobs. */
#include "brix_fault_proxy_state.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#undef main

static struct {
    void *(*entry)(void *);
    void *arg;
    void *allocation;
    int create_error, allocation_error, created, detached, freed;
    int sleeps, cancel_after, random_calls, choice, value;
    unsigned long slept_us;
    const char *job;
} fixture;

void *__real_calloc(size_t n, size_t size);
void __real_free(void *ptr);

void *__wrap_calloc(size_t n, size_t size)
{
    if (n == 1 && size == sizeof(struct ramp_arg)) {
        if (fixture.allocation_error) { errno = ENOMEM; return NULL; }
        fixture.allocation = __real_calloc(n, size);
        return fixture.allocation;
    }
    return __real_calloc(n, size);
}

void __wrap_free(void *ptr)
{
    if (ptr && ptr == fixture.allocation) {
        assert(fixture.freed == 0);
        fixture.freed++;
    }
    __real_free(ptr);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*entry)(void *), void *arg)
{
    assert(attr == NULL && fixture.created == 0);
    fixture.created++;
    fixture.entry = entry;
    fixture.arg = arg;
    if (fixture.create_error) { return EAGAIN; }
    *thread = (pthread_t) 71;
    return 0;
}

int __wrap_pthread_detach(pthread_t thread)
{
    assert(thread == (pthread_t) 71 && !fixture.create_error);
    fixture.detached++;
    return 0;
}

/* Cancellation is injected at the timer boundary, never in the job itself. */
int __wrap_usleep(useconds_t duration)
{
    fixture.sleeps++;
    fixture.slept_us += duration;
    if (fixture.cancel_after && fixture.sleeps == fixture.cancel_after) {
        if (!strcmp(fixture.job, "chaos")) { g_chaos_gen++; }
        if (!strcmp(fixture.job, "flap")) { g_flap_gen++; }
        if (!strcmp(fixture.job, "ramp")) { g_ramp_gen++; }
    }
    assert(fixture.sleeps <= 21);
    return 0;
}

int __wrap_rand_r(unsigned *seed)
{
    (void) seed;
    return fixture.random_calls++ == 0 ? fixture.choice : fixture.value;
}

static void command(const char *text, int error)
{
    char line[4096], reply[4096];
    assert(strlen(text) < sizeof(line));
    strcpy(line, text);
    memset(reply, 0, sizeof(reply));
    apply_command(line, reply, sizeof(reply));
    assert((strncmp(reply, "err", 3) == 0) == error);
    if (error) { fputs(reply, stderr); }
}

/* Output both directions so Python can assert isolation and preservation. */
static void report(void)
{
    const fp_http_cfg *http[] = {&g_http_up, &g_http_down};
    const fp_tls_cfg *tls[] = {&g_tls_up, &g_tls_down};
    const struct fp_trigger *trig[] = {&g_trig_up, &g_trig_down};
    const struct fp_mangle *mangle[] = {&g_mangle_up, &g_mangle_down};
    for (int i = 0; i < 2; i++) {
        const char *side = i ? "down" : "up";
#define H(field) printf("%s.http.%s=%ld\n", side, #field, (long) http[i]->field)
        H(add_cl); H(cl_val); H(add_te); H(dup_cl); H(dup_cl_val);
        H(obfuscate_te); H(naked_lf); H(inj_name_len); H(inj_val_len);
        H(append_len); H(hold_thresh); H(hold_ms); H(hold_partial);
        H(body_hold_thresh); H(body_hold_ms); H(body_hold_partial); H(strip_len);
#undef H
#define T(field) printf("%s.tls.%s=%d\n", side, #field, tls[i]->field)
        T(frag_max); T(set_type); T(set_ver_major); T(set_ver_minor);
        T(inflate_len); T(flip_payload); T(drop_type); T(alert_level); T(alert_desc);
#undef T
        printf("%s.trigger.len=%d\n%s.trigger.once=%d\n%s.trigger.fired=%d\n",
               side, trig[i]->pat_len, side, trig[i]->once, side, trig[i]->fired);
        printf("%s.mangle.active=%d\n%s.mangle.op=%d\n%s.mangle.offset=%ld\n%s.mangle.val=%ld\n",
               side, mangle[i]->active, side, mangle[i]->op,
               side, mangle[i]->offset, side, mangle[i]->val);
    }
}

static void assert_chaos(int choice, int value)
{
    assert(g_up.latency_ms == (choice == 0 ? value % 400 : 0));
    assert(g_up.jitter_ms == (choice == 1 ? value % 200 : 0));
    assert(g_up.corrupt_ppm == (choice == 2 ? (value % 50) * 100 : 0));
    assert(g_up.drop_ppm == (choice == 3 ? (value % 30) * 100 : 0));
    assert(g_up.chunk_bytes == (choice == 4 ? 1 + value % 2048 : 0));
    assert(g_up.rate_kbps == (choice == 5 ? 8 + value % 4096 : 0));
    assert(g_up.reorder_ppm == (choice == 6 ? (value % 2000) * 100 : 0));
    assert(g_abortive == (choice == 7 && value % 4 == 0));
}

static void scheduled(const char *job, const char *mode, int value)
{
    fixture.job = job;
    fixture.create_error = !strcmp(mode, "create-error");
    fixture.allocation_error = !strcmp(mode, "allocation-error");
    fixture.cancel_after = !strcmp(mode, "cancel") ? 1 : 2;
    if (!strcmp(job, "heal")) {
        command("latency 99", 0);
        command(value ? "heal-after 12" : "heal-after 0", 0);
    } else if (!strcmp(job, "ramp")) {
        fixture.cancel_after = !strcmp(mode, "cancel") ? 3 : 0;
        command(value ? "ramp latency 10 50 1000" : "ramp latency 10 50 1",
                fixture.allocation_error);
    } else if (!strcmp(job, "flap")) {
        command(value ? "flap 12 34" : "flap 0 0", 0);
    } else {
        assert(!strcmp(job, "chaos"));
        command(value ? "chaos 30" : "chaos 0", 0);
        fixture.choice = atoi(mode);
        fixture.value = value;
    }
    if (fixture.allocation_error) {
        assert(!fixture.created && !fixture.allocation);
        return;
    }
    assert(fixture.created == 1);
    if (fixture.create_error) {
        assert(!fixture.detached);
        if (!strcmp(job, "ramp")) { assert(fixture.freed == 1); }
        if (!strcmp(job, "flap")) { assert(!g_flap_on); }
        if (!strcmp(job, "chaos")) { assert(!g_chaos_on); }
        if (!strcmp(job, "heal")) { assert(g_up.latency_ms == 99); }
        return;
    }
    assert(fixture.detached == 1);
    if (!strcmp(mode, "superseded")) {
        command("clear", 0);
    }
    fixture.entry(fixture.arg);
    if (!strcmp(mode, "superseded") && strcmp(job, "heal")) {
        assert(!fixture.sleeps && !fixture.random_calls && !g_up.latency_ms);
    } else if (!strcmp(job, "heal")) {
        assert(!g_up.latency_ms && !g_down.latency_ms);
        assert(fixture.slept_us == (value ? 12000u : 0u));
    } else if (!strcmp(job, "ramp")) {
        assert(fixture.freed == 1);
        assert(g_up.latency_ms == (!strcmp(mode, "cancel") ? 14 : 50));
        assert(g_up.latency_ms == g_down.latency_ms);
        assert(fixture.slept_us == (unsigned long) fixture.sleeps * (value ? 50000u : 10000u));
    } else if (!strcmp(job, "flap")) {
        assert(!g_blocked);
        assert(fixture.sleeps == fixture.cancel_after);
        assert(fixture.slept_us == (value ? (fixture.sleeps == 1 ? 12000u : 46000u)
                                                : (unsigned long) fixture.sleeps * 500000));
    } else if (!strcmp(mode, "cancel")) {
        assert(!fixture.random_calls && !g_up.latency_ms);
    } else {
        assert_chaos(fixture.choice, value);
        assert(fixture.random_calls == 2);
    }
    if (fixture.allocation) { assert(fixture.freed == 1); }
}

int main(int argc, char **argv)
{
    assert(argc >= 3);
    clear_all();
    if (!strcmp(argv[1], "schedule")) {
        assert(argc == 5);
        scheduled(argv[2], argv[3], atoi(argv[4]));
        return 0;
    }
    assert(!strcmp(argv[1], "command"));
    for (int i = 2; i < argc; i++) {
        int error = argv[i][0] == '!';
        command(argv[i] + error, error);
    }
    report();
    return 0;
}

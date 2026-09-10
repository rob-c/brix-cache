/*
 * curl_pin_budget_test.c — brix_dns_curl_perform_pinned() is time-bounded
 * (phase-116 amendment 14; the invariant tests/test_blocking_curl_bounded.py
 * states for every blocking libcurl site).
 *
 * WHAT: drives the real pinned transfer loop (src/net/dns/curl_pin.c) against
 *       three local endpoints — a black hole that completes the TCP handshake
 *       and then never answers, a server that redirects once into that black
 *       hole, and a server that answers at once.
 * WHY:  the loop performs on a handle it did not create and re-performs per
 *       redirect hop, so neither "the caller set CURLOPT_TIMEOUT" nor the hop
 *       cap alone bounds it: a caller that sets none hangs the thread-pool
 *       thread for ever, and a caller that sets one still pays it per hop.
 * HOW:  the DNS half is stubbed — every URL here has an IP-literal host, the
 *       path that returns before brix_dns_resolve_sync(), which the stub
 *       aborts on to prove no resolver is reached.  Only the budget is under
 *       test.  Run by tests/test_phase116_curl_pin_budget.py, twice: once as
 *       built, once with -DBRIX_DNS_CURL_TIMEOUT_MS_DEFAULT=400 for the arm
 *       where the caller names no budget at all.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/compat/net_target.h"
#include "net/dns/curl_pin.h"

static int failures;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            failures++;                                                       \
            printf("FAIL %s:%d: ", __func__, __LINE__);                       \
            printf(__VA_ARGS__);                                              \
            printf("\n");                                                     \
        }                                                                     \
    } while (0)


/* --- the stubs curl_pin.o needs ---------------------------------------- */

u_char *
ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...)
{
    /* The unit reads only whether a message was written, never its text, so
     * the nginx format verbs (%ui, %Z) need no implementation here. */
    if (buf != NULL && max > 0) {
        (void) fmt;
        buf[0] = '!';
        if (max > 1) {
            buf[1] = '\0';
        }
    }
    return buf;
}


u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }
    while (--n && *src) {
        *dst++ = *src++;
    }
    *dst = '\0';
    return dst;
}


ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    return (ngx_int_t) strncasecmp((char *) s1, (char *) s2, n);
}


/* The URL is always http://127.0.0.1:PORT/…, so the parser stub only has to
 * split what curl_pin_port() and the literal check read. */
ngx_int_t
brix_net_target_parse(ngx_pool_t *pool, const ngx_str_t *url,
    brix_net_target_t *out, char *err, size_t errsz)
{
    static u_char  scheme[] = "http";
    u_char        *host, *colon, *slash;

    (void) pool; (void) err; (void) errsz;
    ngx_memzero(out, sizeof(*out));
    host = url->data + sizeof("http://") - 1;
    colon = (u_char *) strchr((char *) host, ':');
    slash = (u_char *) strchr((char *) colon, '/');
    if (colon == NULL || slash == NULL) {
        return NGX_ERROR;
    }
    out->scheme.data = scheme;
    out->scheme.len = 4;
    out->host.data = host;
    out->host.len = (size_t) (colon - host);
    out->port = (uint16_t) atoi((char *) colon + 1);
    out->has_port = 1;
    return NGX_OK;
}


ngx_int_t
brix_dns_parse_literal(const ngx_str_t *name, brix_dns_addr_t *out)
{
    char  buf[64];

    ngx_memzero(out, sizeof(*out));
    if (name->len >= sizeof(buf)) {
        return NGX_ERROR;
    }
    memcpy(buf, name->data, name->len);
    buf[name->len] = '\0';
    return (inet_addr(buf) == INADDR_NONE) ? NGX_ERROR : NGX_OK;
}


size_t
brix_dns_addr_ntop(const brix_dns_addr_t *addr, char *buf, size_t sz)
{
    (void) addr; (void) buf; (void) sz;
    return 0;
}


size_t
brix_format_host_port(const char *host, uint16_t port, char *out, size_t sz)
{
    int  n = snprintf(out, sz, "%s:%u", host, (unsigned) port);

    return (n < 0 || (size_t) n >= sz) ? 0 : (size_t) n;
}


ngx_uint_t
brix_dns_resolve_sync(const brix_dns_policy_t *policy, const char *host,
    in_port_t port, brix_af_policy_t af, int socktype,
    brix_dns_addr_t *addrs, ngx_uint_t max, char *err, size_t errsz)
{
    (void) policy; (void) host; (void) port; (void) af; (void) socktype;
    (void) addrs; (void) max; (void) err; (void) errsz;
    /* An IP-literal URL must never reach the resolver. */
    printf("FAIL: brix_dns_resolve_sync called for a literal host\n");
    failures++;
    return 0;
}


/* --- local endpoints ---------------------------------------------------- */

static int
listen_local(int *port_out)
{
    struct sockaddr_in  a;
    socklen_t           len = sizeof(a);
    int                 fd = socket(AF_INET, SOCK_STREAM, 0);

    ngx_memzero(&a, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (fd < 0 || bind(fd, (struct sockaddr *) &a, sizeof(a)) != 0
        || listen(fd, 8) != 0
        || getsockname(fd, (struct sockaddr *) &a, &len) != 0)
    {
        return -1;
    }
    *port_out = ntohs(a.sin_port);
    return fd;
}


typedef struct {
    int   fd;
    long  delay_ms;   /* time this hop itself burns, before answering */
    char  reply[256];
} responder_t;


/* Answer one request with a canned response, then close.  Never accepting at
 * all is the black hole: the backlog completes the handshake, so the connect
 * succeeds and the transfer stalls with no byte ever arriving. */
static void *
responder(void *data)
{
    responder_t  *r = data;
    char          req[1024];
    int           c = accept(r->fd, NULL, NULL);

    if (c < 0) {
        return NULL;
    }
    (void) recv(c, req, sizeof(req), 0);
    if (r->delay_ms > 0) {
        usleep((useconds_t) r->delay_ms * 1000);
    }
    (void) send(c, r->reply, strlen(r->reply), MSG_NOSIGNAL);
    close(c);
    return NULL;
}


static long
elapsed_ms(const struct timespec *t0)
{
    struct timespec  t1;

    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0->tv_sec) * 1000
           + (t1.tv_nsec - t0->tv_nsec) / 1000000;
}


static size_t
sink(char *p, size_t sz, size_t n, void *ud)
{
    (void) p; (void) ud;
    return sz * n;
}


static CURLcode
perform(const char *url, long budget_ms, char *err, size_t errsz, long *took)
{
    struct timespec           t0;
    brix_dns_curl_transfer_t  x;
    CURL                     *curl = curl_easy_init();
    CURLcode                  res;

    ngx_memzero(&x, sizeof(x));
    x.url = url;
    x.max_redirects = 3;
    x.timeout_ms = budget_ms;
    x.err = err;
    x.errsz = errsz;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sink);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    res = brix_dns_curl_perform_pinned(curl, &x);
    *took = elapsed_ms(&t0);
    curl_easy_cleanup(curl);
    return res;
}


/* --- the cases ---------------------------------------------------------- */

/* A black-holed endpoint must end the transfer, not the worker. */
static void
test_black_hole_is_bounded(void)
{
    char  url[128], err[BRIX_DNS_ERROR_LEN];
    int   port, fd = listen_local(&port);
    long  took;
    CURLcode  res;

    CHECK(fd >= 0, "no listener");
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);
    res = perform(url, 400, err, sizeof(err), &took);
    CHECK(res == CURLE_OPERATION_TIMEDOUT, "res=%d (%s)", (int) res,
          curl_easy_strerror(res));
    CHECK(took < 3000, "took %ld ms for a 400 ms budget", took);
    close(fd);
}


/* The budget is the WHOLE transfer's, not each hop's: a redirect into a black
 * hole may not cost the budget twice. */
static void
test_budget_is_shared_across_hops(void)
{
    char        url[128], err[BRIX_DNS_ERROR_LEN];
    int         hole_port, hop_port;
    int         hole = listen_local(&hole_port), hop = listen_local(&hop_port);
    responder_t r;
    pthread_t   th;
    long        took;
    CURLcode    res;

    CHECK(hole >= 0 && hop >= 0, "no listeners");
    r.fd = hop;
    /* The first hop burns most of the budget itself.  A loop that gave each
     * hop the full budget would take delay + budget here; one that spends a
     * single budget down takes the budget. */
    r.delay_ms = 600;
    snprintf(r.reply, sizeof(r.reply),
             "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:%d/\r\n"
             "Content-Length: 0\r\n\r\n", hole_port);
    pthread_create(&th, NULL, responder, &r);

    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", hop_port);
    res = perform(url, 1000, err, sizeof(err), &took);
    CHECK(res != CURLE_OK, "a black-holed second hop returned OK");
    CHECK(took < 1300, "two hops took %ld ms of one 1000 ms budget — the "
          "budget is being spent per hop, not in total", took);
    pthread_join(th, NULL);
    close(hop);
    close(hole);
}


/* A caller that names no budget is still bounded — the unit is built a second
 * time with a small BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT so this arm is fast. */
static void
test_unnamed_budget_takes_the_default(void)
{
    char  url[128], err[BRIX_DNS_ERROR_LEN];
    int   port, fd = listen_local(&port);
    long  took;
    CURLcode  res;

    if (BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT > 1000) {
        close(fd);
        return;                     /* shipped default: proven by the arm below */
    }
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);
    res = perform(url, 0, err, sizeof(err), &took);
    CHECK(res == CURLE_OPERATION_TIMEDOUT, "res=%d with no budget named",
          (int) res);
    CHECK(took < BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT + 2000,
          "unnamed budget took %ld ms", took);
    close(fd);
}


/* A transfer that answers inside its budget is untouched by any of this. */
static void
test_prompt_answer_still_succeeds(void)
{
    char        url[128], err[BRIX_DNS_ERROR_LEN];
    int         port, fd = listen_local(&port);
    responder_t r;
    pthread_t   th;
    long        took;
    CURLcode    res;

    r.fd = fd;
    r.delay_ms = 0;
    snprintf(r.reply, sizeof(r.reply),
             "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    pthread_create(&th, NULL, responder, &r);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);
    res = perform(url, 5000, err, sizeof(err), &took);
    CHECK(res == CURLE_OK, "res=%d (%s)", (int) res, curl_easy_strerror(res));
    CHECK(took < 5000, "a prompt answer took %ld ms", took);
    pthread_join(th, NULL);
    close(fd);
}


/* An unbounded loop would otherwise hang the unit until the pytest timeout;
 * this turns that into a named failure in seconds. */
static void
watchdog(int sig)
{
    (void) sig;
    if (write(STDOUT_FILENO, "FAIL: the transfer never returned\n", 34) < 0) {
        /* nothing to do on a failed write from a signal handler */
    }
    _exit(1);
}


int
main(void)
{
    signal(SIGALRM, watchdog);
    alarm(20);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    test_black_hole_is_bounded();
    test_budget_is_shared_across_hops();
    test_unnamed_budget_takes_the_default();
    test_prompt_answer_still_succeeds();
    curl_global_cleanup();
    if (failures != 0) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("curl_pin budget: all cases passed (default=%d ms)\n",
           (int) BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT);
    return 0;
}

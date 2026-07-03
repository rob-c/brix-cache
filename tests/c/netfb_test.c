/*
 * netfb_test.c — IPv6→IPv4 auto-downgrade (netpref.c + brix_tcp_connect).
 *
 * WHAT: Deterministic checks for the dual-stack-with-broken-IPv6 fallback that
 *       keeps a FUSE mount working (and quiet) on a host whose IPv6 path is dead.
 * WHY:  Proves the connect chokepoint demotes to IPv4-only only on real evidence
 *       (v6 failed, v4 then worked), sticks for the session, logs once, and can
 *       be opted out — without needing an actually-broken network.
 * HOW:  Three modes (argv[1]):
 *         state    — pure netpref state machine (no network, no shim).
 *         connect  — IPv4-only listener + sentinel host "dualstack.invalid"
 *                    (resolved to [::1,127.0.0.1] by the LD_PRELOAD gai_shim):
 *                    connect must succeed AND the session must demote.
 *         disabled — same as connect but with XRDC_NO_IPV6_FALLBACK set: connect
 *                    must still succeed but the session must NOT demote.
 *       Exit 0 = pass; any failed expectation prints to stderr and exits 1.
 */
#include "brix.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SENTINEL "dualstack.invalid"
#define V6ONLY   "v6only.invalid"

static int failures;

static void
check(int cond, const char *what)
{
    if (cond) {
        fprintf(stderr, "  ok: %s\n", what);
    } else {
        fprintf(stderr, "  FAIL: %s\n", what);
        failures++;
    }
}

/* Bind+listen an IPv4-only TCP socket on 127.0.0.1; return fd, *port set. */
static int
listen_v4(int *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port        = 0;   /* ephemeral */
    if (bind(fd, (struct sockaddr *) &a, sizeof(a)) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof(a);
    if (getsockname(fd, (struct sockaddr *) &a, &sl) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

/* Bind+listen an IPv6 TCP socket on ::1; return fd, *port set. */
static int
listen_v6(int *port)
{
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in6 a;
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_addr   = in6addr_loopback;
    a.sin6_port   = 0;
    if (bind(fd, (struct sockaddr *) &a, sizeof(a)) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof(a);
    if (getsockname(fd, (struct sockaddr *) &a, &sl) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(a.sin6_port);
    return fd;
}

static int
mode_state(void)
{
    fprintf(stderr, "[state] netpref state machine\n");
    check(brix_netpref_family() == AF_UNSPEC, "initial family == AF_UNSPEC");
    check(brix_netpref_demoted() == 0,        "initially not demoted");

    brix_netpref_demote_ipv6("server.example");
    check(brix_netpref_demoted() == 1,        "demoted after demote_ipv6");
    check(brix_netpref_family() == AF_INET,   "family == AF_INET after demote");

    brix_netpref_demote_ipv6("server.example");   /* idempotent */
    check(brix_netpref_demoted() == 1,        "still demoted (idempotent)");
    return failures ? 1 : 0;
}

/* Shared connect scenario; `expect_demote` differs for enabled vs disabled. */
static int
mode_connect(int expect_demote)
{
    fprintf(stderr, "[connect] expect_demote=%d\n", expect_demote);

    int port = 0;
    int lfd = listen_v4(&port);
    check(lfd >= 0, "IPv4-only listener bound");
    if (lfd < 0) {
        return 1;
    }

    /* Sentinel resolves (via gai_shim) to [::1:port, 127.0.0.1:port]; ::1 has no
     * listener so the v6 candidate is refused and the connect falls to v4. */
    brix_status st;
    memset(&st, 0, sizeof(st));
    int fd = brix_tcp_connect(SENTINEL, port, 5000, &st);
    check(fd >= 0, "connect fell back to working IPv4");
    if (fd < 0) {
        fprintf(stderr, "    (status: %s)\n", st.msg);
    } else {
        close(fd);
    }

    if (expect_demote) {
        check(brix_netpref_demoted() == 1, "session demoted to IPv4-only");
        /* After demotion the resolver is asked for AF_INET only; a second
         * connect must still succeed straight away. */
        int fd2 = brix_tcp_connect(SENTINEL, port, 5000, &st);
        check(fd2 >= 0, "post-demote connect (IPv4-only resolve) works");
        if (fd2 >= 0) {
            close(fd2);
        }
    } else {
        check(brix_netpref_demoted() == 0, "opt-out: NOT demoted");
        check(brix_netpref_family() == AF_UNSPEC, "opt-out: family stays AF_UNSPEC");
    }

    close(lfd);
    return failures ? 1 : 0;
}

/* The wire-error trigger as a pure state machine (no network). */
static int
mode_wirestate(void)
{
    fprintf(stderr, "[wirestate] note_wire_error / undo_demote\n");
    check(brix_netpref_demoted() == 0, "initially not demoted");

    brix_netpref_note_wire_error(AF_INET);    /* v4 error: not evidence of bad v6 */
    check(brix_netpref_demoted() == 0, "AF_INET wire error does NOT demote");

    brix_netpref_note_wire_error(AF_INET6);   /* v6 error: the trigger */
    check(brix_netpref_demoted() == 1, "AF_INET6 wire error demotes");
    check(brix_netpref_family() == AF_INET, "family AF_INET after wire demote");

    brix_netpref_undo_demote("test revert");  /* self-heal */
    check(brix_netpref_demoted() == 0, "undo_demote reverts");
    check(brix_netpref_family() == AF_UNSPEC, "family AF_UNSPEC after revert");
    return failures ? 1 : 0;
}

/* An established IPv6 connection whose peer drops it mid-read demotes the
 * session — proving the read/write chokepoint feeds the wire-error trigger. */
static int
mode_wireerror(void)
{
    fprintf(stderr, "[wireerror] established IPv6 conn dropped mid-read\n");

    int port = 0;
    int lfd = listen_v6(&port);
    check(lfd >= 0, "IPv6 listener bound");
    if (lfd < 0) {
        return 1;
    }

    int cfd = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_addr   = in6addr_loopback;
    a.sin6_port   = htons((uint16_t) port);
    check(cfd >= 0 && connect(cfd, (struct sockaddr *) &a, sizeof(a)) == 0,
          "client connected over IPv6");

    int afd = accept(lfd, NULL, NULL);
    check(afd >= 0, "server accepted");
    if (afd >= 0) {
        close(afd);   /* peer drops the connection */
    }

    brix_io     io = { .fd = cfd, .ssl = NULL, .timeout_ms = 1000 };
    brix_status st;
    char        buf[16];
    memset(&st, 0, sizeof(st));
    int rc = brix_read_full(&io, buf, sizeof(buf), &st);
    check(rc < 0, "read failed (peer dropped)");
    check(brix_netpref_demoted() == 1, "IPv6 wire error demoted the session");

    if (cfd >= 0) {
        close(cfd);
    }
    close(lfd);
    return failures ? 1 : 0;
}

/* Self-heal: a session demoted to IPv4-only that then meets an IPv6-only host
 * (no A record) must revert to dual-stack and still connect over IPv6. */
static int
mode_selfheal(void)
{
    fprintf(stderr, "[selfheal] demoted session meets an IPv6-only host\n");

    brix_netpref_demote_ipv6("simulated prior failure");
    check(brix_netpref_demoted() == 1, "pre-demoted to IPv4-only");

    int port = 0;
    int lfd = listen_v6(&port);
    check(lfd >= 0, "IPv6 listener bound");
    if (lfd < 0) {
        return 1;
    }

    /* V6ONLY resolves to ::1 for AF_UNSPEC but EAI_NONAME for AF_INET, so the
     * demoted (AF_INET) attempt fails, self-heal reverts, and the AF_UNSPEC
     * retry reaches the IPv6 listener. */
    brix_status st;
    memset(&st, 0, sizeof(st));
    int fd = brix_tcp_connect(V6ONLY, port, 3000, &st);
    check(fd >= 0, "self-heal reverted and connected over IPv6");
    if (fd < 0) {
        fprintf(stderr, "    (status: %s)\n", st.msg);
    } else {
        close(fd);
    }
    check(brix_netpref_demoted() == 0, "demotion reverted (back to dual-stack)");

    close(lfd);
    return failures ? 1 : 0;
}

int
main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "state";

    if (strcmp(mode, "state") == 0) {
        return mode_state();
    }
    if (strcmp(mode, "connect") == 0) {
        return mode_connect(1);
    }
    if (strcmp(mode, "disabled") == 0) {
        return mode_connect(0);
    }
    if (strcmp(mode, "wirestate") == 0) {
        return mode_wirestate();
    }
    if (strcmp(mode, "wireerror") == 0) {
        return mode_wireerror();
    }
    if (strcmp(mode, "selfheal") == 0) {
        return mode_selfheal();
    }
    fprintf(stderr, "usage: %s state|connect|disabled|wirestate|wireerror|selfheal\n",
            argv[0]);
    return 2;
}

/*
 * forksafe_test.c — unit checks for the §7.7 fork-safety registry (forksafe.c).
 *
 * WHAT: Verifies that registration is IDEMPOTENT, that unregistration clears
 *       every slot a conn holds, that a real fork() neuters the child's
 *       inherited conns and empties the child's table, and that the overflow
 *       counter is reachable rather than a number nobody can read.
 * WHY:  The registry is what stands between a forking framework and stream
 *       corruption in the parent's session.  It fails SILENTLY: a table that
 *       fills up does not error, it just stops neutering, and the next child
 *       writes into its parent's wire.  A duplicate slot per re-dial is
 *       therefore not an accounting nit — it is a countdown to that.
 * HOW:  Fake brix_conn objects registered directly (no network); fork() for
 *       the child-side handler.  Exit 0 = pass, 1 = fail.
 */
#include "brix.h"
#include "_brix_net_ext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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

static int
live_count(void)
{
    int live = 0;
    brix_forksafe_stats(&live, NULL);
    return live;
}

static int
overflow_count(void)
{
    int over = 0;
    brix_forksafe_stats(NULL, &over);
    return over;
}

/* A conn shaped like a live one: a non-negative fd is what brix_conn_usable
 * and the child handler both key on.  Nothing here touches the network. */
static void
fake_conn(brix_conn *c)
{
    memset(c, 0, sizeof(*c));
    c->io.fd = STDERR_FILENO + 1;   /* plausible, never written to */
}

/* Re-dialling an already-registered conn must not take a second slot: it is
 * the ordinary child-side path (brix_connect_setup memsets the conn, so there
 * is no close between the two registrations). */
static void
test_register_is_idempotent(void)
{
    brix_conn c;
    int base;

    fprintf(stderr, "[registry] register is idempotent\n");
    base = live_count();
    fake_conn(&c);
    brix_forksafe_register(&c);
    check(live_count() == base + 1, "first registration takes one slot");
    brix_forksafe_register(&c);
    brix_forksafe_register(&c);
    check(live_count() == base + 1, "re-registration takes no further slot");
    brix_forksafe_unregister(&c);
    check(live_count() == base, "unregister releases it");
}

/* Two distinct conns are two entries — the idempotency must be by IDENTITY
 * and not a "one conn only" table. */
static void
test_distinct_conns_get_distinct_slots(void)
{
    brix_conn a, b;
    int base;

    fprintf(stderr, "[registry] distinct conns are distinct entries\n");
    base = live_count();
    fake_conn(&a);
    fake_conn(&b);
    brix_forksafe_register(&a);
    brix_forksafe_register(&b);
    check(live_count() == base + 2, "two conns, two slots");
    brix_forksafe_unregister(&a);
    check(live_count() == base + 1, "unregistering one leaves the other");
    brix_forksafe_unregister(&b);
    check(live_count() == base, "table returns to its starting occupancy");
}

/* An entry left behind by unregister points into memory the caller is about
 * to reuse; the next fork's child handler would write through it. */
static void
test_unregister_is_exhaustive(void)
{
    brix_conn c;
    int base;

    fprintf(stderr, "[registry] unregister leaves nothing behind\n");
    base = live_count();
    fake_conn(&c);
    brix_forksafe_register(&c);
    brix_forksafe_unregister(&c);
    brix_forksafe_unregister(&c);   /* idempotent too: no underflow */
    check(live_count() == base, "double unregister is harmless");
    check(overflow_count() == 0, "nothing overflowed during the unit run");
}

/* The whole point: after fork(), the CHILD's copy is dead and says so, while
 * the parent's is untouched.  Exit status carries the child's verdict because
 * its stderr and the parent's are the same stream. */
static void
test_fork_neuters_the_child_copy(void)
{
    brix_conn c;
    pid_t pid;
    int status = 0;

    fprintf(stderr, "[fork] the child's inherited conn is neutered\n");
    fake_conn(&c);
    brix_forksafe_register(&c);
    check(brix_conn_usable(&c) == 1, "usable before the fork");

    pid = fork();
    if (pid == 0) {
        /* 0 = neutered and the table was emptied; 1..3 name what went wrong. */
        int child_live = live_count();
        if (brix_conn_usable(&c) != 0) { _exit(1); }
        if (c.io.fd != -1)             { _exit(2); }
        if (child_live != 0)           { _exit(3); }
        _exit(0);
    }
    check(pid > 0, "fork succeeded");
    if (pid > 0) {
        (void) waitpid(pid, &status, 0);
        check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "child: conn unusable, fd closed, table emptied");
    }
    check(brix_conn_usable(&c) == 1, "the PARENT's conn is untouched");
    brix_forksafe_unregister(&c);
}

int
main(void)
{
    test_register_is_idempotent();
    test_distinct_conns_get_distinct_slots();
    test_unregister_is_exhaustive();
    test_fork_neuters_the_child_copy();

    fprintf(stderr, failures ? "\nFAILED (%d)\n" : "\nPASSED\n", failures);
    return failures ? 1 : 0;
}

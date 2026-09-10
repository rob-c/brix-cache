/*
 * resolv_conf_unittest.c — standalone unit test for the resolv.conf parser
 * (phase-116 W1).  Built and run by tests/cmdscripts/c_regression_units.py
 * (dns_resolv_conf) and by tests/test_phase116_resolv_conf_parser.py.
 *
 * WHAT: Exercises defaults, keyword parsing, limits, comments, env overrides
 *       the missing-file path, an unreadable path (a directory) and a
 *       symlinked file against glibc's documented behaviour.
 * WHY:  The parser is the single truth for "what the host resolver would do";
 *       a drift here silently changes which nameserver every brix worker asks.
 * HOW:  Plain assert-style checks with a counter; exit status 0 = all pass.
 */
#include "resolv_conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
        }                                                                    \
    } while (0)


static void
test_defaults(void)
{
    brix_resolv_conf_t rc;

    brix_resolv_conf_defaults(&rc);
    CHECK(rc.nnameservers == 1);
    CHECK(strcmp(rc.nameservers[0], "127.0.0.1") == 0);
    CHECK(rc.nsearch == 0);
    CHECK(rc.ndots == 1 && rc.timeout == 5 && rc.attempts == 2);
    CHECK(rc.rotate == 0 && rc.defaulted == 1);
}


static void
test_keywords(void)
{
    brix_resolv_conf_t rc;
    const char *text =
        "# generated\n"
        "nameserver 10.0.0.1\n"
        "nameserver fe80::1%eth0   ; zone dropped\n"
        "domain ignored.example\n"
        "search cern.ch example.org. \n"
        "options ndots:3 timeout:7 attempts:4 rotate edns0 bogus:9\n"
        "sortlist 10.0.0.0/8\n"
        "nameserver 10.0.0.3\n"
        "nameserver 10.0.0.4\n";

    brix_resolv_conf_defaults(&rc);
    brix_resolv_conf_parse_text(&rc, text, strlen(text));
    CHECK(rc.nnameservers == 3);
    CHECK(strcmp(rc.nameservers[0], "10.0.0.1") == 0);
    CHECK(strcmp(rc.nameservers[1], "fe80::1") == 0);
    CHECK(strcmp(rc.nameservers[2], "10.0.0.3") == 0);   /* 4th dropped */
    CHECK(rc.nsearch == 2);                               /* last wins */
    CHECK(strcmp(rc.search[0], "cern.ch") == 0);
    CHECK(strcmp(rc.search[1], "example.org") == 0);     /* dot stripped */
    CHECK(rc.ndots == 3 && rc.timeout == 7 && rc.attempts == 4);
    CHECK(rc.rotate == 1);
}


/* Only address literals reach nginx's resolver: anything glibc would
 * skip is skipped here too, ":port" and "[v6]:port" are kept, a zone is
 * dropped whether bare or bracketed. */
static void
test_nameserver_literals(void)
{
    brix_resolv_conf_t rc;
    const char *text =
        "nameserver\n"
        "nameserver not-an-ip\n"
        "nameserver 999.1.1.1\n"
        "nameserver 10.0.0.2:0\n"
        "nameserver 10.0.0.2:x\n"
        "nameserver 10.0.0.2:70000\n"
        "nameserver [fe80::1\n"
        "nameserver [fe80::1]x\n"
        "nameserver [not-an-ip]:53\n"
        "nameserver 10.0.0.1:5353\n"
        "nameserver [::1]:5354\n"
        "nameserver [fe80::1%eth0]\n";

    brix_resolv_conf_defaults(&rc);
    brix_resolv_conf_parse_text(&rc, text, strlen(text));
    CHECK(rc.nnameservers == 3);
    CHECK(strcmp(rc.nameservers[0], "10.0.0.1:5353") == 0);
    CHECK(strcmp(rc.nameservers[1], "[::1]:5354") == 0);
    CHECK(strcmp(rc.nameservers[2], "fe80::1") == 0);

    /* a bracketed zone with a port is re-assembled without the zone */
    text = "nameserver [fe80::1%eth0]:53\n";
    brix_resolv_conf_defaults(&rc);
    brix_resolv_conf_parse_text(&rc, text, strlen(text));
    CHECK(rc.nnameservers == 1);
    CHECK(strcmp(rc.nameservers[0], "[fe80::1]:53") == 0);

    /* every nameserver line unparseable: none left, the default is NOT
     * silently restored (the builder warns and falls back to libc) */
    text = "nameserver nope\nsearch lab.example\n";
    brix_resolv_conf_defaults(&rc);
    brix_resolv_conf_parse_text(&rc, text, strlen(text));
    CHECK(rc.nnameservers == 0);
    CHECK(rc.nsearch == 1);

    /* no nameserver line at all: the 127.0.0.1 default stands (glibc) */
    text = "search lab.example\noptions ndots:2\n";
    brix_resolv_conf_defaults(&rc);
    brix_resolv_conf_parse_text(&rc, text, strlen(text));
    CHECK(rc.nnameservers == 1);
    CHECK(strcmp(rc.nameservers[0], "127.0.0.1") == 0);
}


static void
test_limits(void)
{
    brix_resolv_conf_t rc;
    const char *text =
        "options ndots:99 timeout:0 attempts:77\n"
        "search a b c d e f g h\n";

    brix_resolv_conf_defaults(&rc);
    brix_resolv_conf_parse_text(&rc, text, strlen(text));
    CHECK(rc.ndots == 15 && rc.timeout == 1 && rc.attempts == 5);
    CHECK(rc.nsearch == 6);
    CHECK(strcmp(rc.search[5], "f") == 0);
}


static void
test_env(void)
{
    brix_resolv_conf_t rc;
    const char *text = "search file.example\noptions ndots:2\n";

    brix_resolv_conf_defaults(&rc);
    brix_resolv_conf_parse_text(&rc, text, strlen(text));
    brix_resolv_conf_apply_env(&rc, "env.one env.two", "ndots:5 rotate");
    CHECK(rc.nsearch == 2 && strcmp(rc.search[0], "env.one") == 0);
    CHECK(rc.env_search == 1);
    CHECK(rc.ndots == 5 && rc.rotate == 1);

    brix_resolv_conf_apply_env(&rc, NULL, NULL);          /* no-op */
    CHECK(rc.nsearch == 2 && rc.ndots == 5);
}


static void
test_missing_file(void)
{
    brix_resolv_conf_t rc;

    unsetenv("LOCALDOMAIN");
    unsetenv("RES_OPTIONS");
    CHECK(brix_resolv_conf_load(&rc, "/nonexistent/resolv.conf") == -1);
    CHECK(rc.defaulted == 1 && rc.nnameservers == 1);
    CHECK(strcmp(rc.nameservers[0], "127.0.0.1") == 0);
}


static void
test_file(void)
{
    brix_resolv_conf_t rc;
    char  path[] = "/tmp/brix_resolv_ut_XXXXXX";
    int   fd = mkstemp(path);
    const char *text = "nameserver 192.0.2.53\nsearch lab.example\n";

    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    CHECK(write(fd, text, strlen(text)) == (ssize_t) strlen(text));
    close(fd);
    unsetenv("LOCALDOMAIN");
    unsetenv("RES_OPTIONS");
    CHECK(brix_resolv_conf_load(&rc, path) == 0);
    CHECK(rc.defaulted == 0);
    CHECK(rc.nnameservers == 1
          && strcmp(rc.nameservers[0], "192.0.2.53") == 0);
    CHECK(rc.nsearch == 1 && strcmp(rc.search[0], "lab.example") == 0);
    unlink(path);
}


/* A path that opens but yields no readable content (a directory) is the
 * operator's path being unusable, not an empty resolv.conf: the loader must
 * fail so the caller warns.  A genuinely empty regular file is a valid
 * resolv.conf and keeps glibc's 127.0.0.1 default silently.
 */
static void
test_unreadable_content(void)
{
    brix_resolv_conf_t rc;
    char  dir[] = "/tmp/brix_resolv_ut_dir_XXXXXX";
    char  path[] = "/tmp/brix_resolv_ut_empty_XXXXXX";
    int   fd;

    unsetenv("LOCALDOMAIN");
    unsetenv("RES_OPTIONS");

    CHECK(mkdtemp(dir) != NULL);
    CHECK(brix_resolv_conf_load(&rc, dir) == -1);
    CHECK(rc.defaulted == 1 && rc.nnameservers == 1);
    CHECK(strcmp(rc.nameservers[0], "127.0.0.1") == 0);
    rmdir(dir);

    fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    close(fd);
    CHECK(brix_resolv_conf_load(&rc, path) == 0);
    CHECK(rc.defaulted == 0 && rc.nnameservers == 1);
    CHECK(strcmp(rc.nameservers[0], "127.0.0.1") == 0);
    unlink(path);
}


/* A symlink is followed to its target's contents: /etc/resolv.conf is one on
 * every systemd host (phase-116 amendment 1).
 */
static void
test_symlinked_file(void)
{
    brix_resolv_conf_t rc;
    char  path[] = "/tmp/brix_resolv_ut_tgt_XXXXXX";
    char  link[sizeof(path) + 5];
    const char *text = "nameserver 192.0.2.54\n";
    int   fd = mkstemp(path);

    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    CHECK(write(fd, text, strlen(text)) == (ssize_t) strlen(text));
    close(fd);
    snprintf(link, sizeof(link), "%s.link", path);
    CHECK(symlink(path, link) == 0);
    unsetenv("LOCALDOMAIN");
    unsetenv("RES_OPTIONS");
    CHECK(brix_resolv_conf_load(&rc, link) == 0);
    CHECK(rc.nnameservers == 1
          && strcmp(rc.nameservers[0], "192.0.2.54") == 0);
    unlink(link);
    unlink(path);
}


static void
test_count_dots(void)
{
    CHECK(brix_resolv_conf_count_dots("host", 4) == 0);
    CHECK(brix_resolv_conf_count_dots("a.b.c", 5) == 2);
    CHECK(brix_resolv_conf_count_dots("a.b.", 4) == 1);
}


int
main(void)
{
    test_defaults();
    test_keywords();
    test_nameserver_literals();
    test_limits();
    test_env();
    test_missing_file();
    test_file();
    test_unreadable_content();
    test_symlinked_file();
    test_count_dots();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("resolv_conf unittest: all checks passed\n");
    return 0;
}

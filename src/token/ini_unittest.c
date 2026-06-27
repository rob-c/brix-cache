/*
 * ini_unittest.c — standalone unit test for the INI parser (token/ini.c).
 *
 * Pure C, no nginx runtime — compile & run directly (mirrors the
 * zip_dir_unittest.c precedent):
 *
 *   gcc -Wall -Wextra -Werror -o /tmp/ini_ut \
 *       src/token/ini_unittest.c src/token/ini.c && /tmp/ini_ut
 *
 * Validates the parser against the real upstream scitokens.cfg grammar
 * (tests/fixtures/scitokens.cfg), comment/blank handling, section tracking,
 * trimming, and the malformed-line error path. Exit 0 = all pass.
 */

#include "ini.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int g_checks;
static int g_failed;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        g_checks++;                                                            \
        if (!(cond)) {                                                         \
            g_failed++;                                                        \
            fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);          \
        }                                                                      \
    } while (0)

/* collector: record every (section,key,value) the parser emits */struct kv {
    char section[64];
    char key[64];
    char value[256];
};

struct collector {
    struct kv kv[64];
    int       n;
};

static int
collect_cb(void *u, const char *section, const char *key, const char *value)
{
    struct collector *c = u;
    if (c->n >= 64) {
        return -1;
    }
    snprintf(c->kv[c->n].section, sizeof(c->kv[c->n].section), "%s", section);
    snprintf(c->kv[c->n].key, sizeof(c->kv[c->n].key), "%s", key);
    snprintf(c->kv[c->n].value, sizeof(c->kv[c->n].value), "%s", value);
    c->n++;
    return 0;
}

static const struct kv *
find_kv(const struct collector *c, const char *section, const char *key)
{
    int i;
    for (i = 0; i < c->n; i++) {
        if (strcmp(c->kv[i].section, section) == 0
            && strcmp(c->kv[i].key, key) == 0)
        {
            return &c->kv[i];
        }
    }
    return NULL;
}

/* write a temp INI file, return its path in `out` */
static void
write_tmp(const char *content, char *out, size_t outsz)
{
    snprintf(out, outsz, "/tmp/ini_ut_%d.cfg", (int) getpid());
    FILE *f = fopen(out, "we");
    if (f == NULL) { perror("fopen"); exit(2); }
    fputs(content, f);
    fclose(f);
}

/* test: the real upstream scitokens.cfg fixture */static void
test_stock_fixture(void)
{
    struct collector c = {0};
    char  err[256] = "";
    const char *path = "tests/fixtures/scitokens.cfg";

    /* allow running from repo root or src/token */
    if (access(path, R_OK) != 0) {
        path = "../../tests/fixtures/scitokens.cfg";
    }
    int rc = xrootd_ini_parse_file(path, collect_cb, &c, err, sizeof(err));
    CHECK(rc == 0, "stock fixture parses");
    if (rc != 0) { fprintf(stderr, "  err: %s\n", err); return; }

    const struct kv *k;
    k = find_kv(&c, "Issuer OSG-Connect", "issuer");
    CHECK(k && strcmp(k->value, "https://scitokens.org/osg-connect") == 0,
          "OSG-Connect issuer URL");
    k = find_kv(&c, "Issuer OSG-Connect", "base_path");
    CHECK(k && strcmp(k->value, "/stash") == 0, "OSG-Connect base_path");
    k = find_kv(&c, "Issuer OSG-Connect", "map_subject");
    CHECK(k && strcmp(k->value, "True") == 0, "OSG-Connect map_subject");
    k = find_kv(&c, "Issuer CMS", "issuer");
    CHECK(k && strcmp(k->value, "https://scitokens.org/cms") == 0,
          "CMS issuer URL");
    k = find_kv(&c, "Issuer CMS", "map_subject");
    CHECK(k && strcmp(k->value, "False") == 0, "CMS map_subject");
}

/* test: trimming, comments, blank lines, [Global] */static void
test_trim_and_comments(void)
{
    struct collector c = {0};
    char err[256], path[64];
    write_tmp(
        "# a comment\n"
        "\n"
        "[Global]\n"
        "   audience   =   https://a , https://b   ; trailing comment\n"
        "\n"
        "[Issuer X]\n"
        "issuer=https://x\n"
        "base_path = /x\n",
        path, sizeof(path));

    int rc = xrootd_ini_parse_file(path, collect_cb, &c, err, sizeof(err));
    CHECK(rc == 0, "trim/comment fixture parses");

    const struct kv *k = find_kv(&c, "Global", "audience");
    CHECK(k != NULL, "global audience present");
    CHECK(k && strcmp(k->value, "https://a , https://b") == 0,
          "value trimmed, inline comment stripped");
    k = find_kv(&c, "Issuer X", "issuer");
    CHECK(k && strcmp(k->value, "https://x") == 0, "no-space key=value");
    unlink(path);
}

/* test: malformed line (no '=') is rejected */static void
test_malformed(void)
{
    struct collector c = {0};
    char err[256], path[64];
    write_tmp("[Issuer X]\nthis line has no equals\n", path, sizeof(path));

    int rc = xrootd_ini_parse_file(path, collect_cb, &c, err, sizeof(err));
    CHECK(rc != 0, "malformed line rejected");
    CHECK(strstr(err, "missing '='") != NULL, "error message names the cause");
    unlink(path);
}

/* test: missing file errors cleanly */static void
test_missing_file(void)
{
    struct collector c = {0};
    char err[256] = "";
    int rc = xrootd_ini_parse_file("/nonexistent/xyz.cfg", collect_cb, &c,
                                   err, sizeof(err));
    CHECK(rc == -1, "missing file returns -1");
    CHECK(err[0] != '\0', "missing file sets an error string");
}

int
main(void)
{
    test_stock_fixture();
    test_trim_and_comments();
    test_malformed();
    test_missing_file();

    printf("ini_unittest: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}

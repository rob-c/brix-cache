/* jsonout_unit.c — unit tests for lib/cli/jsonout.c
 * WHAT: verifies JSON string escaping and kv emit helpers.
 * WHY:  one escaper shared by xrdfs --json and xrddiag --json; a broken
 *       escaper is an output-injection bug.
 * HOW:  render into a memstream, compare byte-exact. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cli/jsonout.h"

static char *render(void (*fn)(FILE *, const char *), const char *in)
{
    char  *buf = NULL;
    size_t sz = 0;
    FILE  *f = open_memstream(&buf, &sz);
    fn(f, in);
    fclose(f);
    return buf;
}

static void test_plain_roundtrip(void)          /* success */
{
    char *s = render(brix_json_fputs, "hello.txt");
    assert(strcmp(s, "\"hello.txt\"") == 0);
    free(s);
}

static void test_escapes(void)                   /* error-shaped input */
{
    char *s = render(brix_json_fputs, "a\"b\\c\nd\te");
    assert(strcmp(s, "\"a\\\"b\\\\c\\nd\\te\"") == 0);
    free(s);
}

static void test_injection_blocked(void)         /* security-negative */
{
    /* An embedded quote+brace must NOT be able to close the JSON string. */
    char *s = render(brix_json_fputs, "x\",\"evil\":1,\"y");
    assert(strstr(s, "\\\"") != NULL);
    assert(strstr(s, "\"evil\"") == NULL);   /* the quotes around evil are escaped */
    free(s);
    /* Control + high bytes become \u00XX (ASCII-safe output). */
    s = render(brix_json_fputs, "\x01\x9f");
    assert(strcmp(s, "\"\\u0001\\u009f\"") == 0);
    free(s);
}

static void test_kv_helpers(void)
{
    char  *buf = NULL; size_t sz = 0;
    FILE  *f = open_memstream(&buf, &sz);
    brix_json_kv_str(f, "name", "a b", 1);
    brix_json_kv_ll(f, "size", 42, 1);
    brix_json_kv_bool(f, "dir", 0, 0);
    fclose(f);
    assert(strcmp(buf, "\"name\":\"a b\",\"size\":42,\"dir\":false") == 0);
    free(buf);
}

int main(void)
{
    test_plain_roundtrip();
    test_escapes();
    test_injection_blocked();
    test_kv_helpers();
    printf("jsonout_unit: ALL PASS\n");
    return 0;
}

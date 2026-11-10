/* Public redirect-cache contracts: bounded chains, eviction and cycle refusal. */
#include "net/redir_registry.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void
check_chain(void)
{
    brix_vredir_record("root://a/file", "root://b/file");
    brix_vredir_record("root://b/file", "roots://c/file");
    assert(strcmp(brix_vredir_lookup("root://a/file"), "roots://c/file") == 0);
    brix_vredir_record("roots://c/file", "root://a/file");
    assert(brix_vredir_lookup("roots://c/file") == NULL);
    assert(brix_vredir_count() == 2);
    brix_vredir_record("root://b/file", "root://d/file");
    assert(strcmp(brix_vredir_lookup("root://a/file"), "root://d/file") == 0);
    brix_vredir_record("root://e/file", "root://a/file");
    assert(strcmp(brix_vredir_lookup("root://e/file"), "root://d/file") == 0);
    brix_vredir_clear();
    assert(brix_vredir_count() == 0 && brix_vredir_lookup("root://a/file") == NULL);
}

static void
check_invalid(void)
{
    const char *bad[] = {NULL, ""};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        brix_vredir_record(bad[i], "root://target/");
        brix_vredir_record("root://source/", bad[i]);
        assert(brix_vredir_lookup(bad[i]) == NULL);
    }
    brix_vredir_record("root://same/", "root://same/");
    assert(brix_vredir_count() == 0);
    assert(brix_vredir_lookup("root://unknown/") == NULL);
    brix_vredir_clear();
}

static void
check_capacity(void)
{
    char key[64];
    for (unsigned i = 0; i < 256; i++) {
        snprintf(key, sizeof(key), "root://host-%u/file", i);
        brix_vredir_record(key, "roots://target/file");
    }
    assert(brix_vredir_count() == 256);
    brix_vredir_record("root://host-0/file", "roots://updated/file");
    brix_vredir_record("root://overflow/file", "roots://target/file");
    assert(brix_vredir_count() == 256);
    assert(brix_vredir_lookup("root://host-1/file") == NULL);
    assert(strcmp(brix_vredir_lookup("root://host-0/file"), "roots://updated/file") == 0);
    assert(strcmp(brix_vredir_lookup("root://overflow/file"), "roots://target/file") == 0);
    brix_vredir_clear();
    brix_vredir_clear();
    assert(brix_vredir_count() == 0);
}

static void
check_hop_bound(void)
{
    char source[32], target[32];
    for (unsigned i = 0; i < 40; i++) {
        snprintf(source, sizeof(source), "root://h%u/", i);
        snprintf(target, sizeof(target), "root://h%u/", i + 1);
        brix_vredir_record(source, target);
    }
    assert(strcmp(brix_vredir_lookup("root://h0/"), "root://h32/") == 0);
    assert(strcmp(brix_vredir_lookup("root://h30/"), "root://h40/") == 0);
    brix_vredir_clear();
}

int
main(void)
{
    check_invalid();
    check_chain();
    check_capacity();
    check_hop_bound();
    puts("redirect registry unit tests: ALL PASS");
    return 0;
}

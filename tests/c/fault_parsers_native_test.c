/* Bound the production fault-proxy parsers and mutations with guard bytes. */
#include "brix_fault_ext.h"
#include "brix_fault_proxy_mods.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef main

static int mutate(unsigned char *out, size_t capacity, const char *kind)
{
    fp_ext_mut mutation = {0}; fp_ext_stats stats = {0}; unsigned seed = 42;
    if (!strcmp(kind, "inject")) { mutation.inject = (const unsigned char *) "prefix"; mutation.inject_len = 6; }
    if (!strcmp(kind, "rewrite")) {
        mutation.find = (const unsigned char *) "ab"; mutation.find_len = 2;
        mutation.repl = (const unsigned char *) "XYZ"; mutation.repl_len = 3;
    }
    if (!strcmp(kind, "drop")) { mutation.drop_ppm = 1000000; }
    if (!strcmp(kind, "repeat")) { mutation.repeat_ppm = 1000000; }
    assert(fp_ext_mut_active(&mutation) == (strcmp(kind, "plain") != 0));
    size_t count = fp_ext_mutate((const unsigned char *) "abab!", 5, out, capacity,
                                &mutation, &seed, &stats);
    fprintf(stderr, "drop=%lu repeat=%lu inject=%lu replace=%lu\n", stats.dropped,
        stats.repeated, stats.injected, stats.replaced);
    return (int) count;
}
static int parse(char **argv, unsigned char *output, size_t capacity)
{
    const char *input = !strcmp(argv[3], "<null>") ? NULL : argv[3];
    if (!strcmp(argv[1], "payload")) { return fp_ext_parse_payload(input, output, capacity); }
    if (!strcmp(argv[1], "v1")) { return fp_ext_proxy_v1((char *) output, capacity, input, argv[4]); }
    if (!strcmp(argv[1], "v2")) { return fp_ext_proxy_v2(output, capacity, input, argv[4]); }
    if (!strcmp(argv[1], "mutate")) { return mutate(output, capacity, input); }
    if (!strcmp(argv[1], "verb")) { return fp_json_to_verb(input, (char *) output, capacity); }
    assert(!strcmp(argv[1], "get")); return fp_json_get(input, argv[4], (char *) output, capacity);
}
int main(int argc, char **argv)
{
    assert(argc == 6); size_t capacity = strtoul(argv[2], NULL, 10); assert(capacity <= 4096);
    unsigned char buffer[4128]; memset(buffer, 0xa5, sizeof(buffer));
    int result = parse(argv, buffer + 8, capacity);
    fprintf(stderr, "result=%d\n", result); assert(result == atoi(argv[5]));
    for (unsigned i = 0; i < 8; ++i) { assert(buffer[i] == 0xa5 && buffer[8 + capacity + i] == 0xa5); }
    if (result >= 0) {
        size_t length = (size_t) result;
        if (!strcmp(argv[1], "verb") || (!strcmp(argv[1], "get") && result == 1)) {
            length = strnlen((char *) buffer + 8, capacity); assert(length < capacity);
        }
        assert(length <= capacity && fwrite(buffer + 8, 1, length, stdout) == length);
    }
    return 0;
}

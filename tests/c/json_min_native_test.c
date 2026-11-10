/* Exercise the diagnostic JSON extractor with exact input extents and canaries. */
#include "core/compat/json_min.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* WHAT: Extract one member and print its bounded output as hex.
 * WHY: Sanitizers must see input without an extra readable terminator.
 * HOW: 1. Allocate exact input. 2. Surround output. 3. Check and report bytes.
 */
int main(int argc, char **argv)
{
    assert(argc == 5);
    size_t length = strlen(argv[1]);
    size_t capacity = (size_t) strtoul(argv[3], NULL, 10);
    assert(capacity <= 1024);
    char *input = malloc(length ? length : 1);
    unsigned char *output = malloc(capacity + 2);
    assert(input != NULL && output != NULL);
    memcpy(input, argv[1], length);
    memset(output, 0xa5, capacity + 2);
    const char *json = strcmp(argv[4], "null-json") == 0 ? NULL : input;
    const char *key = strcmp(argv[4], "null-key") == 0 ? NULL : argv[2];
    char *target = strcmp(argv[4], "null-output") == 0 ? NULL : (char *) output + 1;
    int found = brix_json_get_str(json, length, key, target, capacity);
    assert(output[0] == 0xa5 && output[capacity + 1] == 0xa5);
    printf("%d:", found);
    for (size_t index = 1; index <= capacity; ++index) {
        printf("%02x", output[index]);
    }
    putchar('\n');
    free(output);
    free(input);
    return 0;
}

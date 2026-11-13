/* WHAT: Replay checked-in parser corpora through their actual fuzz entry point.
 * WHY: Deterministic regression runs must retain the fuzz harness assertions
 *      and permit normal-process coverage collection without libFuzzer.
 * HOW: Bound each file, read its exact bytes, invoke the existing harness, and
 *      exit normally only after every supplied input completed successfully. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* WHAT: Replay one corpus file, returning nonzero for invalid/unreadable input.
 * WHY: A missing or oversized corpus must fail instead of yielding a false pass.
 * HOW: Determine its bounded length, read all bytes, then invoke the harness. */
static int
replay_file(const char *path)
{
    FILE *input = fopen(path, "rb");
    if (input == NULL) {
        return 2;
    }
    if (fseek(input, 0, SEEK_END) != 0) {
        fclose(input);
        return 3;
    }
    long length = ftell(input);
    if (length < 0 || length > 16 * 1024 * 1024 ||
        fseek(input, 0, SEEK_SET) != 0) {
        fclose(input);
        return 4;
    }
    uint8_t *data = malloc((size_t) length + 1);
    if (data == NULL) {
        fclose(input);
        return 5;
    }
    size_t received = fread(data, 1, (size_t) length, input);
    fclose(input);
    if (received != (size_t) length) {
        free(data);
        return 6;
    }
    int result = LLVMFuzzerTestOneInput(data, received);
    free(data);
    return result;
}

/* WHAT: Run a finite batch of fuzz inputs, including the empty-input boundary.
 * WHY: Keep every production invariant/assertion in the existing fuzz harness.
 * HOW: Invoke the public fuzz hook, stop on failure, and report replay count. */
int
main(int argc, char **argv)
{
    const uint8_t empty = 0;
    int result = LLVMFuzzerTestOneInput(&empty, 0);
    if (result != 0) {
        return result;
    }
    for (int index = 1; index < argc; index++) {
        result = replay_file(argv[index]);
        if (result != 0) {
            fprintf(stderr, "corpus replay failed: %s\n", argv[index]);
            return result;
        }
    }
    printf("replayed %d corpus files\n", argc - 1);
    return 0;
}

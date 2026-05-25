#include "../../src/compat/crc32c.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int
expect_u32(const char *name, uint32_t got, uint32_t want)
{
    if (got != want) {
        printf("%s failed: got %08x want %08x\n", name, got, want);
        return 1;
    }

    return 0;
}

int
main(void)
{
    const unsigned char known[] = "123456789";
    const unsigned char payload[] = "split crc32c payload";
    unsigned char       copy[sizeof(payload)];
    uint32_t            split;
    int                 failed = 0;

    failed |= expect_u32("known vector",
                         xrootd_crc32c_value(known, strlen((const char *) known)),
                         0xe3069283u);

    memset(copy, 0, sizeof(copy));
    failed |= expect_u32("copy vector",
                         xrootd_crc32c_copy_value(payload, copy, sizeof(payload) - 1),
                         xrootd_crc32c_value(payload, sizeof(payload) - 1));
    if (memcmp(copy, payload, sizeof(payload) - 1) != 0) {
        printf("copy payload failed\n");
        failed = 1;
    }

    split = 0;
    split = xrootd_crc32c_extend(split, payload, 5);
    split = xrootd_crc32c_extend(split, payload + 5, sizeof(payload) - 6);
    failed |= expect_u32("split extend", split,
                         xrootd_crc32c_value(payload, sizeof(payload) - 1));

    if (failed) {
        return 1;
    }

    printf("crc32c compat helpers passed\n");
    return 0;
}

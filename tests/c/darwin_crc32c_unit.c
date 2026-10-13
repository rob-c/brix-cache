/* Apple-Silicon CRC32C success, tail/error, and corruption checks. */
#include "core/compat/crc32c.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static uint32_t
reference_crc32c(uint32_t crc, const uint8_t *data, size_t len)
{
    crc ^= 0xFFFFFFFFu;
    while (len-- != 0) {
        int bit;

        crc ^= *data++;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0x82F63B78u & (uint32_t) -(int) (crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

int
main(void)
{
    uint8_t source[129];
    uint8_t copied[129];
    size_t  i;

    assert(brix_crc32c_value("123456789", 9) == 0xE3069283u);
    for (i = 0; i < sizeof(source); i++) source[i] = (uint8_t) (i * 37U + 11U);
    for (i = 0; i <= sizeof(source); i++) {
        assert(brix_crc32c_value(source, i) == reference_crc32c(0, source, i));
    }
    assert(brix_crc32c_copy_value(source, copied, sizeof(source))
        == reference_crc32c(0, source, sizeof(source)));
    assert(memcmp(source, copied, sizeof(source)) == 0);
    copied[64] ^= 0x80U;
    assert(brix_crc32c_value(copied, sizeof(copied))
        != brix_crc32c_value(source, sizeof(source)));
    return 0;
}

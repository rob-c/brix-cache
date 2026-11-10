/* Execute the Linux ARM64 checksum entry points over guarded, unaligned data.
 * The Python caller supplies an independent numeric oracle for each operation.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

uint32_t brix_adler32_neon(const uint8_t *, size_t, uint32_t);
uint16_t brix_fletcher16_neon(const uint8_t *, size_t);
uint64_t brix_xor_checksum_neon(const uint8_t *, size_t, uint64_t);
uint32_t brix_memcpy_crc32_neon(void *, const void *, size_t, uint32_t);
uint32_t brix_byte_sum_neon(const uint8_t *, size_t);
uint32_t brix_crc32c_generic(const uint8_t *, size_t, uint32_t);
uint32_t brix_crc32c_dispatch(const uint8_t *, size_t, uint32_t);
uint64_t brix_checksum_neon(const void *, size_t);
int brix_arm64_has_crc32_instructions(void);
const char *brix_arm64_get_optimization_info(void);
void brix_arm64_init(void);

/* WHAT: Copy and checksum without touching either red zone.
 * WHY: A vector tail may cross an inaccessible page or overwrite its suffix.
 * HOW: 1. Surround destination with canaries. 2. Compare every copied byte.
 */
static uint32_t copy_crc(const uint8_t *data, size_t length, uint32_t seed)
{
    uint8_t *target = malloc(length + 2);
    assert(target != NULL);
    memset(target, 0xa5, length + 2);
    uint32_t result = brix_memcpy_crc32_neon(target + 1, data, length, seed);
    assert(target[0] == 0xa5 && target[length + 1] == 0xa5);
    assert(memcmp(target + 1, data, length) == 0);
    free(target);
    return result;
}

/* WHAT: Select one real checksum operation.
 * WHY: Each independent process reports the complete result to its oracle.
 * HOW: 1. Dispatch by explicit name. 2. Reject unknown operations.
 */
static uint64_t calculate(const char *name, const uint8_t *data,
                          size_t length, uint64_t seed)
{
    if (strcmp(name, "adler") == 0) {
        return brix_adler32_neon(data, length, (uint32_t) seed);
    }
    if (strcmp(name, "fletcher") == 0) {
        return brix_fletcher16_neon(data, length);
    }
    if (strcmp(name, "xor") == 0) {
        return brix_xor_checksum_neon(data, length, seed);
    }
    if (strcmp(name, "copy-crc") == 0) {
        return copy_crc(data, length, (uint32_t) seed);
    }
    if (strcmp(name, "byte-sum") == 0) {
        return brix_byte_sum_neon(data, length);
    }
    if (strcmp(name, "raw-crc") == 0) {
        return brix_crc32c_generic(data, length, (uint32_t) seed);
    }
    if (strcmp(name, "dispatch-crc") == 0) {
        return brix_crc32c_dispatch(data, length, (uint32_t) seed);
    }
    assert(strcmp(name, "word-sum") == 0);
    return brix_checksum_neon(data, length);
}

/* WHAT: Place deterministic input immediately before a protected page.
 * WHY: Empty input and every vector-tail length must avoid over-reading.
 * HOW: 1. Map enough pages. 2. Protect the last page. 3. Fill only live bytes.
 */
static uint8_t *guarded_input(size_t length, void **mapping, size_t *extent)
{
    size_t page = (size_t) sysconf(_SC_PAGESIZE);
    size_t writable = ((length + page - 1) / page) * page;
    *extent = writable + page;
    *mapping = mmap(NULL, *extent, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(*mapping != MAP_FAILED);
    uint8_t *guard = (uint8_t *) *mapping + writable;
    assert(mprotect(guard, page, PROT_NONE) == 0);
    uint8_t *data = guard - length;
    for (size_t index = 0; index < length; ++index) {
        data[index] = (uint8_t) (index * 37 + 19);
    }
    return data;
}

/* WHAT: Report a checksum or the host capability contract.
 * WHY: Hardware dispatch and software fallback must obey the same raw CRC ABI.
 * HOW: 1. Validate invocation. 2. Exercise real routines. 3. Release mapping.
 */
int main(int argc, char **argv)
{
    assert(argc == 4);
    if (strcmp(argv[1], "features") == 0) {
        int supported = brix_arm64_has_crc32_instructions();
        assert(supported == 0 || supported == 1);
        const char *info = brix_arm64_get_optimization_info();
        assert(strstr(info, supported ? "CRC32=yes" : "CRC32=no") != NULL);
        assert(strstr(info, "PMULL=") != NULL && strstr(info, "SHA2=") != NULL);
        brix_arm64_init();
        assert(brix_arm64_has_crc32_instructions() == supported);
        puts("features ok");
        return 0;
    }
    size_t length = (size_t) strtoul(argv[2], NULL, 10);
    assert(length <= 1024 * 1024);
    uint64_t seed = strtoull(argv[3], NULL, 0);
    void *mapping;
    size_t extent;
    uint8_t *data = guarded_input(length, &mapping, &extent);
    printf("%llu\n", (unsigned long long) calculate(argv[1], data, length, seed));
    assert(munmap(mapping, extent) == 0);
    return 0;
}

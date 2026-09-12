/*
 * test_checksum_accelerate.c - Test program for Accelerate framework vDSP
 * 
 * Compile: clang -framework Accelerate -O3 -o test_checksum test_checksum_accelerate.c
 * Run: ./test_checksum
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <Accelerate/Accelerate.h>

/* Scalar fallback implementation */
static uint64_t
checksum_scalar(const void *buf, size_t len)
{
    const uint64_t *data64 = (const uint64_t *)buf;
    const uint8_t *data8 = (const uint8_t *)buf;
    uint64_t sum = 0;
    size_t i;
    
    for (i = 0; i < len / 8; i++) {
        sum += data64[i];
    }
    
    for (i = len - (len % 8); i < len; i++) {
        sum += data8[i];
    }
    
    return sum;
}

/* vDSP-based checksum using dot product */
static uint64_t
checksum_vdsp_dotpr(const void *buf, size_t len)
{
    const float *data = (const float *)buf;
    size_t count = len / sizeof(float);
    float result = 0.0f;
    
    if (count >= 16) {
        float *ones = (float *)malloc(count * sizeof(float));
        if (ones != NULL) {
            float one = 1.0f;
            vDSP_vfill(&one, ones, 1, count);
            vDSP_dotpr(data, 1, ones, 1, &result, count);
            free(ones);
        } else {
            return checksum_scalar(buf, len);
        }
    } else {
        return checksum_scalar(buf, len);
    }
    
    uint64_t sum = (uint64_t)result;
    
    size_t processed = count * sizeof(float);
    if (processed < len) {
        const uint8_t *remaining = (const uint8_t *)buf + processed;
        size_t remaining_len = len - processed;
        
        for (size_t i = 0; i < remaining_len; i++) {
            sum += remaining[i];
        }
    }
    
    return sum;
}

/* vDSP-based checksum using sum of vector elements */
static uint64_t
checksum_vdsp_sve(const void *buf, size_t len)
{
    const float *data = (const float *)buf;
    size_t count = len / sizeof(float);
    float result = 0.0f;
    
    if (count >= 16) {
        vDSP_sve(data, 1, &result, count);
    } else {
        return checksum_scalar(buf, len);
    }
    
    uint64_t sum = (uint64_t)result;
    
    size_t processed = count * sizeof(float);
    if (processed < len) {
        const uint8_t *remaining = (const uint8_t *)buf + processed;
        size_t remaining_len = len - processed;
        
        for (size_t i = 0; i < remaining_len; i++) {
            sum += remaining[i];
        }
    }
    
    return sum;
}

int
main(int argc, char *argv[])
{
    const size_t test_sizes[] = {16, 64, 256, 1024, 4096, 65536};
    const int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);
    int i, j;
    
    printf("Testing Accelerate framework vDSP checksum...\n\n");
    
    for (i = 0; i < num_tests; i++) {
        size_t len = test_sizes[i];
        void *buf = malloc(len);
        
        if (buf == NULL) {
            fprintf(stderr, "Failed to allocate %zu bytes\n", len);
            return 1;
        }
        
        /* Initialize with pattern */
        memset(buf, 0xAA, len);
        
        /* Calculate checksums */
        uint64_t scalar_result = checksum_scalar(buf, len);
        uint64_t vdsp_dotpr_result = checksum_vdsp_dotpr(buf, len);
        uint64_t vdsp_sve_result = checksum_vdsp_sve(buf, len);
        
        /* Verify alignment */
        uintptr_t addr = (uintptr_t)buf;
        const char *aligned = (addr & 15) ? "misaligned" : "aligned";
        
        /* Print results */
        printf("Buffer size: %6zu bytes (%s)\n", len, aligned);
        printf("  Scalar:    0x%016llx\n", (unsigned long long)scalar_result);
        printf("  vDSP_sve:  0x%016llx %s\n", (unsigned long long)vdsp_sve_result,
               (scalar_result == vdsp_sve_result) ? "✓" : "✗");
        printf("  vDSP_dotpr: 0x%016llx %s\n\n", (unsigned long long)vdsp_dotpr_result,
               (scalar_result == vdsp_dotpr_result) ? "✓" : "✗");
        
        free(buf);
    }
    
    /* Test with random data */
    printf("Testing with random data (1MB)...\n");
    size_t large_size = 1024 * 1024;
    void *large_buf = malloc(large_size);
    
    if (large_buf == NULL) {
        fprintf(stderr, "Failed to allocate large buffer\n");
        return 1;
    }
    
    /* Fill with random pattern */
    for (i = 0; i < large_size / 8; i++) {
        ((uint64_t *)large_buf)[i] = (uint64_t)i * 0x123456789ABCDEF0ULL;
    }
    
    uint64_t scalar_large = checksum_scalar(large_buf, large_size);
    uint64_t vdsp_sve_large = checksum_vdsp_sve(large_buf, large_size);
    uint64_t vdsp_dotpr_large = checksum_vdsp_dotpr(large_buf, large_size);
    
    printf("  Scalar:     0x%016llx\n", (unsigned long long)scalar_large);
    printf("  vDSP_sve:   0x%016llx %s\n", (unsigned long long)vdsp_sve_large,
           (scalar_large == vdsp_sve_large) ? "✓" : "✗");
    printf("  vDSP_dotpr: 0x%016llx %s\n\n", (unsigned long long)vdsp_dotpr_large,
           (scalar_large == vdsp_dotpr_large) ? "✓" : "✗");
    
    free(large_buf);
    
    /* Test vDSP functions directly */
    printf("Direct vDSP function tests:\n");
    
    float test_data[8] = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    float sum_result = 0.0;
    
    vDSP_sve(test_data, 1, &sum_result, 8);
    printf("  vDSP_sve([1..8]) = %.1f (expected 36.0) %s\n", 
           sum_result, (sum_result == 36.0) ? "✓" : "✗");
    
    /* Test vDSP_dotpr */
    float ones[8] = {1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};
    float dotpr_result = 0.0;
    
    vDSP_dotpr(test_data, 1, ones, 1, &dotpr_result, 8);
    printf("  vDSP_dotpr([1..8], [1..1]) = %.1f (expected 36.0) %s\n",
           dotpr_result, (dotpr_result == 36.0) ? "✓" : "✗");
    
    /* Test vDSP_vfill */
    float fill_data[8];
    float fill_value = 42.0;
    vDSP_vfill(&fill_value, fill_data, 1, 8);
    printf("  vDSP_vfill([42.0]) = [");
    for (i = 0; i < 8; i++) {
        printf("%.0f%s", fill_data[i], (i < 7) ? ", " : "");
    }
    printf("] %s\n", (fill_data[0] == 42.0 && fill_data[7] == 42.0) ? "✓" : "✗");
    
    printf("\nAll tests completed!\n");
    
    return 0;
}

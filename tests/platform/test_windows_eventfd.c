/*
 * tests/platform/test_windows_eventfd.c - Windows eventfd implementation tests
 * 
 * Tests for brix_plat_eventfd() and helpers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "../../src/platform/platform_api.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static int test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running %s... ", #name); \
    tests_run++; \
    if (test_##name() == 0) { \
        printf("✅ PASS\n"); \
        tests_passed++; \
    } else { \
        printf("❌ FAIL\n"); \
    } \
} while(0)

TEST(eventfd_create_basic)
{
    /* Test basic eventfd creation */
    int efd = brix_plat_eventfd(0, 0);
    
    if (efd < 0) {
        printf("Failed to create eventfd: errno=%d\n", errno);
        return -1;
    }
    
    /* Cleanup */
    if (brix_plat_eventfd_close(efd) < 0) {
        printf("Failed to close eventfd\n");
        return -1;
    }
    
    return 0;
}

TEST(eventfd_create_cloexec)
{
    /* Test eventfd with CLOEXEC flag */
    int efd = brix_plat_eventfd(0, BRIX_EVENTFD_CLOEXEC);
    
    if (efd < 0) {
        printf("Failed to create eventfd with CLOEXEC: errno=%d\n", errno);
        return -1;
    }
    
    if (brix_plat_eventfd_close(efd) < 0) {
        printf("Failed to close eventfd\n");
        return -1;
    }
    
    return 0;
}

TEST(eventfd_write_read)
{
    /* Test basic write/read cycle */
    int efd = brix_plat_eventfd(0, 0);
    
    if (efd < 0) {
        printf("Failed to create eventfd\n");
        return -1;
    }
    
    /* Write value */
    uint64_t write_val = 1;
    if (brix_plat_eventfd_write(efd, write_val) < 0) {
        printf("Failed to write to eventfd: errno=%d\n", errno);
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    /* Read value */
    uint64_t read_val = 0;
    if (brix_plat_eventfd_read(efd, &read_val) < 0) {
        printf("Failed to read from eventfd: errno=%d\n", errno);
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    if (read_val != write_val) {
        printf("Read value (%llu) != written value (%llu)\n", 
               (unsigned long long)read_val, (unsigned long long)write_val);
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    brix_plat_eventfd_close(efd);
    return 0;
}

TEST(eventfd_initial_value)
{
    /* Test eventfd with initial value */
    int efd = brix_plat_eventfd(5, 0);
    
    if (efd < 0) {
        printf("Failed to create eventfd with initial value\n");
        return -1;
    }
    
    /* Read should return initial value */
    uint64_t read_val = 0;
    if (brix_plat_eventfd_read(efd, &read_val) < 0) {
        printf("Failed to read initial value: errno=%d\n", errno);
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    if (read_val != 5) {
        printf("Initial value (%llu) != expected (5)\n", 
               (unsigned long long)read_val);
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    brix_plat_eventfd_close(efd);
    return 0;
}

TEST(eventfd_multiple_writes)
{
    /* Test multiple writes accumulate */
    int efd = brix_plat_eventfd(0, 0);
    
    if (efd < 0) {
        printf("Failed to create eventfd\n");
        return -1;
    }
    
    /* Write multiple times */
    for (int i = 0; i < 5; i++) {
        if (brix_plat_eventfd_write(efd, 1) < 0) {
            printf("Failed to write to eventfd (iteration %d)\n", i);
            brix_plat_eventfd_close(efd);
            return -1;
        }
    }
    
    /* Read should return sum */
    uint64_t read_val = 0;
    if (brix_plat_eventfd_read(efd, &read_val) < 0) {
        printf("Failed to read accumulated value\n");
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    if (read_val != 5) {
        printf("Accumulated value (%llu) != expected (5)\n", 
               (unsigned long long)read_val);
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    brix_plat_eventfd_close(efd);
    return 0;
}

TEST(eventfd_overflow_check)
{
    /* Test overflow detection */
    int efd = brix_plat_eventfd(0, 0);
    
    if (efd < 0) {
        printf("Failed to create eventfd\n");
        return -1;
    }
    
    /* Write near-max value */
    uint64_t large_val = UINT64_MAX - 100;
    if (brix_plat_eventfd_write(efd, large_val) < 0) {
        printf("Failed to write large value\n");
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    /* Try to overflow - should fail with EINVAL */
    if (brix_plat_eventfd_write(efd, 200) >= 0) {
        printf("Overflow write should have failed\n");
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    if (errno != EINVAL) {
        printf("Expected EINVAL on overflow, got errno=%d\n", errno);
        brix_plat_eventfd_close(efd);
        return -1;
    }
    
    brix_plat_eventfd_close(efd);
    return 0;
}

TEST(eventfd_invalid_fd)
{
    /* Test invalid fd handling */
    uint64_t val;
    
    /* Try to operate on invalid fd */
    if (brix_plat_eventfd_write(-1, 1) >= 0) {
        printf("Write to invalid fd should fail\n");
        return -1;
    }
    
    if (brix_plat_eventfd_read(-1, &val) >= 0) {
        printf("Read from invalid fd should fail\n");
        return -1;
    }
    
    if (brix_plat_eventfd_close(-1) >= 0) {
        printf("Close invalid fd should fail\n");
        return -1;
    }
    
    return 0;
}

TEST(eventfd_double_close)
{
    /* Test double close protection */
    int efd = brix_plat_eventfd(0, 0);
    
    if (efd < 0) {
        printf("Failed to create eventfd\n");
        return -1;
    }
    
    if (brix_plat_eventfd_close(efd) < 0) {
        printf("First close failed\n");
        return -1;
    }
    
    /* Second close should fail with EBADF */
    if (brix_plat_eventfd_close(efd) >= 0) {
        printf("Double close should fail\n");
        return -1;
    }
    
    return 0;
}

TEST(pipe2_basic)
{
    /* Test basic pipe2 creation */
    int pipefd[2];
    
    if (brix_plat_pipe2(pipefd, 0) < 0) {
        printf("Failed to create pipe: errno=%d\n", errno);
        return -1;
    }
    
    /* Test basic write/read */
    const char *msg = "test";
    if (_write(pipefd[1], msg, 5) != 5) {
        printf("Failed to write to pipe\n");
        _close(pipefd[0]);
        _close(pipefd[1]);
        return -1;
    }
    
    char buf[10];
    if (_read(pipefd[0], buf, 5) != 5) {
        printf("Failed to read from pipe\n");
        _close(pipefd[0]);
        _close(pipefd[1]);
        return -1;
    }
    
    if (strcmp(buf, msg) != 0) {
        printf("Pipe message mismatch\n");
        _close(pipefd[0]);
        _close(pipefd[1]);
        return -1;
    }
    
    _close(pipefd[0]);
    _close(pipefd[1]);
    return 0;
}

TEST(pipe2_cloexec)
{
    /* Test pipe2 with CLOEXEC flag */
    int pipefd[2];
    
    if (brix_plat_pipe2(pipefd, BRIX_PIPE_CLOEXEC) < 0) {
        printf("Failed to create pipe with CLOEXEC: errno=%d\n", errno);
        return -1;
    }
    
    /* Cleanup */
    _close(pipefd[0]);
    _close(pipefd[1]);
    return 0;
}

int main(void)
{
    printf("=== Windows eventfd Implementation Tests ===\n\n");
    
    RUN_TEST(eventfd_create_basic);
    RUN_TEST(eventfd_create_cloexec);
    RUN_TEST(eventfd_write_read);
    RUN_TEST(eventfd_initial_value);
    RUN_TEST(eventfd_multiple_writes);
    RUN_TEST(eventfd_overflow_check);
    RUN_TEST(eventfd_invalid_fd);
    RUN_TEST(eventfd_double_close);
    RUN_TEST(pipe2_basic);
    RUN_TEST(pipe2_cloexec);
    
    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    
    return (tests_passed == tests_run) ? 0 : 1;
}

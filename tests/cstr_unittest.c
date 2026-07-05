/* Standalone unit test for src/core/compat/cstr.h — gcc, no nginx. */
#define BRIX_CSTR_NO_NGX 1
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/core/compat/cstr.h"

int main(void)
{
    char buf[8];

    /* success: fits, NUL-terminated, content exact */
    assert(brix_cbuf_copy(buf, sizeof(buf), "abc", 3) == buf);
    assert(strcmp(buf, "abc") == 0);
    /* boundary success: len == bufsize-1 (NUL exactly fills the buffer) */
    assert(brix_cbuf_copy(buf, sizeof(buf), "1234567", 7) == buf);
    assert(buf[7] == '\0' && strcmp(buf, "1234567") == 0);
    /* error: exact-fit-without-NUL and larger both refuse, buffer untouched */
    memset(buf, 'X', sizeof(buf));
    assert(brix_cbuf_copy(buf, sizeof(buf), "12345678", 8) == NULL);
    assert(brix_cbuf_copy(buf, sizeof(buf), "123456789", 9) == NULL);
    assert(buf[0] == 'X');   /* refusal must not partially write */
    /* security-neg: embedded NUL is copied verbatim, bounded, not trusted */
    assert(brix_cbuf_copy(buf, sizeof(buf), "a\0b", 3) == buf);
    assert(buf[3] == '\0' && memcmp(buf, "a\0b", 4) == 0);
    /* edge: empty input still terminates; zero-size and NULL buffers refuse */
    assert(brix_cbuf_copy(buf, sizeof(buf), "", 0) == buf && buf[0] == '\0');
    assert(brix_cbuf_copy(buf, 0, "", 0) == NULL);
    assert(brix_cbuf_copy(NULL, sizeof(buf), "a", 1) == NULL);
    printf("cstr_unittest: all checks passed\n");
    return 0;
}

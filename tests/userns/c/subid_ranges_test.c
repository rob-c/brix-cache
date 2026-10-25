/* Native parser driver: exercise the exact range selection used by both labs. */
#include "subid_ranges.h"

/* WHAT: Parse one supplied row; return 1 on rejection, 2 on bad invocation.
 * WHY: Pin success, malformed and foreign-owner cases without privileges.
 * HOW: Call the real shared parser and print only its bounded numeric result.
 */
int
main(int argc, char **argv)
{
    uint32_t start = 0;
    if (argc != 3) {
        return 2;
    }
    if (!brix_test_subid_parse(argv[1], argv[2], 2100, &start)) {
        return 1;
    }
    printf("%u\n", start);
    return 0;
}

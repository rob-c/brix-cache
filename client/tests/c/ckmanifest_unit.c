/* ckmanifest_unit.c — unit tests for brix_ckmf_parse_line.
 *
 * WHAT: Validates the manifest line parser that guards the tree/check subcommands.
 * WHY:  A hostile or corrupt manifest must never direct reads/writes outside the
 *       audit root; the parser is the sole gate before a file is opened or compared.
 * HOW:  TDD: written before the implementation, verified red then green. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "brix.h"
#include "brix_ops.h"

int main(void)
{
    char hex[132], rel[4096];

    /* success */
    assert(brix_ckmf_parse_line("03e51f2a  sub/dir/f.root\n",
                                hex, sizeof(hex), rel, sizeof(rel)) == 0);
    assert(strcmp(hex, "03e51f2a") == 0 && strcmp(rel, "sub/dir/f.root") == 0);

    /* error: malformed lines */
    assert(brix_ckmf_parse_line("", hex, sizeof(hex), rel, sizeof(rel)) == -1);
    assert(brix_ckmf_parse_line("deadbeef-no-separator", hex, sizeof(hex),
                                rel, sizeof(rel)) == -1);
    assert(brix_ckmf_parse_line("nothex!!  f\n", hex, sizeof(hex),
                                rel, sizeof(rel)) == -1);

    /* security-negative: escaping rel paths are rejected */
    assert(brix_ckmf_parse_line("03e51f2a  ../../etc/passwd\n", hex,
                                sizeof(hex), rel, sizeof(rel)) == -1);
    assert(brix_ckmf_parse_line("03e51f2a  /abs/path\n", hex, sizeof(hex),
                                rel, sizeof(rel)) == -1);

    printf("ckmanifest_unit: ALL PASS\n");
    return 0;
}

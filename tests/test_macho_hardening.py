"""Native Mach-O hardening rejects malformed and deliberately unsafe images."""

import pytest

from lib_py.macho_hardening import check_header, check_segments


def test_pie_and_non_writable_executable_text_are_checked():
    check_header("Mach header\nMH_MAGIC_64 ARM64 EXECUTE DYLDLINK PIE", executable=True)
    check_header("Mach header\nMH_MAGIC_64 ARM64 DYLIB DYLDLINK", executable=False)
    check_segments("segname __TEXT\ninitprot 0x5\nsegname __DATA\ninitprot 0x3\n")


@pytest.mark.parametrize("header", ["ELF DYN PIE", "Mach header\nMH_MAGIC_64 EXECUTE",
                                    "Mach header\nMH_MAGIC_64 EXECUTE PIE ALLOW_STACK_EXECUTION"])
def test_unknown_nonpie_and_executable_stack_images_fail(header):
    with pytest.raises(AssertionError):
        check_header(header, executable=True)


@pytest.mark.parametrize("commands", ["", "segname __DATA\ninitprot 0x3",
                                      "segname __TEXT\ninitprot 0x7"])
def test_missing_text_or_writable_executable_segments_fail(commands):
    with pytest.raises(AssertionError):
        check_segments(commands)

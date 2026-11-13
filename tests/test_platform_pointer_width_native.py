"""Linux pointer plausibility includes the documented 56-bit x86 user range."""

import subprocess
import sys

import pytest

from test_platform_linux_native import native_compile  # noqa: F401

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux PAL')


@pytest.fixture(scope='module', params=[0, 1], ids=['x86_64', 'arm64'])
def pointer_width(request, native_compile, tmp_path_factory):
    """Compile each architecture's pure value check without dereferencing addresses."""
    arm64 = request.param
    selection = tmp_path_factory.mktemp('pointer-policy') / 'selection.h'
    selection.write_text('#include "platform/platform_api.h"\n'
                         '#undef BRIX_ARCH_ARM64\n#define BRIX_ARCH_ARM64 ' + str(arm64) + '\n')
    binary = native_compile('pointer-width-' + str(arm64), r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include "platform/platform_api.h"
int main(int argc, char **argv) {
    assert(argc == 3);
    uintptr_t value = (uintptr_t) strtoull(argv[1], NULL, 16);
    assert(brix_plat_pointer_is_canonical((const void *) value) == atoi(argv[2]));
    return 0;
}
''', ['src/platform/linux/host_info.c'],
        ['-include', str(selection)])
    return binary, arm64


@pytest.mark.parametrize('address', [0x1000, 0x7fffffffffff, 0xf438d24999a0, 0xffffffffffff])
def test_ordinary_and_high_loader_addresses_are_plausible(pointer_width, address):
    """Valid module addresses must not be mistaken for dangling storage drivers."""
    binary, _arm64 = pointer_width
    subprocess.run([str(binary), format(address, 'x'), '1'], check=True, timeout=10)


def test_five_level_user_address_has_architecture_specific_width(pointer_width):
    """Accept x86's 56-bit userspace ceiling while preserving ARM's existing cap."""
    binary, arm64 = pointer_width
    subprocess.run([str(binary), '00ffffffffffffff', str(1 - arm64)], check=True, timeout=10)


@pytest.mark.parametrize('address', [0x0100000000000000, 0xffff800000000000, 0x123400008e773c80])
def test_kernel_and_mangled_addresses_remain_rejected(pointer_width, address):
    """Widening userspace must still refuse the kernel range and invalid high bits."""
    binary, _arm64 = pointer_width
    subprocess.run([str(binary), format(address, 'x'), '0'], check=True, timeout=10)

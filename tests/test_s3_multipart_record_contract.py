"""Multipart staging records must prove marker and sink bounds before use."""
import os
from pathlib import Path
import re
import subprocess

import pytest

from csource_scan import function_body
from lib_py.nginx_build import configured_compile_layout
from test_platform_linux_native import native_compile


@pytest.fixture(scope='module')
def multipart_record_binary(native_compile):
    """Exercise the actual record body and nginx copier under ASan/UBSan."""
    root = Path(__file__).resolve().parents[1]
    source = root / 'src/protocols/s3/multipart_complete_list_uploads.c'
    text = source.read_text()
    structures = re.findall(r'typedef struct\s*\{.*?\}\s*\w+;', text, re.S)
    assert len(structures) == 3
    layout = configured_compile_layout(root, os.environ)
    assert layout is not None
    # Compile only the actual SDK copier body. ASan retains nginx's entire
    # string TU (including unrelated allocator/sort dependencies) on FreeBSD.
    copier = (layout[1] / 'src/core/ngx_string.c').read_text()
    code = _PREAMBLE + '\nu_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n)'
    code += function_body(copier, 'ngx_cpystrn') + '\n'.join(structures[:2])
    code += ('\nstatic void mpu_record_staging(mpu_scan_t *scan, const char *dname, '
             'const char *key_prefix, time_t mtime)')
    code += function_body(text, 'mpu_record_staging') + _MAIN
    return native_compile('s3-multipart-record', code,
                          extra=['-fsanitize=address,undefined',
                                 '-fno-sanitize-recover=all', '-fno-omit-frame-pointer'])


@pytest.mark.parametrize('name,prefix,capacity,count,key,upload', [
    ('.object.mpu-id', '', 2, 0, 'object', 'id'),
    ('.object.mpu-id', 'nested/', 2, 1, 'nested/object', 'id'),
    ('.object', '', 2, 0, '', ''),
    ('..mpu-id', '', 2, 0, '', ''),
    ('.object.mpu-', '', 2, 0, '', ''),
    ('.object.mpu-' + 'a' * 128, '', 2, 0, '', ''),
    ('.object.mpu-id', 'a' * 255, 2, 0, '', ''),
    ('.object.mpu-id', '', 2, 2, '', ''),
    ('.object.mpu-id', '', 0, 0, '', ''),
])
def test_multipart_record_acceptance_and_refusal(multipart_record_binary,
                                                name, prefix, capacity, count, key, upload):
    """Valid entries append exactly once; malformed/full sinks stay unchanged."""
    result = subprocess.run([str(multipart_record_binary), name, prefix,
                             str(capacity), str(count), key, upload],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_PREAMBLE = r'''
#include <ngx_config.h>
#include <ngx_core.h>
#include "protocols/s3/s3.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
'''

_MAIN = r'''
int main(int argc, char **argv)
{
    assert(argc == 7);
    mpu_upload_entry_t entries[2];
    mpu_upload_entry_t previous[2];
    memset(entries, 0xa5, sizeof(entries));
    memcpy(previous, entries, sizeof(entries));
    mpu_scan_t scan = {0};
    scan.uploads = entries;
    scan.max = atoi(argv[3]);
    scan.n = atoi(argv[4]);
    int before = scan.n;
    int accepted = argv[5][0] != '\0';
    mpu_record_staging(&scan, argv[1], argv[2], 12345);
    assert(scan.n == before + accepted);
    for (int index = 0; index < 2; index++) {
        if (accepted && index == before) {
            assert(strcmp(entries[index].key, argv[5]) == 0);
            assert(strcmp(entries[index].upload_id, argv[6]) == 0);
            assert(entries[index].mtime == 12345);
        } else {
            assert(memcmp(&entries[index], &previous[index], sizeof(entries[index])) == 0);
        }
    }
    return 0;
}
'''

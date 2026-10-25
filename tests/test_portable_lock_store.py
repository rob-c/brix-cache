"""Real native lock-store CAS, contention and stale-owner refusal contracts."""
import concurrent.futures
import errno
import os
import subprocess
import sys

import pytest

from cmdscripts.compile_run import compile_binary, pal_xattr_sources


PROGRAM = r'''
#include "platform/platform_api.h"
#include "fs/backend/posix/lock_store.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    const char *expected = NULL, *replacement = NULL;
    int descriptor, result, saved;
    if (argc < 3) { return 2; }
    if (strcmp(argv[2], "create") == 0 && argc == 4) {
        replacement = argv[3];
    } else if (strcmp(argv[2], "replace") == 0 && argc == 5) {
        expected = argv[3]; replacement = argv[4];
    } else if (strcmp(argv[2], "remove") == 0 && argc == 4) {
        expected = argv[3];
    } else if (strcmp(argv[2], "invalid") != 0) { return 2; }
    descriptor = open(argv[1], O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
    if (descriptor < 0) { printf("-1 %d\n", errno); return 0; }
    result = brix_posix_lock_store_update_fd(descriptor,
        expected, expected ? strlen(expected) : 0,
        replacement, replacement ? strlen(replacement) : 0);
    saved = result == 0 ? 0 : errno;
    close(descriptor);
    printf("%d %d\n", result, saved);
    return 0;
}
'''


@pytest.fixture(scope='module')
def store_binary(tmp_path_factory):
    """Compile production storage code with the selected native PAL, no mocks."""
    work = tmp_path_factory.mktemp('portable-lock-store')
    source = work / 'contracts.c'
    source.write_text(PROGRAM)
    output = work / 'contracts'
    result = compile_binary(output, ['-std=c11', '-Wall', '-Wextra', '-Werror',
        '-D_GNU_SOURCE', '-DXRDPROTO_NO_NGX', '-Isrc', str(source),
        'src/fs/backend/posix/lock_store.c', *pal_xattr_sources()])
    assert result.returncode == 0, result.stdout + result.stderr
    return output


@pytest.fixture(params=['file', 'directory'])
def resource(request, tmp_path):
    """Both resource kinds persist records on the inode, never on a sidecar."""
    path = tmp_path / 'resource'
    if request.param == 'file':
        path.write_bytes(b'exported bytes')
    else:
        path.mkdir()
    return path


def _call(binary, path, *arguments):
    result = subprocess.run([str(binary), str(path), *arguments],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return tuple(map(int, result.stdout.split()))


def test_create_refresh_and_remove(store_binary, resource):
    """The native store supplies a complete persisted ownership lifecycle."""
    assert _call(store_binary, resource, 'create', 'owner:initial') == (0, 0)
    assert _call(store_binary, resource, 'replace', 'owner:initial', 'owner:renewed') == (0, 0)
    assert _call(store_binary, resource, 'remove', 'owner:renewed') == (0, 0)
    assert _call(store_binary, resource, 'create', 'successor') == (0, 0)


def test_missing_record_cannot_be_refreshed(store_binary, resource):
    """A stale owner cannot turn refresh into unconditional creation."""
    assert _call(store_binary, resource, 'replace', 'absent', 'forged') == (-1, errno.ENODATA)
    assert _call(store_binary, resource, 'create', 'real') == (0, 0)


def test_stale_reaper_cannot_remove_a_refreshed_lock(store_binary, resource):
    """Exact comparison includes expiry, not only an unchanged owner token."""
    assert _call(store_binary, resource, 'create', 'token:expires=1') == (0, 0)
    assert _call(store_binary, resource, 'replace', 'token:expires=1', 'token:expires=2') == (0, 0)
    assert _call(store_binary, resource, 'remove', 'token:expires=1') == (-1, errno.EBUSY)
    assert _call(store_binary, resource, 'remove', 'token:expires=2') == (0, 0)


def test_foreign_owner_cannot_replace_or_clear_a_record(store_binary, resource):
    """A guessed successor must not overwrite or clear the real owner."""
    assert _call(store_binary, resource, 'create', 'real-owner') == (0, 0)
    assert _call(store_binary, resource, 'replace', 'foreign', 'forged') == (-1, errno.EBUSY)
    assert _call(store_binary, resource, 'remove', 'foreign') == (-1, errno.EBUSY)
    assert _call(store_binary, resource, 'remove', 'real-owner') == (0, 0)


def test_concurrent_creators_have_exactly_one_winner(store_binary, resource):
    """Different processes, not merely threads, compete for one persisted record."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(lambda number: _call(
            store_binary, resource, 'create', 'owner-' + str(number)), range(24)))
    assert outcomes.count((0, 0)) == 1, outcomes
    assert all(result == (0, 0) or result in (
        (-1, errno.EEXIST), (-1, errno.EAGAIN), (-1, errno.EWOULDBLOCK)) for result in outcomes)


def test_kernel_contention_is_bounded_and_owner_death_releases_it(store_binary, resource):
    """Never wait for or steal a held lock; a killed holder leaves no stale mutex."""
    script = ('import fcntl,os,sys,time; f=os.open(sys.argv[1],os.O_RDONLY); '
              'fcntl.flock(f,fcntl.LOCK_EX); print("locked",flush=True); time.sleep(60)')
    owner = subprocess.Popen([sys.executable, '-c', script, str(resource)],
                             stdout=subprocess.PIPE, text=True)
    try:
        assert owner.stdout.readline().strip() == 'locked'
        assert _call(store_binary, resource, 'create', 'contender') in (
            (-1, errno.EAGAIN), (-1, errno.EWOULDBLOCK))
    finally:
        owner.kill()
        owner.wait(timeout=10)
        owner.stdout.close()
    assert _call(store_binary, resource, 'create', 'new-owner') == (0, 0)


def test_invalid_transaction_does_not_create_a_record(store_binary, resource):
    """No-expected/no-replacement is invalid, never an unconditional deletion."""
    assert _call(store_binary, resource, 'invalid') == (-1, errno.EINVAL)
    assert _call(store_binary, resource, 'create', 'still-empty') == (0, 0)


def test_special_file_and_symlink_are_refused(store_binary, tmp_path):
    """A FIFO cannot block a worker, and a symlink cannot redirect lock writes."""
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    assert _call(store_binary, fifo, 'create', 'refused') == (-1, errno.EINVAL)
    target = tmp_path / 'outside'
    target.write_bytes(b'untouched')
    link = tmp_path / 'link'
    link.symlink_to(target)
    assert _call(store_binary, link, 'create', 'refused') in (
        (-1, errno.ELOOP), (-1, errno.EMLINK))
    assert target.read_bytes() == b'untouched'

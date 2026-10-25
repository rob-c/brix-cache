"""Native account command construction for owned privileged test fixtures.

Callers retain account-name/uid ownership and cleanup policy. This module
selects real host tools; it never executes or silently emulates an operation.
"""
import shutil
import sys


def available():
    """Require the actual host's account tools, not Linux utilities on BSD."""
    if sys.platform.startswith('freebsd'):
        return shutil.which('pw') is not None
    return all(shutil.which(name) for name in ('useradd', 'userdel', 'groupadd', 'groupdel'))


def group_add(name, gid):
    """Create the explicit fixture group without allocating a different gid."""
    if sys.platform.startswith('freebsd'):
        return ['/usr/sbin/pw', 'groupadd', name, '-g', str(gid)]
    return ['groupadd', '-g', str(gid), name]


def user_add(name, uid, group, shell, *, system=False):
    """No home creation or interactive password; preserve explicit identity."""
    if sys.platform.startswith('freebsd'):
        return ['/usr/sbin/pw', 'useradd', name, '-u', str(uid),
                '-g', str(group), '-s', shell, '-d', '/nonexistent', '-h', '-']
    return ['useradd', *(['-r'] if system else []), '-M', '-u', str(uid),
            '-g', str(group), '-s', shell, name]


def user_delete(name):
    """Delete the caller-owned account; fixture accounts have no home tree."""
    if sys.platform.startswith('freebsd'):
        return ['/usr/sbin/pw', 'userdel', name]
    return ['userdel', name]


def group_delete(name):
    """Delete only the exact group selected and checked by the caller."""
    if sys.platform.startswith('freebsd'):
        return ['/usr/sbin/pw', 'groupdel', name]
    return ['groupdel', name]

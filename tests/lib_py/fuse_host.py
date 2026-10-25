"""The host's FUSE surface, as the test tier sees it.

WHAT: One answer to "can this host mount a FUSE filesystem unprivileged, and
      how does it unmount one" for every test that drives xrootdfs / brixMount.
WHY:  Two dozen test modules each probed ``/dev/fuse`` and ``fusermount3``,
      which is the Linux libfuse shape only.  macFUSE has neither: the kernel
      extension registers no device node and mounts go through
      ``mount_macfuse`` (invoked by libfuse itself), while an unprivileged
      unmount is the plain ``umount`` of the mount's owner.  Those tests
      skipped wholesale on macOS although the mounts work there.
HOW:  ``FUSE_READY`` is evaluated once at import.  ``unmount_argv`` mirrors the
      tier order the client PAL uses (``brix_plat_fuse_umount_argv`` in
      ``client/lib/platform/<host>/posix.c``), so a test tears a mount down the
      same way ``xrd unmount`` and brixautofs do.
"""
from __future__ import annotations

import os
import errno
import shutil
import stat
import subprocess
import sys

#: macFUSE's mount helper; present iff the macFUSE file system bundle is installed.
MACFUSE_MOUNT = "/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse"
#: FUSE-T (a kext-free macFUSE alternative) ships its own bundle.
FUSE_T_MOUNT = "/Library/Filesystems/fuse-t.fs/Contents/Resources/mount_fuse-t"


def regular_mknod_error(path):
    """Probe the native kernel, without disguising permission or I/O failures.

    FreeBSD rejects regular-file mknod before dispatching to a filesystem. A
    FUSE test must prove that independently, rather than assume its own failure
    is an unavailable capability. Refusal must leave the probe path absent.
    """
    try:
        os.mknod(path, stat.S_IFREG | 0o600)
    except OSError as error:
        if error.errno not in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP):
            raise
        assert not os.path.lexists(path), "refused native mknod created a node"
        return error.errno
    try:
        info = os.lstat(path)
        assert stat.S_ISREG(info.st_mode) and info.st_size == 0
    finally:
        os.unlink(path)
    return 0


def _linux_ready() -> bool:
    return os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None


def _darwin_ready() -> bool:
    if os.path.exists(FUSE_T_MOUNT):
        return True
    if not os.path.exists(MACFUSE_MOUNT) or shutil.which("kextstat") is None:
        return False
    status = subprocess.run(["kextstat"], capture_output=True, text=True)
    return status.returncode == 0 and "macfuse" in status.stdout.lower()


def _freebsd_usermount_allowed() -> bool:
    """FreeBSD uses its native mount helper and explicit unprivileged policy."""
    if os.geteuid() == 0:
        return True
    try:
        status = subprocess.run(["sysctl", "-n", "vfs.usermount"],
                                capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return status.returncode == 0 and status.stdout.strip() == "1"


def _freebsd_ready() -> bool:
    """Check real native prerequisites; a mount still has to prove success."""
    return (os.access('/dev/fuse', os.R_OK | os.W_OK)
            and shutil.which('mount_fusefs') is not None
            and _freebsd_usermount_allowed())


def fuse_ready() -> bool:
    """True when an unprivileged FUSE mount can be attempted on this host."""
    if sys.platform == "darwin":
        return _darwin_ready()
    if sys.platform.startswith("freebsd"):
        return _freebsd_ready()
    return _linux_ready()


#: Mount options a FUSE test should add on this host, on top of whatever the
#: scenario itself passes.
#:
#: macFUSE's ``daemon_timeout`` (default 60 s) is how long the kernel waits on
#: a daemon that has stopped answering — including at shutdown, so a mount
#: helper that exits on SIGTERM keeps its process alive for the full minute
#: before the session tears down (measured: 60.0 s, exactly the default).
#: Every fixture here is local and answers in milliseconds, so 5 s is ample
#: and makes teardown prompt.  The PRODUCT default is deliberately left alone:
#: a real cache miss against a distant origin can legitimately take longer
#: than 5 s, and exceeding daemon_timeout fails the operation.
HOST_MOUNT_OPTS: tuple[str, ...] = (
    ("daemon_timeout=5",) if sys.platform == "darwin" else ())


def _opt_name(option: str) -> str:
    return option.split("=", 1)[0]


def _split_opts(opts: str) -> list[str]:
    return [p for p in opts.split(",") if p]


def _host_additions(have: set[str]) -> list[str]:
    return [o for o in HOST_MOUNT_OPTS if _opt_name(o) not in have]


def with_host_mount_opts(opts: str) -> str:
    """``opts`` plus this host's additions, as one libfuse ``-o`` string.
    An option the caller already names is left exactly as the caller wrote it."""
    parts = _split_opts(opts)
    return ",".join(parts + _host_additions({_opt_name(p) for p in parts}))


#: Evaluated once; import this for ``skipif`` marks.
FUSE_READY = fuse_ready()

#: The reason string every FUSE skip carries.
SKIP_REASON = ("fuse mount prerequisites missing (active macFUSE / FUSE-T)"
               if sys.platform == "darwin"
               else "fuse mount prerequisites missing (accessible /dev/fuse, mount_fusefs, vfs.usermount=1)"
               if sys.platform.startswith("freebsd")
               else "fuse mount prerequisites missing (/dev/fuse, fusermount3)")


def host_mount_opts() -> str | None:
    """The `-o` value the client PAL adds to every mount on this host
    (``brix_plat_fuse_host_opts``): macFUSE needs ``noappledouble`` or its
    ``._name`` sidecars turn every write into ENXIO; Linux needs nothing."""
    return "noappledouble" if sys.platform == "darwin" else None


def freebsd_mount_options(path):
    """Inspect our mounted test filesystem, never assume Linux procfs exists.

    FreeBSD has no nodev flag: mknod(8) documents that nodes outside devfs
    cannot access devices. Do not fabricate that flag in the kernel evidence.
    """
    if not os.path.ismount(path):
        return None
    flags = os.statvfs(path).f_flag
    options = ['ro' if flags & os.ST_RDONLY else 'rw']
    if flags & os.ST_NOSUID:
        options.append('nosuid')
    return ','.join(options)


def mount_device_access_disabled(options):
    """Compare the device-access policy, not a non-existent FreeBSD flag."""
    if options is None:
        return False
    return sys.platform.startswith('freebsd') or 'nodev' in options.split(',')


def freebsd_fuse_mounts_under(prefix):
    """Use FreeBSD's cached native table, never Darwin's struct statfs ABI."""
    import psutil

    root = os.path.abspath(prefix).rstrip('/')
    return [entry.mountpoint for entry in psutil.disk_partitions(all=True)
            if 'fuse' in entry.fstype.lower() and
            (entry.mountpoint == root or entry.mountpoint.startswith(root + '/'))]


def unmount_tiers(lazy: bool = False) -> list[list[str]]:
    """Every unmount command this host tries, most specific first, without the
    mount point.  Linux: fusermount3, fusermount, umount.  Darwin: umount only
    (``-f`` is the closest thing to a lazy detach there)."""
    if sys.platform == "darwin" or sys.platform.startswith("freebsd"):
        return [["umount", "-f"] if lazy else ["umount"]]
    return [["fusermount3", "-u"] + (["-z"] if lazy else []),
            ["fusermount", "-u"] + (["-z"] if lazy else []),
            ["umount"] + (["-l"] if lazy else [])]


def unmount_argv(mountpoint: str, lazy: bool = False) -> list[str]:
    """The first unmount command whose tool exists on PATH, plus the mount
    point.  Falls back to the last tier when nothing resolves so the caller's
    error names a real tool rather than an empty argv."""
    tiers = unmount_tiers(lazy)
    for tier in tiers:
        if shutil.which(tier[0]) is not None:
            return tier + [mountpoint]
    return tiers[-1] + [mountpoint]


def unmount(mountpoint: str, lazy: bool = False,
            timeout: float = 30) -> subprocess.CompletedProcess:
    """Best-effort unmount through the host's tool; never raises on a
    non-zero exit (a mount that is already gone is not an error here)."""
    return subprocess.run(unmount_argv(mountpoint, lazy), capture_output=True,
                          text=True, timeout=timeout)

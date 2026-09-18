"""``lib_py.fuse_host.with_host_mount_opts``: the per-host additions a FUSE
test's ``-o`` string needs.

On macOS that is ``daemon_timeout``: macFUSE's default is 60 s and it governs
shutdown too, so a mount helper that exits on SIGTERM lingers for the full
minute (measured exactly 60.0 s) before its session tears down.
"""
import sys
from unittest import mock

from lib_py import fuse_host
from lib_py.fuse_host import with_host_mount_opts


def test_the_host_additions_are_appended():
    """success: the scenario's own options are kept, the host's are added."""
    with mock.patch.object(fuse_host, "HOST_MOUNT_OPTS", ("daemon_timeout=5",)):
        assert with_host_mount_opts("idle=0,timeout=30") == \
            "idle=0,timeout=30,daemon_timeout=5"


def test_an_explicit_value_is_never_overridden():
    """error path: a scenario that pins the option keeps its own value — the
    helper adds, it does not rewrite."""
    with mock.patch.object(fuse_host, "HOST_MOUNT_OPTS", ("daemon_timeout=5",)):
        assert with_host_mount_opts("daemon_timeout=99") == "daemon_timeout=99"


def test_no_additions_means_the_string_is_untouched():
    """security-negative: on a host with nothing to add (Linux) the option
    string is byte-identical — no empty element, no stray comma that libfuse
    would reject and no silently injected mount behaviour."""
    with mock.patch.object(fuse_host, "HOST_MOUNT_OPTS", ()):
        assert with_host_mount_opts("ro,allow_other") == "ro,allow_other"
        assert with_host_mount_opts("") == ""


def test_this_host_matches_its_platform():
    """the live value, so a future edit cannot quietly arm macFUSE options on
    Linux (where daemon_timeout is not a libfuse option at all)."""
    if sys.platform == "darwin":
        assert "daemon_timeout=5" in fuse_host.HOST_MOUNT_OPTS
    else:
        assert fuse_host.HOST_MOUNT_OPTS == ()

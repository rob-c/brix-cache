"""Opt-in FUSE lifecycle expressed entirely as managed resources."""

import os
import time

import pytest

from brixtest import Lifecycle, Placement, binary, case, mount, probe, server, volume

pytestmark = pytest.mark.skipif(
    not (os.environ.get("BRIXTEST_FUSE_DRIVER") and os.environ.get("BRIXTEST_FUSE_IMAGE")),
    reason="set BRIXTEST_FUSE_DRIVER and digest-pinned BRIXTEST_FUSE_IMAGE",
)

DRIVER = binary("fuse_driver", path=os.environ.get("BRIXTEST_FUSE_DRIVER", "/bin/false"))
DEVICE = volume("fuse_device", kind="device", source="/dev/fuse")
MOUNTPOINT = volume("mountpoint", kind="shared")
FILESYSTEM = server(
    "fuse_filesystem",
    command=(DRIVER, "--foreground", "{mount_mount}"),
    mounts=(
        mount(DEVICE, "dev_fuse", read_only=False),
        mount(MOUNTPOINT, "mount", read_only=False, propagation="bidirectional"),
    ),
    placement=Placement(backend="docker", image=os.environ.get("BRIXTEST_FUSE_IMAGE")),
    lifecycle=Lifecycle(
        shutdown_command=("fusermount3", "-u", "{mount_mount}"),
        stop_timeout=10,
    ),
    probe=probe("none"),
)


@case(DEVICE, MOUNTPOINT, FILESYSTEM, DRIVER, timeout=60, keep="never")
def test_fuse_mount_is_supervised_and_always_unmounted(run):
    mounted = run.server(FILESYSTEM)
    mountpoint = run.volume(MOUNTPOINT)
    deadline = time.monotonic() + 10
    while not os.path.ismount(mountpoint):
        assert time.monotonic() < deadline
        time.sleep(0.05)
    mounted.fs.write_text(mountpoint / "roundtrip.txt", "fuse data")
    assert mounted.fs.read_text(mountpoint / "roundtrip.txt") == "fuse data"
    assert mounted.fs.stat(mountpoint)["is_dir"] is True

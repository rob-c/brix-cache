"""Run real FreeBSD namespace, identity, descriptor and metadata primitives."""
import subprocess
import sys
import os
import stat
import errno

import pytest

from cmdscripts.compile_run import compile_binary, platform_host_name


pytestmark = pytest.mark.skipif(not sys.platform.startswith("freebsd"),
                                reason="native FreeBSD PAL contracts")


@pytest.fixture(scope="module")
def freebsd_contract_binary(tmp_path_factory):
    """Link production adapters and inject only native attribute-list races."""
    output = tmp_path_factory.mktemp("freebsd-pal") / "contracts"
    sources = ["tests/c/freebsd_pal_contracts.c", *(
        f"src/platform/freebsd/{name}_wrapper.c"
        for name in ("path", "process", "storage", "priv", "xattr"))]
    result = compile_binary(output, ["-std=gnu11", "-Wall", "-Wextra", "-Werror",
        "-Isrc", *sources, "-lcrypt", "-Wl,--wrap=extattr_list_file"])
    assert result.returncode == 0, result.stdout + result.stderr
    return output


@pytest.mark.parametrize("case", ["xattrs", "descriptors", "paths", "no-new-privileges",
    "events-peer", "list-empty-growth", "list-oversize", "list-malformed"])
def test_native_freebsd_contracts(freebsd_contract_binary, tmp_path, case):
    """Positive, error and hostile-input verdicts execute on the native kernel."""
    result = subprocess.run([str(freebsd_contract_binary), case, str(tmp_path)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("spelling", ["freebsd", "freebsd14", "freebsd15"])
def test_freebsd_selector_never_falls_back_to_linux(spelling):
    """The test compiler must select the same explicit PAL as the native build."""
    assert platform_host_name(spelling) == "freebsd"


@pytest.fixture
def native_root_endpoint(lifecycle, tmp_path):
    """Exercise actual server wire decoding independently of reference bindings."""
    from ephemeral_port import free_port
    from server_registry import NginxInstanceSpec
    from settings import BIND_HOST
    from _test_audit15g_helpers import seed_tree

    payload = bytes(range(256)) * 16
    root = tmp_path / "export"
    seed_tree(root, {"range.bin": payload})
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-freebsd-native-wire", template="nginx_min_sec.conf",
        port=free_port(BIND_HOST), protocol="root", data_root=str(root),
        readiness="root", template_values={"TLS_LINES": "", "AUTH": "none",
                                           "MIN_SEC": "none"},
        reason="native offset decoding and fail-closed range validation"))
    return endpoint.port, payload


@pytest.mark.uses_lifecycle_harness
def test_native_server_nonzero_range_is_byte_exact(native_root_endpoint):
    from _test_audit15g_helpers import ReadHandle

    port, payload = native_root_endpoint
    with ReadHandle(port, "/range.bin") as handle:
        assert handle.read(1000, 250) == payload[1000:1250]
        assert handle.read(4090, 100) == payload[4090:]


@pytest.mark.uses_lifecycle_harness
def test_native_server_missing_range_object_is_an_error(native_root_endpoint):
    from _test_audit15g_helpers import ReadError, ReadHandle

    port, _payload = native_root_endpoint
    with pytest.raises(ReadError) as failure:
        ReadHandle(port, "/absent.bin")
    assert failure.value.errcode == 3011


@pytest.mark.uses_lifecycle_harness
def test_native_server_rejects_negative_and_overflow_offsets(native_root_endpoint):
    from _test_audit15g_helpers import ReadHandle

    port, payload = native_root_endpoint
    with ReadHandle(port, "/range.bin") as handle:
        for offset in (-1, (1 << 63) - 1):
            data, code = handle.try_read(offset, 16)
            assert code == 3000 and data == b""
        assert handle.read(1000, 250) == payload[1000:1250]


@pytest.mark.skipif(os.geteuid() != 0, reason='root-only native non-devfs device policy proof')
def test_native_non_devfs_device_nodes_cannot_access_devices(tmp_path):
    """The kernel's documented nodev-equivalent boundary, not a mount flag."""
    device = tmp_path / 'zero-device'
    os.mknod(device, stat.S_IFCHR | 0o600, os.stat('/dev/zero').st_rdev)
    assert stat.S_ISCHR(device.lstat().st_mode)
    try:
        descriptor = os.open(device, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, 'rb', buffering=0) as stream:
            # ZFS can open the inert inode as an empty file. A functional
            # /dev/zero alias would instead return a NUL byte immediately.
            assert stream.read(1) == b''
    except OSError as refused:
        assert refused.errno in (errno.ENXIO, errno.ENODEV, errno.EOPNOTSUPP)

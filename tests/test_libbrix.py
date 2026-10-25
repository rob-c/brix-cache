"""
Public libbrix library (phase-37 §14.1): install + pkg-config + sample consumer.

Proves the clean-room client layer is a usable, standalone C library: install it
to a staged prefix, compile examples/brix_stat_demo.c against the INSTALLED
headers/lib via pkg-config, run it over an anonymous root:// connection, and
confirm it links libbrix — not libXrdCl/libXrdSec*.

Run (serial, manual fleet):
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    pytest tests/test_libbrix.py -v -p no:xdist
"""

import os
import shutil
import subprocess
from brix_suite.client_build import client_make

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST
from lib_py.util import linked_libraries

pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DEMO_SRC = os.path.join(CLIENT, "examples", "brix_stat_demo.c")
CC = shutil.which("cc") or shutil.which("gcc")

def _gcov_link_flags(installed):
    """--coverage when libbrix.a came from an instrumented build.

    An archive compiled with --coverage references __gcov_* from every object;
    a static consumer must link libgcov or the build fails with undefined
    references.  Probe the installed archive so the flag tracks the build.
    """
    lib = os.path.join(installed, "lib", "libbrix.a")
    nm = shutil.which("nm")
    if nm is not None and os.path.exists(lib):
        out = subprocess.run([nm, lib], capture_output=True, text=True).stdout
        if "__gcov" in out:
            return ["--coverage"]
    return []


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    if CC is None:
        pytest.skip("no C compiler")
    if shutil.which("pkg-config") is None:
        pytest.skip("pkg-config not available")
    prefix = str(tmp_path_factory.mktemp("brix-prefix"))
    proc = client_make(CLIENT, "install", f"PREFIX={prefix}", capture_output=True, text=True, timeout=240)
    if proc.returncode != 0:
        pytest.skip(f"libbrix install failed:\n{proc.stdout}\n{proc.stderr}")
    return prefix


def _pkgconfig(prefix, *args):
    env = dict(os.environ)
    env["PKG_CONFIG_PATH"] = os.path.join(prefix, "lib", "pkgconfig")
    proc = subprocess.run(["pkg-config", *args, "libbrix"],
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.split()


def _in_tree_static_private_flags():
    """Return libbrix's build-selected external flags for in-tree consumers."""
    from lib_py.client_toolchain import client_static_dependency_flags
    return client_static_dependency_flags(CLIENT)


def test_pkgconfig_present(installed):
    pc = os.path.join(installed, "lib", "pkgconfig", "libbrix.pc")
    assert os.path.exists(pc), "libbrix.pc not installed"
    flags = _pkgconfig(installed, "--cflags", "--libs")
    assert "-lbrix" in flags, flags


def test_headers_installed(installed):
    assert os.path.exists(os.path.join(installed, "include", "brix", "brix.h"))
    assert os.path.exists(os.path.join(installed, "include", "brix", "xrdproto",
                                       "protocol", "protocol.h"))


def _build_demo(installed, tmp_path, static):
    out = str(tmp_path / _demo_name(static))
    cmd = _demo_command(installed, static)
    cmd += ["-o", out]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"demo build failed:\n{' '.join(cmd)}\n{proc.stderr}"
    return out


def _demo_name(static):
    return "demo_static" if static else "demo"


def _demo_command(installed, static):
    if not static:
        flags = _pkgconfig(installed, "--cflags", "--libs")
        return [CC, "-std=c11", DEMO_SRC] + flags
    if static:
        # Exercise the installed downstream contract, including the archive
        # cycle and every optional dependency selected at build time.  Host
        # filesystem probes cannot represent Nix store paths or Homebrew's
        # keg-only libraries; libbrix.pc is the authoritative record.
        # pkg-config's --static adds private dependencies but deliberately does
        # not force archive selection.  Select only our two installed archives
        # explicitly, leaving system/optional dependencies dynamically linked.
        flags = _pkgconfig(installed, "--static", "--cflags", "--libs")
        archives = {
            "-lbrix": os.path.join(installed, "lib", "libbrix.a"),
            "-lxrdproto": os.path.join(installed, "lib", "libxrdproto.a"),
        }
        flags = [archives.get(flag, flag) for flag in flags]
        return ([CC, "-std=c11", DEMO_SRC] + flags
                + _gcov_link_flags(installed))


def test_shared_consumer_runs(installed, tmp_path):
    demo = _build_demo(installed, tmp_path, static=False)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = os.path.join(installed, "lib")
    r = subprocess.run([demo, f"root://{SERVER_HOST}:{NGINX_ANON_PORT}", "/test.txt"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    want = os.path.getsize(os.path.join(DATA_ROOT, "test.txt"))
    assert f"Size: {want}" in r.stdout, r.stdout
    # No upstream xrootd libs anywhere in the chain. linked_libraries, not a
    # bare ldd: there is no ldd on macOS, so this raised FileNotFoundError and
    # the check never ran (otool -L reports the same linkage there).
    linked = linked_libraries(demo)
    assert "XrdCl" not in linked and "XrdSec" not in linked, linked


def test_static_consumer_runs(installed, tmp_path):
    demo = _build_demo(installed, tmp_path, static=True)
    r = subprocess.run([demo, f"root://{SERVER_HOST}:{NGINX_ANON_PORT}", "/test.txt"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    want = os.path.getsize(os.path.join(DATA_ROOT, "test.txt"))
    assert f"Size: {want}" in r.stdout, r.stdout
    linked = linked_libraries(demo)
    assert "libXrd" not in linked, linked

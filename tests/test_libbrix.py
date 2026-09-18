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

import glob
import os
import shutil
import subprocess
import sys
from brix_suite.client_build import client_make

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST
from lib_py.util import linked_libraries

pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DEMO_SRC = os.path.join(CLIENT, "examples", "brix_stat_demo.c")
CC = shutil.which("cc") or shutil.which("gcc")

# Where a host keeps the shared runtimes libbrix.a may reference, and what a
# shared library is called there. A static consumer has to link whatever the
# archive was COMPILED against, so these probes decide the link line; probing
# only Linux names found nothing on macOS and the demo then failed to link with
# undefined codec symbols, even though the archive had been built with them.
_LINUX_LIBDIRS = ("/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib", "/lib64")
_LIBDIRS = _LINUX_LIBDIRS                    # kept: the Linux-only probes below
_DARWIN_LIBDIRS = ("/usr/local/lib", "/opt/homebrew/lib")
#: Homebrew keeps "keg-only" formulas (krb5, xz) out of the link path entirely,
#: so those need their own -L.
_DARWIN_KEGS = ("/usr/local/opt", "/opt/homebrew/opt")


def _sdk_lib_dir():
    """The active SDK's lib directory, which carries .tbd stubs for the
    libraries macOS ships itself (bz2, z), or None."""
    try:
        sdk = subprocess.run(["xcrun", "--show-sdk-path"], capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    path = sdk.stdout.strip()
    return os.path.join(path, "usr", "lib") if path else None


def _in_link_path(stem):
    """Whether lib<stem> sits in a directory the linker already searches."""
    return any(glob.glob(os.path.join(directory, f"lib{stem}*.dylib"))
               for directory in _DARWIN_LIBDIRS)


def _keg_lib_dir(stem, keg):
    """The keg directory holding lib<stem>, or None. Homebrew keeps keg-only
    formulas (krb5, xz) out of the link path, so linking them needs a -L."""
    for prefix in _DARWIN_KEGS:
        directory = os.path.join(prefix, keg or stem, "lib")
        if glob.glob(os.path.join(directory, f"lib{stem}*.dylib")):
            return directory
    return None


def _in_sdk(stem):
    """Whether the active SDK carries a stub for lib<stem> (bz2, z and the
    other libraries macOS ships itself)."""
    sdk = _sdk_lib_dir()
    return bool(sdk) and os.path.exists(os.path.join(sdk, f"lib{stem}.tbd"))


def _darwin_library_flags(stem, flag, keg):
    """Link flags for lib<stem> on macOS, or [] when the host has no copy."""
    if _in_link_path(stem):
        return [flag]
    keg_dir = _keg_lib_dir(stem, keg)
    if keg_dir is not None:
        return [f"-L{keg_dir}", flag]
    return [flag] if _in_sdk(stem) else []


def _library_flags(stem, flag=None, keg=None, linux_flag=None):
    """Link flags for lib<stem> if this host has it, else [].

    ``linux_flag`` exists for the one library the Linux line pins by soname
    (``-l:liblz4.so.1``): that is GNU ld syntax which Apple's linker rejects,
    so each platform gets the spelling its linker understands.
    """
    flag = flag or f"-l{stem}"
    if sys.platform == "darwin":
        return _darwin_library_flags(stem, flag, keg)
    for directory in _LINUX_LIBDIRS:
        if glob.glob(os.path.join(directory, f"lib{stem}.so*")):
            return [linux_flag or flag]
    return []


def _codec_link_libs():
    """Link flags for whichever compression codecs are present on this host.

    libxrdproto.a is compiled with all available codecs, so a *static* consumer
    must also link their runtime libraries (ZSTD_isError, LZ4F_isError, …).
    Probe for each lib and emit its flag only when found, so the list matches
    exactly what libxrdproto was built against on this machine.
    """
    libs = []
    for stem, keg, linux_flag in (
        ("zstd",       None,  None),
        ("lz4",        None,  "-l:liblz4.so.1"),
        ("lzma",       "xz",  None),
        ("brotlienc",  "brotli", None),
        ("brotlidec",  "brotli", None),
        ("bz2",        None,  None),
    ):
        libs += _library_flags(stem, keg=keg, linux_flag=linux_flag)
    return libs


def _krb5_link_libs():
    """Link flags for Kerberos, when libbrix was compiled with krb5 support.

    The client's krb5 security module (sec_krb5.o) is compiled into libbrix.a
    only when the krb5 dev headers are present at build time; that object then
    references krb5_init_context / krb5_cc_default / … which live in libkrb5.
    A static consumer must link it or the build fails with undefined references.
    Probe by file presence so the flag appears exactly when the symbols do.
    """
    return _library_flags("krb5", keg="krb5")


def _uring_link_libs():
    """Link flag for liburing, when libbrix was compiled with io_uring support.

    The client's disk/io_uring fast path (uring.o) is compiled into libbrix.a
    only when liburing dev headers are present at build time; it then references
    io_uring_queue_init / io_uring_submit / … from liburing.  A static consumer
    must link it.  Probe by file presence so the flag tracks the build exactly.
    """
    for d in _LIBDIRS:
        if any(os.path.exists(os.path.join(d, n))
               for n in ("liburing.so", "liburing.so.2", "liburing.so.1")):
            return ["-luring"]
    return []


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
    return subprocess.run(["pkg-config", *args, "libbrix"],
                          capture_output=True, text=True, env=env).stdout.split()


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
        # Force the archive form + its deps.  libxrdproto.a is built with the
        # compression codecs (zstd/lz4/lzma/brotli/bz2), so its codec objects
        # reference ZSTD_isError / LZ4F_isError / … — a static consumer must link
        # those libraries too or the link fails with undefined references.  Only
        # append codecs whose runtime lib is actually present (matches however
        # libxrdproto was built; harmless to over-link, fatal to under-link).
        return ([CC, "-std=c11", DEMO_SRC,
                 "-I" + os.path.join(installed, "include", "brix"),
                 "-I" + os.path.join(installed, "include", "brix", "xrdproto"),
                 os.path.join(installed, "lib", "libbrix.a"),
                 os.path.join(installed, "lib", "libxrdproto.a"),
                 "-lssl", "-lcrypto", "-lz"]
                + _codec_link_libs() + _krb5_link_libs() + _uring_link_libs()
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

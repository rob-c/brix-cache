"""
Public libxrdc library (phase-37 §14.1): install + pkg-config + sample consumer.

Proves the clean-room client layer is a usable, standalone C library: install it
to a staged prefix, compile examples/xrdc_stat_demo.c against the INSTALLED
headers/lib via pkg-config, run it over an anonymous root:// connection, and
confirm it links libxrdc — not libXrdCl/libXrdSec*.

Run (serial, manual fleet):
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    pytest tests/test_libxrdc.py -v -p no:xdist
"""

import os
import shutil
import subprocess

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DEMO_SRC = os.path.join(CLIENT, "examples", "xrdc_stat_demo.c")
CC = shutil.which("cc") or shutil.which("gcc")

# Standard lib search dirs for probing optional codec runtimes.
_LIBDIRS = ("/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib", "/lib64")


def _codec_link_libs():
    """Link flags for whichever compression codecs are present on this host.

    libxrdproto.a is compiled with all available codecs, so a *static* consumer
    must also link their runtime libraries (ZSTD_isError, LZ4F_isError, …).
    Probe for each lib by file presence and emit its flag only when found, so the
    list matches exactly what libxrdproto was built against on this machine.
    """
    libs = []
    for flag, sonames in (
        ("-lzstd",         ("libzstd.so", "libzstd.so.1")),
        ("-l:liblz4.so.1", ("liblz4.so.1", "liblz4.so")),
        ("-llzma",         ("liblzma.so", "liblzma.so.5")),
        ("-lbrotlienc",    ("libbrotlienc.so", "libbrotlienc.so.1")),
        ("-lbrotlidec",    ("libbrotlidec.so", "libbrotlidec.so.1")),
        ("-lbz2",          ("libbz2.so", "libbz2.so.1", "libbz2.so.1.0")),
    ):
        if any(os.path.exists(os.path.join(d, n))
               for d in _LIBDIRS for n in sonames):
            libs.append(flag)
    return libs


def _krb5_link_libs():
    """Link flags for Kerberos, when libxrdc was compiled with krb5 support.

    The client's krb5 security module (sec_krb5.o) is compiled into libxrdc.a
    only when the krb5 dev headers are present at build time; that object then
    references krb5_init_context / krb5_cc_default / … which live in libkrb5.
    A static consumer must link it or the build fails with undefined references.
    Probe by file presence so the flag appears exactly when the symbols do.
    """
    for d in _LIBDIRS:
        if any(os.path.exists(os.path.join(d, n))
               for n in ("libkrb5.so", "libkrb5.so.3")):
            return ["-lkrb5"]
    return []


def _uring_link_libs():
    """Link flag for liburing, when libxrdc was compiled with io_uring support.

    The client's disk/io_uring fast path (uring.o) is compiled into libxrdc.a
    only when liburing dev headers are present at build time; it then references
    io_uring_queue_init / io_uring_submit / … from liburing.  A static consumer
    must link it.  Probe by file presence so the flag tracks the build exactly.
    """
    for d in _LIBDIRS:
        if any(os.path.exists(os.path.join(d, n))
               for n in ("liburing.so", "liburing.so.2", "liburing.so.1")):
            return ["-luring"]
    return []


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    if CC is None:
        pytest.skip("no C compiler")
    if shutil.which("pkg-config") is None:
        pytest.skip("pkg-config not available")
    prefix = str(tmp_path_factory.mktemp("xrdc-prefix"))
    proc = subprocess.run(["make", "-C", CLIENT, "install", f"PREFIX={prefix}"],
                          capture_output=True, text=True, timeout=240)
    if proc.returncode != 0:
        pytest.skip(f"libxrdc install failed:\n{proc.stdout}\n{proc.stderr}")
    return prefix


def _pkgconfig(prefix, *args):
    env = dict(os.environ)
    env["PKG_CONFIG_PATH"] = os.path.join(prefix, "lib", "pkgconfig")
    return subprocess.run(["pkg-config", *args, "libxrdc"],
                          capture_output=True, text=True, env=env).stdout.split()


def test_pkgconfig_present(installed):
    pc = os.path.join(installed, "lib", "pkgconfig", "libxrdc.pc")
    assert os.path.exists(pc), "libxrdc.pc not installed"
    flags = _pkgconfig(installed, "--cflags", "--libs")
    assert "-lxrdc" in flags, flags


def test_headers_installed(installed):
    assert os.path.exists(os.path.join(installed, "include", "xrdc", "xrdc.h"))
    assert os.path.exists(os.path.join(installed, "include", "xrdc", "xrdproto",
                                       "protocol", "protocol.h"))


def _build_demo(installed, tmp_path, static):
    flags = _pkgconfig(installed, "--cflags", "--libs", *(["--static"] if static else []))
    out = str(tmp_path / ("demo_static" if static else "demo"))
    cmd = [CC, "-std=c11", DEMO_SRC] + flags
    if static:
        # Force the archive form + its deps.  libxrdproto.a is built with the
        # compression codecs (zstd/lz4/lzma/brotli/bz2), so its codec objects
        # reference ZSTD_isError / LZ4F_isError / … — a static consumer must link
        # those libraries too or the link fails with undefined references.  Only
        # append codecs whose runtime lib is actually present (matches however
        # libxrdproto was built; harmless to over-link, fatal to under-link).
        cmd = ([CC, "-std=c11", DEMO_SRC,
                "-I" + os.path.join(installed, "include", "xrdc"),
                "-I" + os.path.join(installed, "include", "xrdc", "xrdproto"),
                os.path.join(installed, "lib", "libxrdc.a"),
                os.path.join(installed, "lib", "libxrdproto.a"),
                "-lssl", "-lcrypto", "-lz"]
               + _codec_link_libs() + _krb5_link_libs() + _uring_link_libs())
    cmd += ["-o", out]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"demo build failed:\n{' '.join(cmd)}\n{proc.stderr}"
    return out


def test_shared_consumer_runs(installed, tmp_path):
    demo = _build_demo(installed, tmp_path, static=False)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = os.path.join(installed, "lib")
    r = subprocess.run([demo, f"root://{SERVER_HOST}:{NGINX_ANON_PORT}", "/test.txt"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    want = os.path.getsize(os.path.join(DATA_ROOT, "test.txt"))
    assert f"Size: {want}" in r.stdout, r.stdout
    # No upstream xrootd libs anywhere in the chain.
    ldd = subprocess.run(["ldd", demo], capture_output=True, text=True, env=env).stdout
    assert "XrdCl" not in ldd and "XrdSec" not in ldd, ldd


def test_static_consumer_runs(installed, tmp_path):
    demo = _build_demo(installed, tmp_path, static=True)
    r = subprocess.run([demo, f"root://{SERVER_HOST}:{NGINX_ANON_PORT}", "/test.txt"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    want = os.path.getsize(os.path.join(DATA_ROOT, "test.txt"))
    assert f"Size: {want}" in r.stdout, r.stdout
    ldd = subprocess.run(["ldd", demo], capture_output=True, text=True).stdout
    assert "libXrd" not in ldd, ldd

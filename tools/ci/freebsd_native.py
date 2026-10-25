#!/usr/bin/env python3
"""Build the real FreeBSD server and clients, then run native validation.

Use a disposable FreeBSD 15+ VM. Run tests under a dedicated non-wheel account;
root is reserved for explicit privilege tests, not an identity bypass.
The nginx source SDK is caller-supplied and must match the deployment nginx.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.logging_support import diagnostic  # noqa: E402


def build_commands(source, build, jobs):
    """Delegate source ownership and dependency selection to CMake/Makefiles."""
    return [["cmake", "-S", str(ROOT), "-B", str(build),
        "-DNGINX_SRC_DIR=" + str(source), "-DBRIX_BUILD_NGINX=ON",
        "-DBRIX_BUILD_CLIENT=ON", "-DBRIX_BUILD_JOBS=" + str(jobs)],
        ["cmake", "--build", str(build), "--parallel", str(jobs)]]


def native_environment(environment=None):
    """Keep native FreeBSD tools ahead of separately installed GNU binutils.

    LLVM-built kernel/module and sanitizer fixtures must not silently pick a
    different ld/objcopy just because /usr/local/bin precedes /usr/bin.
    Explicit compiler and dependency-SDK choices remain authoritative.
    """
    env = dict(os.environ if environment is None else environment)
    directories = [str(Path(sys.executable).parent), '/usr/bin', '/bin',
                   '/usr/sbin', '/sbin', *env.get('PATH', '').split(os.pathsep)]
    env['PATH'] = os.pathsep.join(dict.fromkeys(path for path in directories if path))
    for variable, executable in (('CC', '/usr/bin/cc'), ('CXX', '/usr/bin/c++'),
                                 ('LD', '/usr/bin/ld')):
        env.setdefault(variable, executable)
    return env


def validation_environment(build, test_root):
    """Pin every native test binary and SDK path; never select another build."""
    modules = build / "modules"
    env = {**native_environment(), "TEST_ROOT": str(test_root),
        "PYTHONPYCACHEPREFIX": str(test_root / "pycache"),
        "TEST_REGISTRY_ROOT": str(test_root / "registry"),
        "PYTHONPATH": os.pathsep.join((str(ROOT / "tests"), str(ROOT / "brixtest/src"))),
        "TEST_NGINX_BIN": str(modules / "nginx"),
        "NGINX_BIN": str(modules / "nginx"),
        "NGX_SRC": str(build / "nginx-src"),
        "NGX_BUILD": str(build / "nginx-src"),
        "NGX_MAKEFILE": str(modules / "Makefile"),
        "TEST_NGINX_SRC": str(build / "nginx-src"),
        "TEST_NGINX_BUILD_DIR": str(modules),
        "TEST_NGINX_OBJS": str(modules), "BRIX_NGINX_BUILD_DIR": str(build),
        "BRIX_DYN_NGINX_BIN": str(modules / "nginx"),
        "BRIX_DYN_STREAM_SO": str(modules / "ngx_stream_brix_module.so"),
        "BRIX_DYN_FILTER_SO": str(modules / "ngx_http_brix_xrdhttp_filter_module.so"),
        "BRIX_DYN_NGX_STREAM_MODULE": str(modules / "ngx_stream_module.so"),
        "TEST_XRDCP_BIN": str(ROOT / "client/bin/xrdcp"),
        "TEST_XRDFS_BIN": str(ROOT / "client/bin/xrdfs"),
        "XRDCP_BIN": str(ROOT / "client/bin/xrdcp"),
        "XRDFS_BIN": str(ROOT / "client/bin/xrdfs"),
        "TEST_NGINX_LOAD_MODULES": os.pathsep.join(str(modules / name) for name in (
            "ngx_stream_module.so", "ngx_stream_brix_module.so",
            "ngx_http_brix_xrdhttp_filter_module.so")),
        "TEST_BRIX_BIN": "/usr/local/bin/xrootd", "XROOTD_BIN": "/usr/local/bin/xrootd",
        "TEST_REF_XRDCP_BIN": "/usr/local/bin/xrdcp"}
    env.pop("TEST_SKIP_SERVER_SETUP", None)
    return env


def validation_commands(build, level):
    """Always load/serve with the built module before reporting native tests."""
    commands = [[sys.executable, str(ROOT / "tools/ci/smoke.py")]]
    if level == "privileged":
        return commands + _privileged_commands(build)
    if level == "full":
        commands.append([sys.executable, str(ROOT / "tools/ci/native_suite.py"),
                         "--output", str(build / "test-results"), "--workers", "2",
                         "--include-suite-jobs"])
    else:
        commands.append([sys.executable, "-m", "pytest", "-q", "-o",
            "cache_dir=" + str(build / "pytest-cache"),
            "--junitxml=" + str(build / "native-contracts.xml"),
            "tests/test_freebsd_native.py", "tests/test_openssl_key_compat.py",
            "tests/test_pal_unlinkat_unit.py", "tests/test_pal_process_identity_unit.py",
            "tests/test_gsi_proxy_crypto.py"])
    return commands


def _privileged_commands(build):
    """Use a separate root-only identity lane, never run the whole suite as root."""
    prepare = ('from brix_suite.security.pki import blitz_test_pki; blitz_test_pki(); '
        'from brix_suite.security.tokens.manifest import fleet_artifacts; '
        'from settings import TOKENS_DIR; fleet_artifacts(TOKENS_DIR)')
    selected = sorted(str(path) for path in (ROOT / 'tests').glob('test_mu_*.py'))
    if not selected:
        raise ValueError('native privileged authorization catalogue is absent')
    selected.extend(str(ROOT / 'tests' / path) for path in (
        'test_impersonation_gridmap_root.py', 'test_pblock_group_multiuser.py',
        'test_pblock_privilege_drop.py', 'test_worker_deescalation_root.py',
        'test_chkpoint_recover_export.py', 'mu_authz_lib/test_accounts_selftest.py'))
    selected.append(str(ROOT / 'tests/test_freebsd_native.py') +
                    '::test_native_non_devfs_device_nodes_cannot_access_devices')
    return [[sys.executable, '-c', prepare],
        [sys.executable, '-m', 'pytest', '-q', '-p', 'no:rerunfailures',
         '-p', 'tools.ci.native_suite', '-o', 'cache_dir=' + str(build / 'privileged-cache'),
         '--junitxml=' + str(build / 'native-privileged.xml'), *selected]]


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx-source", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--test-level", choices=("contracts", "full", "privileged"),
                        default="contracts")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args(argv)
    if platform.system() != "FreeBSD" or int(platform.release().split(".")[0]) < 15:
        parser.error("requires a native FreeBSD 15+ kernel, not a Linux container")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    _validate_privileged_arguments(parser, args)
    source, build = args.nginx_source.resolve(), args.build_dir.resolve()
    if not (source / "src/core/nginx.h").is_file():
        parser.error("--nginx-source must contain the matching unpacked nginx SDK")
    return args, source, build


def _validate_privileged_arguments(parser, args):
    """Require explicit root-only validation without creating root build outputs."""
    if args.test_level != 'privileged':
        return
    if os.geteuid() != 0 or not args.no_build:
        parser.error('privileged validation requires root and --no-build; build as the test user first')


def _build_target(args, source, build):
    if args.no_build:
        return
    for command in build_commands(source, build, args.jobs):
        subprocess.run(command, env=native_environment(), check=True)


def _child_environment(env, command):
    child = dict(env)
    if "pytest" in command:
        child["TEST_SKIP_SERVER_SETUP"] = "1"
    return child


def _validate_target(build, level):
    # Reference daemons put AF_UNIX admin sockets below this root. A long
    # build-directory prefix exceeds FreeBSD's sockaddr_un.sun_path limit.
    test_root = Path(tempfile.mkdtemp(prefix="bf-", dir="/tmp"))
    diagnostic("INFO", __file__, "native_test_root", str(test_root))
    env = validation_environment(build, test_root)
    for command in validation_commands(build, level):
        subprocess.run(command, env=_child_environment(env, command), check=True)


def main(argv=None):
    args, source, build = _arguments(argv)
    os.chdir(ROOT)
    build.mkdir(parents=True, exist_ok=True)
    try:
        _build_target(args, source, build)
        _validate_target(build, args.test_level)
    except (OSError, subprocess.CalledProcessError) as error:
        diagnostic("ERROR", __file__, "native_target_failed", str(error))
        return 1
    diagnostic("INFO", __file__, "native_target_complete",
               f"FreeBSD {platform.release()} {platform.machine()} level={args.test_level}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Keep native test drivers on the SDK selected by their actual tools."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from brix_suite.client_build import client_make


def client_static_dependency_flags(client_dir):
    """External link/runtime flags recorded by the archive's own build graph."""
    client = Path(client_dir).resolve()
    build = client_make(client, "libbrix.pc", capture_output=True, text=True, timeout=60)
    build.check_returncode()
    env = dict(os.environ, PKG_CONFIG_PATH=str(client) + os.pathsep
               + os.environ.get("PKG_CONFIG_PATH", ""))
    probe = subprocess.run([
        "pkg-config", "--define-variable=libdir=" + str(client),
        "--static", "--libs", "libbrix",
    ], env=env, capture_output=True, text=True, check=True, timeout=30)
    # Callers link their explicit in-tree archives; do not accidentally add
    # an installed/shared copy of BriX or a stale installation-prefix -L.
    own = {"-lbrix", "-lxrdproto", "-L" + str(client)}
    return [flag for flag in shlex.split(probe.stdout) if flag not in own]


def uses_prefix_toolchain(prefix, *executables):
    """An inactive CONDA_PREFIX cannot override an explicitly selected SDK."""
    root = os.path.realpath(prefix)
    return any(executable and os.path.commonpath([root, os.path.realpath(executable)]) == root
               for executable in executables)


def client_test_env():
    env = dict(os.environ)
    prefix = env.get("CONDA_PREFIX") or sys.prefix
    if not uses_prefix_toolchain(prefix, sys.executable, shutil.which("pkg-config")):
        return env
    pcdir = os.path.join(prefix, "lib", "pkgconfig")
    if os.path.isdir(pcdir):
        loader = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
        env[loader] = os.path.join(prefix, "lib") + os.pathsep + env.get(loader, "")
        env["PKG_CONFIG_PATH"] = pcdir + os.pathsep + env.get("PKG_CONFIG_PATH", "")
    return env

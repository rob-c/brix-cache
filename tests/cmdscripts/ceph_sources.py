"""Use the shipped client build graph as the live Ceph driver's source closure."""

import shlex
import re

from brix_suite.client_build import client_make
from cmdscripts.compile_run import REPO_ROOT


def _sources_from_metadata(output, variable):
    """Accept only existing in-repository C sources, never arbitrary copy paths."""
    values = re.findall(r"^" + re.escape(variable) + r"\s*:?=\s*(.*)$", output, re.M)
    if not values or not values[-1]:
        raise ValueError(f"client build graph did not report {variable}")
    sources = []
    for name in shlex.split(values[-1]):
        path = (REPO_ROOT / "client" / name).resolve()
        relative = path.relative_to(REPO_ROOT)
        if path.suffix != ".c" or not path.is_file():
            raise ValueError(f"invalid Ceph source in build graph: {relative}")
        sources.append(relative.as_posix())
    return sources


def backend_sources(cephfs=False):
    """Expand canonical Make variables without building or requiring local Ceph."""
    # -pn also works with Apple's GNU make 3.81; --eval requires a newer make.
    query = client_make(REPO_ROOT / "client", "-s", "--no-print-directory",
                        "-pn", "libbrix.pc",
                        capture_output=True, text=True, timeout=60)
    query.check_returncode()
    sources = _sources_from_metadata(query.stdout, "CEPH_CORE_SRCS")
    if cephfs:
        sources += _sources_from_metadata(query.stdout, "CEPHFS_RO_SRCS")
    return list(dict.fromkeys(sources))


def driver_arguments(driver, output, cephfs=False):
    """Compile the real source closure with one consistent standalone shim."""
    return ["gcc", "-std=c11", "-D_GNU_SOURCE", "-D_FILE_OFFSET_BITS=64",
               "-DBRIX_PLATFORM_HOST=linux",
               "-Wall", "-Wextra", "-Werror", "-DXRDPROTO_NO_NGX", "-DBRIX_HAVE_CEPH",
               "-I", "src", "-I", "src/fs/backend", "-I", "src/fs/backend/rados",
               "-include", "client/apps/ceph/ngx_shim.h", driver,
               *backend_sources(cephfs), "-lrados", "-o", output]


def driver_command(driver, output, cephfs=False):
    """Retain the container operator's existing working-directory contract."""
    return "cd /work/repo && " + shlex.join(
        driver_arguments(driver, output, cephfs))

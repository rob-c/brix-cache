#!/usr/bin/env python3
"""Compile the mock HSM shared object (frm_mock_hsm.c) for the frm:// library-
native adapter tests (tests/test_frm_lib_adapter.py).

The .so is the vendor stand-in the sd_frm "lib" adapter dlopen()s: it exports the
sd_frm_lib_abi.h symbols (brix_frm_hsm_exists/recall/migrate) and simulates tape
with a local directory named by ``$BRIX_FRM_MOCK_TAPE``. ``purge`` is deliberately
omitted so the build also covers the adapter's optional-symbol path.
"""

from __future__ import annotations

import os
import shutil
import subprocess

_HERE = os.path.dirname(os.path.realpath(__file__))
_REPO = os.path.dirname(_HERE)                       # tests/
_SRC = os.path.join(_HERE, "frm_mock_hsm.c")
_ABI_DIR = os.path.join(os.path.dirname(_REPO), "src", "fs", "backend", "frm")


def build(dest_dir, name: str = "libmockhsm.so") -> str:
    """Compile frm_mock_hsm.c into ``dest_dir/name`` and return its path.

    Raises RuntimeError if a C compiler is unavailable (the caller skips).
    """
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        raise RuntimeError("no C compiler (cc/gcc) available")
    dest = os.path.join(str(dest_dir), name)
    subprocess.run(
        [cc, "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
         f"-I{_ABI_DIR}", "-o", dest, _SRC],
        check=True, capture_output=True, text=True)
    os.chmod(dest, 0o755)
    return dest

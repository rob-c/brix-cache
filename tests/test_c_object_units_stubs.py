"""The C object units that link ``sd_registry.o`` stub its driver symbols from
the row list that generates the registry, never from a hand-written list.

rhB43 (history-testing-and-incidents §24.17) halted on
``test_c_object_unit[vfs_caps]``: the registry table is generated from
``core/types/fs_list.h``, a BACKEND row (``ram``) was added there, and the
unit's hand-listed stubs went stale — a deterministic link failure that only
surfaces when a lane reaches the C units.  The unit now expands
``BRIX_FS_DRIVER_LIST`` for its stubs; these pins keep it (and any future
sibling) on that shape and tie the shape to the object it links against.
"""
import re
import subprocess
from pathlib import Path

import pytest

from cmdscripts.c_object_units import SPECS, addon

REPO = Path(__file__).resolve().parents[1]
FS_LIST = REPO / "src/core/types/fs_list.h"
HAND_STUB = re.compile(r"^\s*(?:extern\s+)?const\s+brix_sd_driver_t\s+brix_sd_\w+_driver\s*;", re.M)
ROW = re.compile(r'^\s*X\(\s*(\w+),\s*(\w+),\s*"[^"]*",\s*(\w+)\)', re.M)


def _registry_units() -> list[tuple[str, Path]]:
    """(spec name, C source) of every unit that links the registry object."""
    reg = addon("backend/sd_registry.o")
    out = []
    for name, spec in SPECS.items():
        if reg in spec.required:
            out += [(name, REPO / a) for a in spec.args if a.endswith(".c")]
    return out


def _backend_rows(header: Path) -> set[str]:
    return {sym for _id, sym, kind in ROW.findall(header.read_text()) if kind == "BACKEND"}


def test_registry_units_expand_the_row_list_and_hand_list_nothing():
    units = _registry_units()
    assert units, "no C unit links sd_registry.o any more — retarget this pin"
    for name, src in units:
        body = src.read_text()
        assert "BRIX_FS_DRIVER_LIST(BRIX_FS_ROW)" in body, f"{name}: stubs are not generated from fs_list.h"
        assert not HAND_STUB.findall(body), f"{name}: hand-listed driver stub(s) {HAND_STUB.findall(body)}"


def test_the_detector_fires_on_the_hand_listed_shape(tmp_path):
    stale = tmp_path / "unit.c"
    stale.write_text("const brix_sd_driver_t brix_sd_posix_driver;\n"
                     "extern const brix_sd_driver_t brix_sd_block_driver;\n")
    assert len(HAND_STUB.findall(stale.read_text())) == 2
    assert "BRIX_FS_DRIVER_LIST(BRIX_FS_ROW)" not in stale.read_text()


def test_every_driver_the_registry_object_references_is_a_backend_row():
    """Ground truth: a driver reached by sd_registry.o outside fs_list.h could
    not be stubbed by the generated list — the unit would be unlinkable and
    this pin says why before the compile does."""
    obj = addon("backend/sd_registry.o")
    if not obj.exists():
        pytest.skip(f"{obj} not built")
    nm = subprocess.run(["nm", "-u", str(obj)], capture_output=True, text=True, check=True, timeout=30)
    referenced = {m.group(1) for m in re.finditer(r"\bbrix_sd_(\w+)_driver\b", nm.stdout)}
    assert referenced, "sd_registry.o references no driver struct — the generated table is gone?"
    rows = _backend_rows(FS_LIST)
    assert referenced <= rows, f"referenced outside the row list: {sorted(referenced - rows)}"

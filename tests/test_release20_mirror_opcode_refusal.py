"""2.0 readiness F11 — ``brix_mirror_opcodes`` / ``brix_mirror_exclude_opcodes``
refuse ``read`` and ``readv`` at ``nginx -t``.

A read addresses an open handle that only the primary session holds; the
one-shot shadow replay never carried it (``brix_mirror_request_replayable``
returned 0), yet the parser accepted the names and ``all`` expanded to them, so
an operator's mask silently meant less than it said.  Since 2.0 the names are
refused with a message that says why, ``all`` no longer includes them, and the
two shipped test configs that listed them were corrected.  Legs: the remaining
vocabulary still parses (success); each directive refuses each name with the
handle explanation (error); ``all`` and the shipped configs no longer carry the
bits (security negative — a config cannot claim reads are mirrored).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from settings import BIND_HOST, HOST

REPO = Path(__file__).resolve().parents[1]
MIRROR_H = REPO / "src" / "net" / "mirror" / "mirror.h"
CONFIGS = REPO / "tests" / "configs"


def _parse(tmp_path, knobs):
    port = shadow = PARSE_PLACEHOLDER_PORT  # nginx -t never binds it
    (tmp_path / "data").mkdir(exist_ok=True)  # the export root must exist to parse
    result = nginx_t(
        "nginx_mirror_stream_parse.conf", tmp_path,
        BIND_HOST=BIND_HOST, HOST=HOST, PORT=port, SHADOW_PORT=shadow,
        DATA_ROOT=str(tmp_path / "data"), LOG_DIR=str(tmp_path),
        MIRROR_KNOBS=knobs,
    )
    return result.returncode, (result.stdout or "") + (result.stderr or "")


@pytest.mark.parametrize("knob", [
    "        brix_mirror_opcodes open stat statx dirlist query;\n",
    "        brix_mirror_opcodes all;\n",
    "        brix_mirror_exclude_opcodes stat locate;\n",
])
def test_remaining_vocabulary_parses(tmp_path, knob):
    rc, out = _parse(tmp_path, knob)
    assert rc == 0, out


@pytest.mark.parametrize("directive", ["brix_mirror_opcodes", "brix_mirror_exclude_opcodes"])
@pytest.mark.parametrize("name", ["read", "readv"])
def test_read_names_are_refused_with_the_handle_reason(tmp_path, directive, name):
    rc, out = _parse(tmp_path, f"        {directive} open {name};\n")
    assert rc != 0
    assert f'{directive}: "{name}" addresses an open handle' in out
    assert "reads are never mirrored" in out


def test_unknown_names_still_list_the_vocabulary_without_read(tmp_path):
    rc, out = _parse(tmp_path, "        brix_mirror_opcodes bogus;\n")
    assert rc != 0
    m = re.search(r"expected one of([^)]*)\)", out)
    assert m, out
    words = m.group(1).split()
    assert "read" not in words and "readv" not in words
    assert {"all", "stat", "open", "write"} <= set(words)


def test_all_mask_and_shipped_configs_carry_no_read_bits():
    """Security negative: neither ``all`` nor any shipped config can claim that
    reads are mirrored."""
    src = MIRROR_H.read_text(encoding="utf-8")
    start = src.index("#define BRIX_MIRROR_OP_ALL")
    block = src[start:src.index(")", start)]
    assert "BRIX_MIRROR_OP_READ" not in block, block
    offenders = []
    for conf in CONFIGS.glob("*.conf"):
        for line in conf.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s.startswith(("brix_mirror_opcodes", "brix_mirror_exclude_opcodes")):
                if re.search(r"\b(read|readv)\b", s.split(";")[0]):
                    offenders.append(f"{conf.name}: {s}")
    assert offenders == []

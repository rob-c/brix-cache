"""Tests for the source-derived directive reference generator."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools/ci/generate_directive_reference.py"


def _fixture(tmp_path: Path, declarations: str):
    source = tmp_path / "src/protocols/webdav"
    source.mkdir(parents=True)
    (source / "module.c").write_text(declarations)
    document = tmp_path / "directives.md"
    document.write_text("# Reference\n\n## Directives\n\nCurated prose.\n")
    env = os.environ.copy()
    env.update({
        "BRIX_REGISTRY_SRC": str(tmp_path / "src"),
        "BRIX_DIRECTIVE_DOC": str(document),
    })
    return document, env


def _run(env, *args):
    return subprocess.run(
        [sys.executable, str(GENERATOR), *args],
        cwd=ROOT, env=env, text=True, capture_output=True,
    )


def test_generator_expands_structural_reference_and_is_idempotent(tmp_path):
    document, env = _fixture(tmp_path, """
static ngx_command_t commands[] = {
 { ngx_string("brix_probe"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
   ngx_conf_set_str_slot, 0, 0, NULL },
};
""")
    assert _run(env).returncode == 0
    text = document.read_text()
    assert "| `brix_probe` | http | `<value>` |" in text
    assert _run(env, "--check").returncode == 0


def test_check_mode_reports_source_document_drift_without_writing(tmp_path):
    document, env = _fixture(tmp_path, """
static ngx_command_t commands[] = {
 { ngx_string("brix_first"), NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
   ngx_conf_set_flag_slot, 0, 0, NULL },
};
""")
    assert _run(env).returncode == 0
    before = document.read_text()
    source = tmp_path / "src/protocols/webdav/module.c"
    source.write_text(source.read_text().replace("brix_first", "brix_second"))
    checked = _run(env, "--check")
    assert checked.returncode == 1
    assert "stale" in checked.stderr
    assert document.read_text() == before


def test_cross_plane_registration_is_reported_as_one_shared_surface(tmp_path):
    document, env = _fixture(tmp_path, """
static ngx_command_t commands[] = {
 { ngx_string("brix_shared"), NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
   ngx_conf_set_flag_slot, 0, 0, NULL },
 { ngx_string("brix_shared"), NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
   ngx_conf_set_flag_slot, 0, 0, NULL },
};
""")
    assert _run(env).returncode == 0
    rows = [line for line in document.read_text().splitlines()
            if line.startswith("| `brix_shared`")]
    assert rows == [next(line for line in rows if "http, stream" in line)]

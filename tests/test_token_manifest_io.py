import json
from pathlib import Path

import pytest

from lib import tokenconf
from tokenforge import Manifest


def test_load_manifest_filters_a_complete_manifest(monkeypatch, tmp_path: Path):
    manifest = {"cases": [
        {"case_id": "AUD-01"},
        {"case_id": "SIG-01"},
    ]}
    (tmp_path / "token_manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(tokenconf, "TOKENS_DIR", str(tmp_path))

    assert tokenconf.load_manifest("AUD") == [{"case_id": "AUD-01"}]


def test_load_manifest_rebuilds_a_truncated_file(monkeypatch, tmp_path: Path):
    (tmp_path / "token_manifest.json").write_text("")
    monkeypatch.setattr(tokenconf, "TOKENS_DIR", str(tmp_path))

    rows = tokenconf.load_manifest("AUD")

    assert [row["case_id"] for row in rows] == [
        "AUD-01", "AUD-02", "AUD-03", "AUD-04", "AUD-05", "AUD-06",
    ]
    json.loads((tmp_path / "token_manifest.json").read_text())


def test_manifest_write_failure_preserves_previous_file(monkeypatch, tmp_path: Path):
    target = tmp_path / "token_manifest.json"
    target.write_text('{"cases": [{"case_id": "OLD"}]}')
    manifest = Manifest()

    def fail_dump(*_args, **_kwargs):
        raise RuntimeError("injected serialization failure")

    monkeypatch.setattr("tokenforge.json.dump", fail_dump)
    with pytest.raises(RuntimeError, match="injected serialization failure"):
        manifest.write(str(target))

    assert json.loads(target.read_text())["cases"][0]["case_id"] == "OLD"
    assert list(tmp_path.glob(".token_manifest.json.*.tmp")) == []

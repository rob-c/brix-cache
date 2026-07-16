from pathlib import Path

from cmdscripts.operator_runtime import run_checks


def test_operator_runtime_ports_are_importable(tmp_path: Path):
    results = run_checks(tmp_path)
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)

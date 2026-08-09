"""Guards for the suite's single ownership boundary: settings.TEST_ROOT."""

import os
from pathlib import Path

from settings import ARTIFACTS_DIR, CWD_DIR, LOG_DIR, TEST_ROOT, TMP_DIR


def _is_beneath(path: str, root: str) -> bool:
    return os.path.commonpath((os.path.realpath(path), os.path.realpath(root))) == os.path.realpath(root)


def test_all_session_output_roots_are_beneath_test_root():
    for path in (ARTIFACTS_DIR, CWD_DIR, LOG_DIR, TMP_DIR):
        assert _is_beneath(path, TEST_ROOT), f"output root escapes TEST_ROOT: {path}"


def test_artifact_directory_exists_during_pytest_session():
    artifact_root = Path(ARTIFACTS_DIR)
    assert artifact_root.is_dir()
    assert artifact_root.parent == Path(TEST_ROOT)


def test_tmpdir_environment_is_confined_to_test_root():
    assert os.environ["TMPDIR"] == TMP_DIR
    assert _is_beneath(os.environ["TMPDIR"], TEST_ROOT)

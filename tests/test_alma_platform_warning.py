"""Alma RPM platform-warning scriptlet contracts."""

import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
WARNING = ROOT / "packaging" / "rpm" / "alma-platform-warning.sh"


def _run_warning(os_release: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["BRIX_OS_RELEASE_FILE"] = str(os_release)
    return subprocess.run(
        ["sh", str(WARNING)], capture_output=True, text=True, env=env, check=False
    )


def test_rocky_install_emits_unsupported_warning(tmp_path: Path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text('NAME="Rocky Linux"\nID="rocky"\nVERSION_ID="9.6"\n')

    result = _run_warning(os_release)

    assert result.returncode == 0
    assert "Rocky Linux is NOT supported" in result.stderr
    assert "built for AlmaLinux" in result.stderr


def test_alma_install_is_quiet(tmp_path: Path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text('NAME="AlmaLinux"\nID="almalinux"\nVERSION_ID="9.6"\n')

    result = _run_warning(os_release)

    assert result.returncode == 0
    assert result.stderr == ""


def test_os_release_is_parsed_as_data_not_executed(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    os_release = tmp_path / "os-release"
    os_release.write_text(f'ID="$(touch {marker})"\n')

    result = _run_warning(os_release)

    assert result.returncode == 0
    assert result.stderr == ""
    assert not marker.exists()

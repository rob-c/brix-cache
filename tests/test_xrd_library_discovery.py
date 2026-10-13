"""Cross-distribution discovery for versioned XRootD plugin libraries."""

from lib_py.util import _direct_xrd_library, _library_below, nologin_shell


def test_exact_xrootd_library_is_preferred(tmp_path):
    """An explicitly requested ABI remains preferred when several are installed."""
    exact = tmp_path / "libXrdSec-5.so"
    exact.touch()
    (tmp_path / "libXrdSec-6.so").touch()

    assert _library_below(tmp_path, exact.name) == exact.resolve()


def test_newer_xrootd_soversion_is_discovered(tmp_path):
    """A distro's current XRootD ABI satisfies a legacy-version probe."""
    current = tmp_path / "libXrdSec-6.so"
    current.touch()

    assert _library_below(tmp_path, "libXrdSec-5.so") == current.resolve()


def test_xrootd_library_discovery_ignores_directories(tmp_path):
    """A lookalike directory cannot satisfy the executable-library prerequisite."""
    (tmp_path / "libXrdSec-99.so").mkdir()

    assert _library_below(tmp_path, "libXrdSec-5.so") is None


def test_explicit_nix_xrootd_library_directory_is_searched(tmp_path,
                                                           monkeypatch):
    library = tmp_path / "libXrdSec-5.so"
    library.touch()
    monkeypatch.setenv("BRIX_XROOTD_LIBDIR", str(tmp_path))

    assert _direct_xrd_library(library.name) == library.resolve()


def test_relative_xrootd_library_directory_is_never_trusted(tmp_path,
                                                            monkeypatch):
    library = tmp_path / "libXrdSec-5.so"
    library.touch()
    monkeypatch.chdir(tmp_path.parent)
    monkeypatch.setenv("BRIX_XROOTD_LIBDIR", tmp_path.name)

    assert _direct_xrd_library(library.name) != library.resolve()


def test_nologin_shell_resolves_non_fhs_path(tmp_path, monkeypatch):
    command = tmp_path / "nologin"
    command.touch(mode=0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    assert nologin_shell() == str(command.resolve())

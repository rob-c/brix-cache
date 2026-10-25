"""The fork-safety harness uses the SDK selected by its actual tools."""

from test_client_forksafe_registry import _uses_prefix_toolchain


def test_actual_conda_tools_select_the_conda_sdk():
    assert _uses_prefix_toolchain("/opt/conda", "/opt/conda/bin/python", "/usr/bin/pkg-config")


def test_homebrew_tools_do_not_inherit_an_inactive_conda_sdk():
    assert not _uses_prefix_toolchain("/opt/conda", "/opt/homebrew/bin/python", "/opt/homebrew/bin/pkg-config")


def test_similarly_named_prefix_is_not_the_selected_environment():
    assert not _uses_prefix_toolchain("/opt/conda", "/opt/conda-untrusted/bin/python", None)

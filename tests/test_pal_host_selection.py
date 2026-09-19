# tests/test_pal_host_selection.py
"""Guards the PAL's computed host include against compiler-predefined tokens.

INVARIANT 14 keeps the PAL interface headers host-free: the build passes
`-DBRIX_PLATFORM_HOST=<linux|darwin|windows>` and `src/platform/platform.h`
turns that token into ONE computed `#include "<host>/host.h"` by stringifying
it.  Stringification expands the token first, and GCC/Clang predefine the bare
identifier `linux` as `1` in GNU mode — the default when no `-std=` is given.
The nginx module build takes its flags from `./configure`, which passes no
`-std=`, so on Linux the include became

    src/platform/platform.h:37:38: fatal error: 1/host.h: No such file or directory

and no module object compiled.  The client and xrdproto Makefiles pass
`-std=c11`, which hides the predefined spellings, which is why only the module
build broke and only on Linux.

`platform.h` now retires those spellings before the stringify, so the host name
always arrives as a plain identifier.  These checks exercise the real header
under the module build's own flag set (no `-std=`), for every host token — the
Darwin and Windows cases run on this host too, because the selection happens in
the preprocessor, before any SDK header is needed.

    PYTHONPATH=tests pytest tests/test_pal_host_selection.py -v
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

from cmdscripts.compile_run import run

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "src"
HOSTS = ("linux", "darwin", "windows")

pytestmark = pytest.mark.timeout(60)


def _include_pal(*flags: str) -> tuple[int, str]:
    """Preprocess a TU that includes the PAL umbrella; return (rc, output).

    `-H` makes the compiler report every header it opens, so the host header it
    SELECTED is observable even when that header then needs an SDK this host
    does not have (Darwin's TargetConditionals.h, Windows' windows.h).  Only
    the selection is under test here, not cross-compilability.
    """
    if shutil.which("gcc") is None:
        pytest.skip("no gcc")
    with tempfile.TemporaryDirectory() as scratch:
        tu = pathlib.Path(scratch) / "pal_host_selection.c"
        tu.write_text('#include "platform/platform.h"\n')
        proc = run(["gcc", "-E", "-H", "-I", str(SRC), str(tu), *flags], cwd=REPO)
    return proc.returncode, proc.stdout + proc.stderr


@pytest.mark.parametrize("host", HOSTS)
def test_each_host_token_selects_its_own_directory(host: str) -> None:
    """Success: with the module build's flags (no -std=), every host token
    reaches its own src/platform/<host>/host.h."""
    _rc, out = _include_pal(f"-DBRIX_PLATFORM_HOST={host}")
    assert f"platform/{host}/host.h" in out, (
        f"-DBRIX_PLATFORM_HOST={host} did not select src/platform/{host}/host.h:\n{out}"
    )


@pytest.mark.parametrize("host", HOSTS)
def test_no_host_token_is_swallowed_by_a_predefined_macro(host: str) -> None:
    """The regression itself: the include must never resolve to "1/host.h".

    That is what a predefined `linux`/`unix`-style token does to the stringify,
    and it is the exact failure this guard exists to keep out.
    """
    _rc, out = _include_pal(f"-DBRIX_PLATFORM_HOST={host}")
    assert "1/host.h" not in out, (
        f"BRIX_PLATFORM_HOST={host} expanded through a predefined macro before "
        f"stringification:\n{out}"
    )


def test_a_hostile_predefine_cannot_hijack_the_host_name() -> None:
    """Negative: an explicitly injected `-Ddarwin=1 -Dlinux=1 -Dwindows=1`
    must not redirect the computed include.

    A toolchain (or a wrapper prepending flags) is free to predefine these bare
    identifiers; the header owns its token regardless, so the PAL cannot be
    pointed at another host's adapters by anything on the command line.
    """
    injected = ["-Dlinux=1", "-Ddarwin=1", "-Dwindows=1"]
    _rc, out = _include_pal("-DBRIX_PLATFORM_HOST=darwin", *injected)
    assert "platform/darwin/host.h" in out, (
        f"injected predefines redirected the host include:\n{out}"
    )
    assert "1/host.h" not in out, out


def test_the_module_build_flags_preprocess_this_host_cleanly() -> None:
    """Success, end to end: the host we are on preprocesses with no -std= flag.

    This is the module build's actual condition — the one that failed — so it
    must complete, not merely select the right directory.
    """
    rc, out = _include_pal("-DBRIX_PLATFORM_HOST=linux", "-DBRIX_PLATFORM_LINUX=1")
    assert rc == 0, f"the Linux PAL does not preprocess without -std=:\n{out}"


def test_a_missing_host_token_still_reports_the_actionable_error() -> None:
    """Error path: omitting the define must keep saying how to fix it.

    Retiring the predefined spellings must not turn a missing
    -DBRIX_PLATFORM_HOST into a confusing "no such file" for `/host.h`.
    """
    rc, out = _include_pal()
    assert rc != 0, "a build with no BRIX_PLATFORM_HOST must not succeed"
    assert "BRIX_PLATFORM_HOST is not defined" in out, (
        f"the missing-host diagnostic no longer names the flag to pass:\n{out}"
    )


# --- the harness seams -------------------------------------------------------
# The checks above prove the header behaves.  These prove the CALLERS pass the
# token.  That distinction is the whole reason this section exists: when the PAL
# landed, ./config and client/Makefile learned -DBRIX_PLATFORM_HOST but the
# pytest harnesses that assemble their own gcc lines did not, and 32 standalone
# C tests died on the #error above with nothing pointing at the cause.  Each
# seam below is where one family of those lines is built.  They are checked by
# capturing the argv rather than by compiling, so the guard costs nothing and
# stays honest about WHICH line is missing the flag.


def _captured_argv(monkeypatch, module, call):
    """Every argv `call` hands `module.run`, with no command actually run."""
    seen: list[list[str]] = []

    def _fake_run(argv, **_kwargs):
        seen.append([str(a) for a in argv])
        return subprocess.CompletedProcess(list(argv), 0, "", "")

    monkeypatch.setattr(module, "run", _fake_run)
    call()
    assert seen, "the seam ran no command at all"
    return seen[0]


def _host_token(argv: list[str]) -> str | None:
    """The -DBRIX_PLATFORM_HOST=<host> on a command line, or None."""
    for arg in argv:
        if arg.startswith("-DBRIX_PLATFORM_HOST="):
            return arg
    return None


def test_the_shared_compile_seams_pass_the_host_token(monkeypatch, tmp_path) -> None:
    """Success: each helper that hand-rolls a compile line carries the token.

    One check per seam, named, so a failure says which harness family regressed
    instead of leaving 30-odd unrelated C tests to fail on a header #error.
    """
    from cmdscripts import c_auth_units, c_regression_units, sd_slot_unit

    seams = {
        "c_regression_units._cc": lambda: _captured_argv(
            monkeypatch, c_regression_units,
            lambda: c_regression_units._cc(["unit.c"])),
        "c_auth_units.compile_and_run": lambda: _captured_argv(
            monkeypatch, c_auth_units,
            lambda: c_auth_units.compile_and_run(tmp_path / "ut", ["unit.c"])),
        "sd_slot_unit.run_one": lambda: _captured_argv(
            monkeypatch, sd_slot_unit,
            lambda: sd_slot_unit.run_one(tmp_path, next(iter(sd_slot_unit.UNITS)))),
        "c_auth_units.x509_gcc_args": lambda: c_auth_units.x509_gcc_args(
            c_auth_units.X509_HARNESS_TUS["x509_oracle"]),
    }
    missing = [name for name, produce in seams.items()
               if _host_token(produce()) is None]
    assert not missing, (
        "these compile seams build a gcc line with no -DBRIX_PLATFORM_HOST; "
        f"every tree header reaching platform/platform.h will #error: {missing}"
    )


def test_the_seam_token_names_the_host_being_built_for() -> None:
    """The token must name THIS host, not merely be present.

    `-DBRIX_PLATFORM_HOST=darwin` on Linux compiles nothing useful — it selects
    an adapter set whose SDK is absent — so a seam that hard-codes one host is
    as broken as a seam that passes none.
    """
    from cmdscripts.compile_run import PLATFORM_HOST_FLAGS

    expected = "darwin" if sys.platform == "darwin" else "linux"
    assert f"-DBRIX_PLATFORM_HOST={expected}" in PLATFORM_HOST_FLAGS, (
        f"PLATFORM_HOST_FLAGS does not select this host: {PLATFORM_HOST_FLAGS}"
    )


def test_a_seam_without_the_token_is_actually_caught() -> None:
    """Negative control: the detector above is not vacuously true.

    A guard that scans argv is only worth its runtime if it FAILS on a line that
    omits the flag — otherwise a helper could quietly drop the token and the
    sweep would keep passing.
    """
    assert _host_token(["gcc", "-Wall", "-I", "src", "unit.c"]) is None
    assert _host_token(["gcc", "-DBRIX_PLATFORM_HOST=linux"]) == \
        "-DBRIX_PLATFORM_HOST=linux"
    # A near-miss spelling must not be mistaken for the real flag.
    assert _host_token(["gcc", "-DBRIX_PLATFORM_HOSTNAME=linux"]) is None

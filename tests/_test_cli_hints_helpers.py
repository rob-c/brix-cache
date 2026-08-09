"""
test_cli_hints.py — PTY and pipe tests for TTY-gated usability hints.

WHAT:  Test classes covering P1 (WS-1 env-alias divergence note) and
       P3 (WS-3 double-slash URL hint + WS-7 did-you-mean + doctor referral).

       P1 classes (existing):
         TestHintFiredOnPty       — divergence note fires on a PTY
         TestHintAbsentOnPipe     — note absent on pipe (C3)
         TestHintTableFull        — 17th key silently dropped
         TestNoteNoControlBytes   — note contains no control bytes

       P3 classes (new, task 3):
         TestSuggestDidYouMeanPty — did-you-mean hint fires on PTY, silent on pipe
         TestDoubleSlashHintPty   — double-slash URL hint fires when bit set
         TestDoctorReferralPty    — doctor referral fires on auth failure

WHY:   Spec C3: hints must never appear in scripts, pipelines, or cron jobs.
       Spec WS-3, WS-7: canned hints must fire correctly in interactive sessions.

HOW:   A C probe binary (suggest_probe.c) is compiled against the client lib
       to exercise each hint function.  run_pty attaches a PTY so isatty=1;
       run_pipe uses a regular pipe so isatty=0.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

import pytest

# Defined here (not only in the parent test module) so this helper's own
# functions resolve it: reexport copies helper->test, so a name the helper USES
# must live in the helper, not be stranded in the test's later top-level code.
SUGGEST_PROBE_SRC = pathlib.Path(__file__).parent / "helpers" / "suggest_probe.c"

# ---------------------------------------------------------------------------
# Fixture: compile the probe binary once per session
# ---------------------------------------------------------------------------

CLIENT_DIR = pathlib.Path(__file__).parent.parent / "client"
PROBE_SRC = pathlib.Path(__file__).parent / "helpers" / "envalias_probe.c"
PROBE_BIN = None  # set by the fixture


def _compile_probe(tmp_dir: pathlib.Path) -> pathlib.Path:
    """Compile the helper probe that calls brix_env_resolve and exits.

    WHAT: builds a minimal binary that exercises the divergence-note path so
          we can observe it through a PTY or pipe without involving any real
          server or authentication.
    WHY:  the library's brix_env_resolve() is a pure C function; compiling a
          standalone probe is the fastest, most direct way to drive it.
    HOW:  mirrors the make test recipe — link against CLIENT_LIB + PROTO_LIB
          so the probe picks up the full resolved dependencies.
    """
    client_lib  = CLIENT_DIR / "libbrix.a"
    proto_lib   = CLIENT_DIR / ".." / "shared" / "xrdproto" / "libxrdproto.a"
    probe_out   = tmp_dir / "envalias_probe"

    if not client_lib.exists():
        pytest.skip("client/libbrix.a not built; run `make -C client lib` first")
    if not proto_lib.exists():
        pytest.skip("shared/xrdproto/libxrdproto.a not built")
    if not PROBE_SRC.exists():
        pytest.skip(f"probe source not found: {PROBE_SRC}")

    result = subprocess.run(
        [
            "cc", "-std=c11", "-Wall",
            f"-I{CLIENT_DIR / 'lib'}",
            f"-I{CLIENT_DIR / '..' / 'src'}",
            f"-I{CLIENT_DIR / '..' / 'shared'}",
            "-DXRDPROTO_NO_NGX",
            str(PROBE_SRC),
            str(client_lib),
            str(proto_lib),
            "-lssl", "-lcrypto", "-lz",
            "-o", str(probe_out),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(
            f"could not compile envalias_probe: {result.stderr[:500]}"
        )
    return probe_out


@pytest.fixture(scope="session")
def probe_binary(tmp_path_factory):
    """Return path to the compiled probe binary (compiled once per session)."""
    tmp = tmp_path_factory.mktemp("envalias_probe")
    return _compile_probe(tmp)


# ---------------------------------------------------------------------------
# Import run_pty / run_pipe from the helpers module
# ---------------------------------------------------------------------------
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from cli_pty import run_pipe, run_pty  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: build an env dict with BRIX_NO_HINTS cleared
# ---------------------------------------------------------------------------

def _base_env(**extra):
    """Return os.environ copy with BRIX_NO_HINTS removed plus any extras."""
    env = dict(os.environ)
    env.pop("BRIX_NO_HINTS", None)
    env.update(extra)
    return env


# ---------------------------------------------------------------------------
# success tests
# ---------------------------------------------------------------------------

def _compile_suggest_probe(tmp_dir: pathlib.Path) -> pathlib.Path:
    """Compile suggest_probe.c against libbrix.a for PTY-based hint tests.

    WHAT: suggest_probe exercises brix_suggest(), brix_hint_url_double_slash(),
          and brix_hint_doctor_referral() via argv[1] subcommands.
    WHY:  hint functions gate on isatty(STDERR_FILENO); we need a standalone
          binary whose stderr we can attach to a PTY or pipe.
    HOW:  same link recipe as the Makefile test target.
    """
    client_lib = CLIENT_DIR / "libbrix.a"
    proto_lib  = CLIENT_DIR / ".." / "shared" / "xrdproto" / "libxrdproto.a"
    probe_out  = tmp_dir / "suggest_probe"

    if not client_lib.exists():
        pytest.skip("client/libbrix.a not built; run `make -C client` first")
    if not proto_lib.exists():
        pytest.skip("shared/xrdproto/libxrdproto.a not built")
    if not SUGGEST_PROBE_SRC.exists():
        pytest.skip(f"probe source not found: {SUGGEST_PROBE_SRC}")

    # Detect optional libraries from the Makefile LDLIBS (best-effort).
    extra_libs = ["-lssl", "-lcrypto", "-lz"]
    for lib in ["krb5", "k5crypto", "com_err", "zstd", "lzma", "uring"]:
        extra_libs.append(f"-l{lib}")

    cmd = [
        "cc", "-std=c11", "-Wall",
        f"-I{CLIENT_DIR / 'lib'}",
        f"-I{CLIENT_DIR / '..' / 'src'}",
        f"-I{CLIENT_DIR / '..' / 'shared'}",
        "-DXRDPROTO_NO_NGX",
        str(SUGGEST_PROBE_SRC),
        str(client_lib),
        str(proto_lib),
    ] + extra_libs + ["-o", str(probe_out)]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        pytest.skip(
            f"could not compile suggest_probe: {result.stderr[:500]}"
        )
    return probe_out


@pytest.fixture(scope="session")
def suggest_probe_binary(tmp_path_factory):
    """Return path to the compiled suggest_probe binary."""
    tmp = tmp_path_factory.mktemp("suggest_probe")
    return _compile_suggest_probe(tmp)

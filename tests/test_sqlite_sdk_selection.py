"""The nginx module must use SQLite headers and libraries from the same SDK."""

import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def _probe(tmp_path, *, metadata=True, compiles=True, disabled=False):
    source = (ROOT / "config").read_text()
    block = source.split('BRIX_SQLITE_CFLAGS=""', 1)[1].split('\n_xrd_ssl_verified=""', 1)[0]
    bindir = tmp_path / "bin"
    bindir.mkdir()
    pkg_config = bindir / "pkg-config"
    pkg_config.write_text('''#!/bin/sh
test "$HAS_METADATA" = 1 || exit 1
case "$1" in
    --exists) exit 0 ;;
    --cflags) printf '%s\\n' '-I/selected/sqlite/include' ;;
    --libs) printf '%s\\n' '-L/selected/sqlite/lib -lsqlite3' ;;
esac
''')
    pkg_config.chmod(0o755)
    script = '''
compile_probe() {
    printf '%s\\n' "$*" > "$TRACE"
    test "$COMPILES" = 1
}
BRIX_SQLITE_CFLAGS=""
''' + block + '\nprintf "FLAGS=%s\\nLIBS=%s\\n" "$CFLAGS" "$BRIX_SQLITE_LIBS"\n'
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
               NGX_AUTOTEST=str(tmp_path / "configure-probe"),
               TRACE=str(tmp_path / "compiler-args"), CC="compile_probe",
               CC_TEST_FLAGS="", CFLAGS="", HAS_METADATA=str(int(metadata)),
               COMPILES=str(int(compiles)), BRIX_WITHOUT_SQLITE=str(int(disabled)))
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    trace = tmp_path / "compiler-args"
    return result.stdout, trace.read_text() if trace.exists() else ""


def test_selected_sqlite_headers_and_libraries_travel_together(tmp_path):
    """A keg-only or Nix SQLite is tested and linked as one selected SDK."""
    output, command = _probe(tmp_path)
    assert "-I/selected/sqlite/include" in command
    assert "-L/selected/sqlite/lib -lsqlite3" in command
    assert "FLAGS= -I/selected/sqlite/include -DBRIX_HAVE_SQLITE=1" in output
    assert "LIBS=-L/selected/sqlite/lib -lsqlite3" in output


def test_failed_selected_sdk_cannot_advertise_a_working_driver(tmp_path):
    """An unusable dependency must neither enable pblock nor leak link flags."""
    output, _command = _probe(tmp_path, compiles=False)
    assert "disabled" in output and "-DBRIX_HAVE_SQLITE" not in output
    assert output.endswith("FLAGS=\nLIBS=\n")


def test_explicit_disable_cannot_be_overridden_by_available_metadata(tmp_path):
    """Operator exclusion wins without attempting the compiler probe."""
    output, command = _probe(tmp_path, disabled=True)
    assert command == "" and "disabled" in output
    assert output.endswith("FLAGS=\nLIBS=\n")


def test_missing_metadata_preserves_the_system_fallback(tmp_path):
    """A usable system SQLite remains available without a pkg-config file."""
    output, command = _probe(tmp_path, metadata=False)
    assert "-lsqlite3" in command and "-I/selected" not in command
    assert "-DBRIX_HAVE_SQLITE=1" in output and "LIBS=-lsqlite3" in output

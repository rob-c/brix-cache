"""brix-xrdcp transport-option parsing — the descriptor table in xrdcp_parse.c.

`xrdcp_parse_transport_option` was decomposed (coding-standards §8.6) into a
spelling→field descriptor table (`xrdcp_transport_flags`) plus three value-taking
helpers.  A table row that loses its spelling, or a row order that lets a shorter
prefix swallow a longer flag, turns a flag into a silent no-op — the copy still
runs, just without the posture the operator asked for.  Nothing else in the suite
passes these spellings on the command line, so this file pins them.

The probe needs no fleet: the parser runs to completion before the first
connect, so a dead endpoint separates the two outcomes cleanly.  (Single
exception: the --force field-level proof in TestStockLongSpellings is
fleet-marked, because the exists-check runs only after a successful connect.)

  * success   — every valueless flag spelling parses (exit 51 = connect failed,
                i.e. argv was accepted), incl. all three --io-uring-direct forms
  * error     — a bad value for a value-taking option is a usage error (exit 50)
  * security  — a flag look-alike is rejected as unknown, never folded into the
                nearest real row (no prefix/substring acceptance)

Run:
    PYTHONPATH=tests pytest tests/test_xrdcp_transport_opts.py -v
"""

from __future__ import annotations

import os
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

# Port 1 is privileged and never bound by the suite: connect fails immediately.
DEAD_SRC = "root://127.0.0.1:1//x"  # net-literal-allow: deliberately unreachable probe

USAGE_ERROR = 50      # argv rejected before any I/O
CONNECT_FAILED = 51   # argv accepted; the transfer failed at connect

pytestmark = [
    pytest.mark.timeout(120),
    pytest.mark.skipif(not os.path.exists(XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
]


def _run(args, tmp_path):
    """Run xrdcp with `args` prepended to a dead-source copy; return CompletedProcess."""
    dst = os.path.join(str(tmp_path), "out.bin")
    return subprocess.run([XRDCP, *args, DEAD_SRC, dst],
                          capture_output=True, text=True, timeout=60)


def _run_upload(args, tmp_path):
    """Same probe with the directions swapped, for flags that require a local source."""
    src = os.path.join(str(tmp_path), "in.bin")
    with open(src, "wb") as f:
        f.write(b"payload\n")
    return subprocess.run([XRDCP, *args, src, "root://127.0.0.1:1//x"],  # net-literal-allow: deliberately unreachable probe
                          capture_output=True, text=True, timeout=60)


# ---- success: every table row's spelling is accepted ----

@pytest.mark.parametrize("flag", [
    "--parallel",
    "--no-metalink",
    "--io-uring-direct",
    "--io-uring-direct=on",
    "--io-uring-direct=off",
])
def test_valueless_flag_accepted(flag, tmp_path):
    res = _run([flag], tmp_path)
    assert res.returncode == CONNECT_FAILED, (flag, res.returncode, res.stderr)
    assert "unknown option" not in res.stderr


@pytest.mark.parametrize("flag", ["--zip", "--zip-append"])
def test_zip_flag_accepted(flag, tmp_path):
    """The zip rows carry a post-parse rule (local source only), so they are
    probed as an upload — reaching connect proves the row was applied."""
    res = _run_upload([flag], tmp_path)
    assert res.returncode == CONNECT_FAILED, (flag, res.returncode, res.stderr)
    assert "unknown option" not in res.stderr


@pytest.mark.parametrize("args", [
    ["--io-uring", "on"],
    ["--io-uring=off"],
    ["--io-uring=auto"],
    ["--sources", "4"],
    ["-S", "2"],
    ["--streams", "2"],
])
def test_value_taking_option_accepted(args, tmp_path):
    res = _run(args, tmp_path)
    assert res.returncode == CONNECT_FAILED, (args, res.returncode, res.stderr)


def test_io_uring_direct_not_swallowed_by_io_uring(tmp_path):
    """--io-uring-direct must reach its own row, not be read as --io-uring's value.

    Were the shorter spelling matched first, `--io-uring-direct` would consume
    the next argv slot as a mode and fail on it.  Combining both options in one
    command line proves each landed on its own row.
    """
    res = _run(["--io-uring-direct", "--io-uring", "off"], tmp_path)
    assert res.returncode == CONNECT_FAILED, (res.returncode, res.stderr)
    assert "invalid mode" not in res.stderr


# ---- error: bad values are clean usage errors ----

@pytest.mark.parametrize("args,needle", [
    (["--io-uring", "bogus"], "--io-uring"),
    (["--io-uring=bogus"], "--io-uring"),
    (["--io-uring="], "--io-uring"),
    (["--sources", "0"], "--sources"),
    (["--sources", "17"], "--sources"),
    (["--sources", "notanumber"], "--sources"),
])
def test_bad_value_is_usage_error(args, needle, tmp_path):
    res = _run(args, tmp_path)
    assert res.returncode == USAGE_ERROR, (args, res.returncode, res.stderr)
    assert needle in res.stderr


# ---- security-negative: look-alikes are never folded into a real row ----

@pytest.mark.parametrize("bogus", [
    "--io-uring-directX",     # longest row + a suffix
    "--io-uring-direct=ON",   # value case is significant; no fuzzy match
    "--io-uring-direct=yes",
    "--zip-append=1",         # valueless row given a value
    "--zip=1",
    "--parallel=8",
    "--no-metalink=1",
    "--zip-appen",            # truncated row
    "--io-uring-dir",
])
def test_flag_lookalike_rejected(bogus, tmp_path):
    """A near-miss spelling must be an unknown option, not the nearest row.

    Silent acceptance would be the dangerous failure: `--parallel=8` quietly
    enabling the fail-closed parallel path, or `--no-metalink=1` disabling
    metalink resolution, with no diagnostic and no way for the caller to tell.
    """
    res = _run([bogus], tmp_path)
    assert res.returncode == USAGE_ERROR, (bogus, res.returncode, res.stderr)
    assert "unknown option" in res.stderr
    assert bogus in res.stderr


# ---- stock-xrdcp compatibility: -A / --allow-http ----

@pytest.mark.parametrize("flag", ["-A", "--allow-http"])
def test_allow_http_is_accepted(flag, tmp_path):
    """Stock xrdcp gates http/davs behind -A; this client has no such gate.

    Every WebDAV recipe in the field carries the flag — the docs here do, and
    so does tests/test_a_webdav_clients.py — so a client shipping under the
    stock name has to accept it. Reaching connect proves argv was taken AND
    that the valueless flag did not swallow the source positional.
    """
    res = _run([flag], tmp_path)
    assert res.returncode == CONNECT_FAILED, (flag, res.returncode, res.stderr)
    assert "unknown option" not in res.stderr


@pytest.mark.parametrize("bogus", ["--allow-https", "--allow-http=1", "-Ax", "--allow"])
def test_allow_http_lookalike_rejected(bogus, tmp_path):
    """The compat row is an exact match, not a prefix — a near miss is unknown."""
    res = _run([bogus], tmp_path)
    assert res.returncode == USAGE_ERROR, (bogus, res.returncode, res.stderr)
    assert "unknown option" in res.stderr


def test_allow_http_grants_nothing_and_relaxes_nothing(tmp_path):
    """The flag GRANTS a capability we already have; it must not relax one.

    Read as a TLS knob it would be a downgrade — silently implying --notlsok
    or clearing the default-on host verification. Proving inertness directly:
    the run with the flag must be indistinguishable from the run without it,
    same exit and same diagnostics, with no posture message in between.
    """
    plain = _run([], tmp_path)
    compat = _run(["--allow-http"], tmp_path)
    assert (compat.returncode, compat.stderr) == (plain.returncode, plain.stderr)
    for leaked in ("notlsok", "cleartext", "verifyhost", "insecure"):
        assert leaked not in compat.stderr.lower()
# ---- stock xrdcp long spellings (parity-audit §7.13) ----

class TestStockLongSpellings:
    """Stock xrdcp long spellings are aliases of the short flags, so drop-in
    scripts written against the reference client keep working.

      * success  — --force/--recursive/--nopbar/--silent parse (probe reaches
                   connect), and --force provably lands on the force field: an
                   existing local destination fails without it, succeeds with it
      * error    — a stock spelling with a bolted-on value is a usage error
      * security — truncations of the new spellings stay unknown options
    """

    @pytest.mark.parametrize("flag", [
        "--force", "--recursive", "--nopbar", "--silent",
    ])
    def test_stock_spelling_accepted(self, flag, tmp_path):
        res = _run([flag], tmp_path)
        assert res.returncode == CONNECT_FAILED, (flag, res.returncode,
                                                  res.stderr)
        assert "unknown option" not in res.stderr

    @pytest.mark.requires_local_server
    def test_force_alias_reaches_force_field(self, tmp_path):
        """Download onto an existing local destination: refused without
        --force (destination exists), byte-exact overwrite with it — proving
        the alias sets the same field as -f, not merely parsing.  The one
        fleet-backed case in this file: the exists-check runs after connect,
        so a dead endpoint cannot separate the two outcomes."""
        from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST
        name = "xrdcp-force-alias.bin"
        os.makedirs(DATA_ROOT, exist_ok=True)
        with open(os.path.join(DATA_ROOT, name), "wb") as f:
            f.write(b"fresh payload\n")
        try:
            url = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//{name}"
            dst = os.path.join(str(tmp_path), "dst.bin")
            with open(dst, "wb") as f:
                f.write(b"stale\n")
            res = subprocess.run([XRDCP, url, dst],
                                 capture_output=True, text=True, timeout=60)
            assert res.returncode != 0, \
                "existing destination accepted without force"
            res = subprocess.run([XRDCP, "--force", url, dst],
                                 capture_output=True, text=True, timeout=60)
            assert res.returncode == 0, res.stderr
            with open(dst, "rb") as f:
                assert f.read() == b"fresh payload\n"
        finally:
            os.unlink(os.path.join(DATA_ROOT, name))

    @pytest.mark.parametrize("bogus", [
        "--force=1", "--recursive=1", "--nopbar=1",
    ])
    def test_stock_spelling_with_value_rejected(self, bogus, tmp_path):
        res = _run([bogus], tmp_path)
        assert res.returncode == USAGE_ERROR, (bogus, res.returncode,
                                               res.stderr)
        assert "unknown option" in res.stderr

    @pytest.mark.parametrize("bogus", [
        "--forc", "--recursiv", "--nopba", "--forceX",
    ])
    def test_stock_spelling_truncation_rejected(self, bogus, tmp_path):
        res = _run([bogus], tmp_path)
        assert res.returncode == USAGE_ERROR, (bogus, res.returncode,
                                               res.stderr)
        assert "unknown option" in res.stderr

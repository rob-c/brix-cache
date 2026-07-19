"""
test_client_compat_naming.py — the brix-cache-client-compat identity contract.

The compat package ships the SAME name-agnostic client binaries as
brix-cache-client under a "brix-" prefix (brix-xrdcp, brix-xrdfs, …) so they
co-install with the official xrootd-client tools. This module pins the runtime
half of that contract — that every tool self-identifies from argv[0] — WITHOUT
touching or rewiring any existing test (the stock client/bin/<name> tools and
their oracles stay exactly as they are).

Three assertion classes per the change governance:

  SUCCESS / SELF-ID  — a brix- tool prints its OWN name in usage/version/footer
                       (never the stock name), multi-call personalities dispatch
                       through the prefix, and the xrd umbrella execs prefixed
                       siblings.
  ERROR-GOLDEN       — a bad-arg invocation still exits non-zero, and the stock
                       xrd umbrella is unaffected (still execs the stock sibling).
  SECURITY-NEG       — the FUSE mounts are NOT prefixed (compat never shadows a
                       FUSE tool), and no identity surface leaks the stock name.

Fleet-free: every check runs a local binary with --help / --version / a bad arg
or a checksum over a temp file. The compat links are produced on demand via the
Makefile `compat` target; if the client tree is not built the module skips.
"""

import os
import subprocess

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CLIENT = os.path.join(_REPO, "client")
_BIN = os.path.join(_CLIENT, "bin")

# Core CLI tools whose prefixed aliases must self-identify. Personalities
# (adler32) are covered separately by the dispatch test.
_CORE_TOOLS = [
    "xrdcp", "xrdfs", "xrdcksum", "xrddiag", "xrdmapc",
    "xrdgsiproxy", "xrdgsitest", "xrdstorascan", "xrdqstats",
]


def _run(name, *args, timeout=10):
    """Run client/bin/<name> with *args; return (rc, stdout, stderr)."""
    r = subprocess.run(
        [os.path.join(_BIN, name), *args],
        capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


@pytest.fixture(scope="module", autouse=True)
def _ensure_compat_links():
    """Produce the brix- prefixed links via `make compat`; skip if unbuilt."""
    if not os.path.exists(os.path.join(_BIN, "xrdcp")):
        pytest.skip("client tools not built (run `make -C client`)")
    if not os.path.exists(os.path.join(_BIN, "brix-xrdcp")):
        subprocess.run(
            ["make", "-C", _CLIENT, "compat"],
            check=True, capture_output=True, text=True, timeout=120,
        )
    if not os.path.exists(os.path.join(_BIN, "brix-xrdcp")):
        pytest.skip("`make -C client compat` did not produce brix- links")


def _usage_header(out, err):
    """The first 'usage:' line across stdout+err, or '' if none."""
    for line in (out + err).splitlines():
        if line.lstrip().startswith("usage:"):
            return line.strip()
    return ""


# ---------------------------------------------------------------------------
# SUCCESS / SELF-ID
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tool", _CORE_TOOLS)
def test_version_banner_self_ids_as_brix(tool):
    """`brix-<tool> --version` names the prefixed alias, never the stock tool."""
    rc, out, err = _run(f"brix-{tool}", "--version")
    assert rc == 0, (rc, out, err)
    first = (out + err).strip().splitlines()[0]
    assert first.startswith(f"brix-{tool} "), first
    # The bare stock name must not be the program identity.
    assert not first.startswith(f"{tool} "), first


@pytest.mark.parametrize("tool", _CORE_TOOLS)
def test_usage_header_self_ids_as_brix(tool):
    """`brix-<tool> --help` prints `usage: brix-<tool> …`, not the stock name."""
    rc, out, err = _run(f"brix-{tool}", "--help")
    header = _usage_header(out, err)
    assert header.startswith(f"usage: brix-{tool}"), (header, rc)


def test_footer_names_the_invoked_alias():
    """The man-page footer references `man brix-xrdcp`, not `man xrdcp`."""
    _, out, err = _run("brix-xrdcp", "--help")
    blob = out + err
    assert "man brix-xrdcp" in blob, blob
    assert "man xrdcp " not in blob and "man xrdcp\n" not in blob, blob


# ---------------------------------------------------------------------------
# SUCCESS — multi-call personality dispatch through the prefix
# ---------------------------------------------------------------------------
def test_personality_dispatch_adler32(tmp_path):
    """`brix-xrdadler32` behaves as the adler32 personality (prefix stripped)."""
    f = tmp_path / "data.bin"
    f.write_bytes(b"brix-compat-adler32\n" * 64)

    rc_b, out_b, err_b = _run("brix-xrdadler32", str(f))
    assert rc_b == 0, (rc_b, out_b, err_b)
    # Identical result to the stock personality — dispatch stripped "brix-".
    rc_s, out_s, _ = _run("xrdadler32", str(f))
    assert rc_s == 0
    assert out_b.split()[0] == out_s.split()[0], (out_b, out_s)
    # An 8-hex-digit adler32 over the file, and the path echoed back.
    checksum = out_b.split()[0]
    assert len(checksum) == 8 and int(checksum, 16) >= 0, out_b


def test_personality_dispatch_qstats_self_ids():
    """`brix-xrdqstats --help` routes to the qstats personality under the prefix."""
    rc, out, err = _run("brix-xrdqstats", "--help")
    assert rc == 0, (rc, out, err)
    assert _usage_header(out, err).startswith("usage: brix-xrdqstats"), (out, err)


# ---------------------------------------------------------------------------
# SUCCESS — sibling exec resolves the prefixed sibling
# ---------------------------------------------------------------------------
def test_umbrella_execs_prefixed_sibling():
    """`brix-xrd cp --help` execs brix-xrdcp; the child self-IDs as brix-xrdcp."""
    rc, out, err = _run("brix-xrd", "cp", "--help")
    header = _usage_header(out, err)
    assert header.startswith("usage: brix-xrdcp"), (header, rc)


# ---------------------------------------------------------------------------
# ERROR-GOLDEN
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tool", ["xrdcp", "xrdfs", "xrdmapc", "xrdstorascan"])
def test_bad_arg_exits_nonzero(tool):
    """A bad-arg invocation of a brix- tool still fails cleanly (non-zero)."""
    rc, out, err = _run(f"brix-{tool}", "--definitely-not-a-flag")
    assert rc != 0, (tool, rc, out, err)


def test_stock_umbrella_unaffected():
    """The stock `xrd cp --help` still execs the stock xrdcp (no prefix leak)."""
    rc, out, err = _run("xrd", "cp", "--help")
    header = _usage_header(out, err)
    assert header.startswith("usage: xrdcp"), (header, rc)
    assert not header.startswith("usage: brix-"), header


# ---------------------------------------------------------------------------
# SECURITY-NEG
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fuse", ["brix-xrootdfs", "brix-brixMount", "brix-brixmount"])
def test_fuse_tools_are_not_prefixed(fuse):
    """Compat never shadows a FUSE mount — no brix-<fuse> alias is produced."""
    assert not os.path.exists(os.path.join(_BIN, fuse)), fuse


def test_no_stock_identity_leak_in_version():
    """No prefixed tool's --version line prints the bare stock name as identity."""
    leaks = []
    for tool in _CORE_TOOLS:
        _, out, err = _run(f"brix-{tool}", "--version")
        first = (out + err).strip().splitlines()[0]
        if not first.startswith(f"brix-{tool} "):
            leaks.append((tool, first))
    assert not leaks, leaks

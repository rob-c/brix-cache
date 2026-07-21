"""Guards for the CMS-mesh SSS keytab tool: naming, resolution, and mint format.

The fail-closed ``sss_mgr`` mesh topology needs an SSS keytab, minted by the
clean-room ``xrdsssadmin-brix`` tool.  Two things kept it from ever launching on
a stock box, and this file pins both fixes:

* **naming/resolution** — the tool ships as ``xrdsssadmin-brix`` (the ``-brix``
  suffix is what keeps the brix client RPM co-installable with the stock xrootd
  *server* package, which owns ``/usr/bin/xrdsssadmin``).  ``cms_mesh_lib`` used
  to resolve a bare ``xrdsssadmin-brix`` on PATH only — absent in a dev checkout,
  so the manager was silently skipped.  Resolution now spans a ``TEST_*_BIN``
  override, the in-tree build, and the RPM-installed binary on PATH;
* **CLI shape** — the brix tool has its own interface (``add`` + ``-k/--keytab``
  + ``--user/--group/--name/--id``), NOT the stock tool's flags; the mint call
  must speak it, and the emitted keytab must be the text format nginx's SSS
  parser reads.
"""

from __future__ import annotations

import os
import re

import pytest

import cms_mesh_lib as lib
from cmdscripts import fake_exec


# A minted keytab entry: `<off> u:<user> g:<group> N:<id> k:<64 hex> n:<name>`.
_KEYTAB_LINE = re.compile(
    r"^\d+\s+u:\S+\s+g:\S+\s+N:\d+\s+k:[0-9a-f]{64}\s+n:\S+\s*$"
)


def _have_sssadmin() -> bool:
    return lib._ensure_sssadmin() is not None


def test_sssadmin_binary_is_brix_suffixed_not_stock():
    """The resolved tool is the ``-brix`` build, never the stock ``xrdsssadmin``.

    The whole point of the rename is co-installability with the stock xrootd
    server RPM; resolving the bare stock binary would pick up an incompatible
    CLI and mis-mint the keytab.
    """
    assert lib.XRDSSSADMIN_BIN.endswith("xrdsssadmin-brix")
    if not _have_sssadmin():
        pytest.skip("xrdsssadmin-brix unavailable/unbuildable on this box")
    assert os.path.basename(lib._ensure_sssadmin()) == "xrdsssadmin-brix"


def test_gen_sss_keytab_emits_the_nginx_sss_format(tmp_path):
    """A minted keytab is 0600 and in the exact text shape nginx's parser reads."""
    if not _have_sssadmin():
        pytest.skip("xrdsssadmin-brix unavailable/unbuildable on this box")

    kt = lib.gen_sss_keytab(str(tmp_path / "cfg" / "cms.keytab"))
    assert kt is not None and os.path.exists(kt), "keytab was not minted"
    assert (os.stat(kt).st_mode & 0o777) == 0o600, "keytab must be private (0600)"

    lines = [ln for ln in open(kt).read().splitlines() if ln.strip()]
    assert lines, "keytab is empty"
    for ln in lines:
        assert _KEYTAB_LINE.match(ln), f"unexpected keytab line: {ln!r}"
    # The mesh mints the cms node identity — assert the fields we asked for.
    assert "u:cmsnode" in lines[0] and "g:cms" in lines[0]


def test_gen_sss_keytab_returns_existing_without_reminting(tmp_path):
    """An already-present keytab is returned verbatim — no rebuild, no clobber."""
    if not _have_sssadmin():
        pytest.skip("xrdsssadmin-brix unavailable/unbuildable on this box")

    path = tmp_path / "cms.keytab"
    path.write_text("0 u:sentinel g:sentinel N:1 k:%s n:sentinel\n" % ("a" * 64))
    before = path.read_text()

    kt = lib.gen_sss_keytab(str(path))
    assert kt == str(path)
    assert path.read_text() == before, "existing keytab must not be overwritten"


def test_sssadmin_resolution_precedence(monkeypatch, tmp_path):
    """TEST_XRDSSSADMIN_BIN overrides; a missing override resolves to None.

    Pins the ``match the rpm`` resolution contract: an explicit override wins,
    and an override pointing at nothing is a hard miss (rather than silently
    falling through to some other binary).
    """
    # A resolvable executable (never run — only its path resolution is asserted).
    stub = fake_exec.install(tmp_path, "xrdsssadmin-brix")

    monkeypatch.setenv("TEST_XRDSSSADMIN_BIN", stub)
    assert lib._find_sssadmin() == stub

    monkeypatch.setenv("TEST_XRDSSSADMIN_BIN", str(tmp_path / "nope"))
    assert lib._find_sssadmin() is None

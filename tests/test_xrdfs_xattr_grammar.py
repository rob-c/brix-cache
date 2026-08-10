"""xrdfs xattr stock-grammar acceptance (parity-audit §7.12).

Stock xrdfs spells xattr ops `xattr <path> <code> <params>` with codes
set/get/del/list (set takes a single `name=value`); BriX spells them
`xattr <code> <path> ...` with set/get/rm/ls.  A stock-form invocation
(`xattr /f set a=b`) used to be silently mis-read as a bare LIST of `/f`.
BriX now accepts the stock form as a drop-in alias, disambiguated by the
first token: a BriX subcommand keeps BriX semantics, otherwise a path
followed by a stock code is the stock form.

  * success   — a full stock-form set/get/list/del round-trip works, and the
                value set via the stock form reads back via BOTH grammars
  * error     — stock `set` without `name=value` is a clean usage error; a
                bare `xattr <path>` still lists (unchanged)
  * disambiguation — `xattr get <path> <name>` (BriX) and
                `xattr <path> get <name>` (stock) BOTH read the same attribute

Run:
    PYTHONPATH=tests pytest tests/test_xrdfs_xattr_grammar.py -v
"""

import os
import subprocess

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(60),
    pytest.mark.skipif(not os.path.exists(XRDFS),
                       reason="brix-xrdfs not built (client/bin/xrdfs)"),
]

NAME = "xattr-grammar.bin"


@pytest.fixture()
def staged():
    os.makedirs(DATA_ROOT, exist_ok=True)
    p = os.path.join(DATA_ROOT, NAME)
    with open(p, "wb") as f:
        f.write(b"xattr grammar probe\n")
    yield "/" + NAME
    try:
        os.remove(p)
    except FileNotFoundError:
        pass


def _fs(*args):
    return subprocess.run([XRDFS, URL, *args],
                          capture_output=True, text=True, timeout=30)


class TestStockGrammar:

    def test_stock_roundtrip(self, staged):
        """(success) stock set/get/list/del all work in the `path first` form."""
        assert _fs("xattr", staged, "set", "user.prov=run42").returncode == 0
        got = _fs("xattr", staged, "get", "user.prov")
        assert got.returncode == 0 and got.stdout.strip() == "run42", got

        lst = _fs("xattr", staged, "list")
        assert lst.returncode == 0 and "user.prov" in lst.stdout, lst

        assert _fs("xattr", staged, "del", "user.prov").returncode == 0
        after = _fs("xattr", staged, "list")
        assert "user.prov" not in after.stdout, after

    def test_both_grammars_read_same_attr(self, staged):
        """(disambiguation) a value set via the stock form reads back through
        BOTH the stock (`<path> get`) and BriX (`get <path>`) spellings."""
        assert _fs("xattr", staged, "set", "user.k=shared").returncode == 0
        stock = _fs("xattr", staged, "get", "user.k")
        brix = _fs("xattr", "get", staged, "user.k")
        assert stock.stdout.strip() == "shared", stock
        assert brix.stdout.strip() == "shared", brix


class TestBrixGrammarRegression:

    def test_brix_form_unchanged(self, staged):
        """(regression) BriX's own `xattr <code> <path>` form is untouched."""
        assert _fs("xattr", "set", staged, "user.bx", "qux").returncode == 0
        got = _fs("xattr", "get", staged, "user.bx")
        assert got.stdout.strip() == "qux", got
        assert _fs("xattr", "rm", staged, "user.bx").returncode == 0

    def test_bare_path_lists(self, staged):
        """(unchanged) `xattr <path>` with no code still lists attributes."""
        _fs("xattr", "set", staged, "user.a", "1")
        res = _fs("xattr", staged)
        assert res.returncode == 0 and "user.a" in res.stdout, res


class TestErrors:

    def test_stock_set_without_equals(self, staged):
        """(error) stock `set` requires name=value — a bare name is a clean
        usage error, not a silent mis-parse."""
        res = _fs("xattr", staged, "set", "user.noeq")
        assert res.returncode == 50
        assert "name=value" in res.stderr

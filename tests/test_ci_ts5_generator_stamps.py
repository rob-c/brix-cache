"""The fleet-prep cache must stamp the code that actually mints the artifacts.

`brix_suite.prep_steps` caches a prepared PKI + token tree and restores it when
nothing that generates it has changed.  "Nothing has changed" is decided by
`_generator_stamps()` over `_GENERATOR_SOURCES` — mtime and size of each
generator source.

The TS-5 moves broke that premise without breaking anything visible.  Once
`tokenforge.py` became a §10.2 shim, stamping it reported "unchanged" for every
edit inside `brix_suite/security/tokens/`: a lane would restore a token tree
built by the *previous* generator, with every sentinel file present, every
mtime plausible, and no step reporting a thing.  These tests pin the fix and,
more importantly, fail the next time a generator moves out from under its flat
spelling.
"""

from pathlib import Path

import pytest

import brix_suite.prep_steps as prep_steps

#: The line a §10.2 shim ends on.  A file carrying it holds no logic, so its
#: mtime says nothing about what the generator will produce.
def _check_test_the_moved_token_generator_is_stamped_module_by_module_1(names):
    assert names == {"__main__.py", "claims.py", "issuer_cfg.py", "jose.py",
                     "manifest.py", "mint.py", "signing.py"}

def _check_test_the_moved_token_generator_is_stamped_module_by_module_2(flat):
    assert flat == [], "the shim is stamped again; edits to the package are invisible"


_SHIM_MARK = "_sys.modules[__name__] = _canonical"


def test_every_generator_source_is_a_real_file():
    """A path to nothing stamps nothing, and stamps nothing *silently*."""
    missing = [p for p in prep_steps._GENERATOR_SOURCES if not p.is_file()]
    assert missing == []


def test_the_moved_token_generator_is_stamped_module_by_module():
    """The whole `security/tokens` package, not the shim that fronts it."""
    names = {p.name for p in prep_steps._GENERATOR_SOURCES if p.parent.name == "tokens"}
    _check_test_the_moved_token_generator_is_stamped_module_by_module_1(names)
    flat = [p for p in prep_steps._GENERATOR_SOURCES if p.name == "tokenforge.py"]
    _check_test_the_moved_token_generator_is_stamped_module_by_module_2(flat)


def test_no_generator_source_is_a_shim():
    """The regression, stated as a rule rather than as one file's name.

    This is the test that will fail when `pki_helpers.py` — or any other
    generator — moves into a package and leaves a shim behind.
    """
    shims = [p for p in prep_steps._GENERATOR_SOURCES
             if _SHIM_MARK in p.read_text(encoding="utf-8")]
    assert shims == [], f"stamping a §10.2 shim reports 'unchanged' forever: {shims}"


def test_stamp_keys_do_not_collide():
    """Two generators sharing a basename must not fold into one stamp.

    The sources stopped being siblings when the packages arrived; a `mint.py`
    under `tokens/` and a `mint.py` under some future `kdc/` would have
    collapsed to a single key under the old `p.name` scheme, dropping one
    generator out of the cache key entirely.
    """
    stamps = prep_steps._generator_stamps()
    assert len(stamps) == len(prep_steps._GENERATOR_SOURCES)


def test_a_package_expands_to_its_modules_but_not_its_facade(tmp_path):
    pkg = tmp_path / "widgets"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("from .a import *\n")
    (pkg / "a.py").write_text("A = 1\n")
    (pkg / "b.py").write_text("B = 1\n")
    (pkg / "notes.txt").write_text("not source\n")

    assert prep_steps._sources(pkg) == (pkg / "a.py", pkg / "b.py")
    assert prep_steps._sources(pkg / "a.py") == (pkg / "a.py",)


def test_an_edit_inside_a_moved_generator_still_busts_the_cache(tmp_path, monkeypatch):
    """The security-negative: a stale generator can never be served from cache.

    A token generator whose semantics changed — a claim dropped, an algorithm
    swapped, a scope widened — must not be able to hand back a tree minted
    under the old rules.  With the shim stamped, this is exactly what happened
    and nothing in the suite could see it.
    """
    pkg = tmp_path / "tokens"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "mint.py").write_text("SCOPE = 'storage.read:/'\n")
    monkeypatch.setattr(prep_steps, "_GENERATOR_SOURCES", prep_steps._sources(pkg))

    before = prep_steps._generator_stamps()
    (pkg / "mint.py").write_text("SCOPE = 'storage.modify:/'\n")
    assert prep_steps._generator_stamps() != before


def test_a_shim_in_front_of_that_package_would_not_have_noticed(tmp_path, monkeypatch):
    """The same edit, stamped the old way: no change reported.

    Kept as the counter-example the fix exists for — it documents that the
    failure mode is silence, not an error.
    """
    shim = tmp_path / "tokenforge.py"
    shim.write_text("import brix_suite.security.tokens as _c\n" + _SHIM_MARK + "\n")
    pkg = tmp_path / "tokens"
    pkg.mkdir()
    (pkg / "mint.py").write_text("SCOPE = 'storage.read:/'\n")
    monkeypatch.setattr(prep_steps, "_GENERATOR_SOURCES", (shim,))

    before = prep_steps._generator_stamps()
    (pkg / "mint.py").write_text("SCOPE = 'storage.modify:/'\n")
    assert prep_steps._generator_stamps() == before

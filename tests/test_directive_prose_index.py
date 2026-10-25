"""The release prose gate indexes exactly the original whole-token matches."""

import pytest

from test_release20_directive_surface import _documented_directive_names


@pytest.mark.parametrize("text,expected", [
    ("Use `brix_cache` and brix_auth; then brix_cache.", {"brix_cache", "brix_auth"}),
    ("No directive names appear here.", set()),
    ("xbrix_cache brix_cache_extra brix_cacheé ébrix_auth", {"brix_cache_extra"}),
    ("brix_cache1 brix_cache_2", {"brix_cache1", "brix_cache_2"}),
])
def test_prose_index_preserves_word_boundaries(text, expected):
    """Adjacent identifier or Unicode word characters cannot document a knob."""
    assert _documented_directive_names(text) == expected

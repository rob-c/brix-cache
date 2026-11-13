"""Reference-client wording changes must preserve differential error classes."""

import pytest

from official_interop_lib import err_code


def test_empty_output_has_no_error():
    assert err_code("") == "ok"


@pytest.mark.parametrize("message", [
    "[3018] file already exists (destination)",
    "[3018] Unable to create /target; file exists (destination)",
])
def test_existing_destination_wording_has_one_category(message):
    assert err_code(message) == "exists"


def test_permission_denial_does_not_become_an_existing_destination():
    assert err_code("[3010] permission denied") == "permission"

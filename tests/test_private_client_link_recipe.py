"""Private links ignore make diagnostics and require exactly one executable recipe."""

from pathlib import Path

import pytest

from test_xrd_dispatch_native import private_link_command


def test_make_directory_banner_does_not_enter_shell_parsing():
    plan = "make: Entering directory `/fixture/client'\ncc main.o -o /tmp/private/xrd\n"
    assert private_link_command(plan, Path('/tmp/private/xrd')) == ['cc', 'main.o', '-o', '/tmp/private/xrd']


def test_unrelated_quoted_diagnostic_and_compile_recipe_are_not_executable_links():
    plan = "note: compiler's optional feature is disabled\ncc -c main.c -o /tmp/private/xrd\n"
    with pytest.raises(AssertionError):
        private_link_command(plan, Path('/tmp/private/xrd'))


def test_two_executable_recipes_are_rejected_instead_of_selecting_one():
    plan = 'cc first.o -o /tmp/private/xrd\ncc second.o -o /tmp/private/xrd\n'
    with pytest.raises(AssertionError):
        private_link_command(plan, Path('/tmp/private/xrd'))

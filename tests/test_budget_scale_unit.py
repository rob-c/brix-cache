"""``lib_py.util.budget_scale``: the wall-clock multiplier tests apply to
their fixed budgets on a slower or shared host (``TEST_BUDGET_SCALE``)."""
import os
from unittest import mock

from lib_py.util import budget_scale


def test_the_reference_host_scales_by_one():
    """success: unset ⇒ 1.0, budgets are exactly what the file says."""
    with mock.patch.dict(os.environ, {}, clear=True):
        assert budget_scale() == 1.0


def test_an_operator_multiplier_is_honoured():
    """success: the knob stretches every budget that reads it."""
    with mock.patch.dict(os.environ, {"TEST_BUDGET_SCALE": "5"}, clear=True):
        assert budget_scale() == 5.0


def test_garbage_or_zero_never_shrinks_a_budget():
    """security-negative: a typo or a zero cannot turn a budget into an
    instant failure — both fall back to the reference multiplier."""
    for bad in ("banana", "0", "-2"):
        with mock.patch.dict(os.environ, {"TEST_BUDGET_SCALE": bad}, clear=True):
            assert budget_scale() == 1.0, bad

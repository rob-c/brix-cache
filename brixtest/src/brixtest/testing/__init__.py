"""Contract kits: reusable obligation checks an adapter runs against
its own registrations.  These are the only core modules besides the
harness that import pytest — an adapter that registers a kind or a
backend points a test file at the matching kit and inherits the
core's expectations as executable cases."""

from brixtest.testing.backend_contract import check_backend_contract
from brixtest.testing.extension_contract import (
    assert_extension_contract,
    check_extension_capabilities,
)
from brixtest.testing.kind_contract import check_kind_contract
from brixtest.testing.runtime_contracts import (
    check_case_backend_contract,
    check_executor_contract,
    check_launcher_contract,
    check_managed_resource_provider_contract,
    check_provider_contract,
)

__all__ = [
    "assert_extension_contract", "check_backend_contract", "check_case_backend_contract",
    "check_extension_capabilities",
    "check_executor_contract", "check_kind_contract", "check_launcher_contract",
    "check_managed_resource_provider_contract", "check_provider_contract",
]

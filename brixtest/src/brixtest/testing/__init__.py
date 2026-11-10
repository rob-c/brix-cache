"""Testing utilities for BrixTest - dependency injection over monkeypatching.

This module provides configuration objects and interfaces for writing tests
without monkeypatching. The goal is to make dependencies explicit and tests
more maintainable.

Usage:
    from brixtest.testing import test_config, FakeCommandRunner, FakeToolProvider
    
    # Create test configuration
    config = test_config(oci_registry="registry.test/team")
    
    # Create fake dependencies
    runner = FakeCommandRunner(returncode=0, stdout="output")
    tools = FakeToolProvider({"kubectl": "/fake/kubectl"})
    
    # Inject into code under test
    executor = CommandExecutor(runner=runner)
    manager = KubernetesManager(tools=tools)
"""

from brixtest.testing.config import BrixTestConfig, test_config
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
from brixtest.testing.interfaces import (
    # Protocols
    BinaryFinder,
    BundleBuilder,
    Clock,
    CommandRunner,
    FileSystem,
    HTTPClient,
    PortAllocator,
    Reservation,
    RuntimeExecutor,
    ToolProvider,
    # Fake implementations
    FakeBinaryFinder,
    FakeClock,
    FakeCommandRunner,
    FakeFileSystem,
    FakeHTTPClient,
    FakePortAllocator,
    FakeReservation,
    FakeResponse,
    FakeToolProvider,
)

__all__ = [
    "check_backend_contract",
    "assert_extension_contract",
    "check_extension_capabilities",
    "check_case_backend_contract",
    "check_executor_contract",
    "check_kind_contract",
    "check_launcher_contract",
    "check_managed_resource_provider_contract",
    "check_provider_contract",
    # Config
    "BrixTestConfig",
    "test_config",
    # Protocols
    "BinaryFinder",
    "BundleBuilder",
    "Clock",
    "CommandRunner",
    "FileSystem",
    "HTTPClient",
    "PortAllocator",
    "Reservation",
    "RuntimeExecutor",
    "ToolProvider",
    # Fakes
    "FakeBinaryFinder",
    "FakeClock",
    "FakeCommandRunner",
    "FakeFileSystem",
    "FakeHTTPClient",
    "FakePortAllocator",
    "FakeReservation",
    "FakeResponse",
    "FakeToolProvider",
]

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

"""Core interfaces for dependency injection - replace monkeypatching.

This module defines protocols (interfaces) for external dependencies that were
previously monkeypatched. Tests can provide fake implementations of these
interfaces instead of monkeypatching module-level functions.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class CommandRunner(Protocol):
    """Interface for running commands - replaces subprocess.run monkeypatching.
    
    Example fake implementation for tests:
    
        class FakeCommandRunner:
            def __init__(self):
                self.calls = []
            
            def run(self, args, **kwargs):
                self.calls.append((args, kwargs))
                return subprocess.CompletedProcess(args, 0, "output", "")
    """
    
    def run(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        ...


@runtime_checkable
class ToolProvider(Protocol):
    """Interface for providing tool paths - replaces _tool monkeypatching.
    
    Example fake implementation for tests:
    
        class FakeToolProvider:
            def get_tool(self, name: str) -> str:
                return f"/fake/path/to/{name}"
    """
    
    def get_tool(self, name: str) -> str:
        """Get the path to a tool by name."""
        ...


@runtime_checkable
class BinaryFinder(Protocol):
    """Interface for finding binaries - replaces shutil.which monkeypatching.
    
    Example fake implementation for tests:
    
        class FakeBinaryFinder:
            def find(self, name: str) -> Optional[str]:
                return f"/usr/bin/{name}"
    """
    
    def find(self, name: str) -> Optional[str]:
        """Find a binary by name, returning its path or None."""
        ...


@runtime_checkable
class PortAllocator(Protocol):
    """Interface for allocating ports - replaces _free_port monkeypatching.
    
    Example fake implementation for tests:
    
        class FakePortAllocator:
            def __init__(self, base_port: int = 18488):
                self.base_port = base_port
                self.counter = 0
            
            def allocate(self, requested: int) -> tuple[int, Reservation]:
                port = self.base_port + self.counter
                self.counter += 1
                return (port, FakeReservation())
    """
    
    def allocate(self, requested: int) -> tuple[int, Reservation]:
        """Allocate a port, returning (port, reservation)."""
        ...


class Reservation:
    """A port reservation that can be closed."""
    
    def close(self) -> None:
        """Release the reserved port."""
        pass


class FakeReservation(Reservation):
    """Fake reservation for testing."""
    
    def close(self) -> None:
        pass


@runtime_checkable
class FileSystem(Protocol):
    """Interface for filesystem operations - replaces Path monkeypatching.
    
    Example fake implementation for tests:
    
        class FakeFileSystem:
            def __init__(self):
                self.files = {}
            
            def read_text(self, path: Path) -> str:
                return self.files.get(str(path), "")
            
            def write_text(self, path: Path, content: str) -> None:
                self.files[str(path)] = content
    """
    
    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        """Read text from a file."""
        ...
    
    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
        """Write text to a file."""
        ...
    
    def exists(self, path: Path) -> bool:
        """Check if a path exists."""
        ...
    
    def is_dir(self, path: Path) -> bool:
        """Check if a path is a directory."""
        ...


@runtime_checkable
class HTTPClient(Protocol):
    """Interface for HTTP operations - replaces urllib.request.urlopen monkeypatching.
    
    Example fake implementation for tests:
    
        class FakeHTTPClient:
            def open(self, request, timeout=None):
                return FakeResponse(b"response body")
    """
    
    def open(self, request: Any, timeout: Optional[float] = None) -> Any:
        """Open a URL and return a response."""
        ...


@runtime_checkable
class Clock(Protocol):
    """Interface for time operations - replaces time.sleep monkeypatching.
    
    Example fake implementation for tests:
    
        class FakeClock:
            def __init__(self):
                self.current_time = 0.0
                self.sleep_calls = []
            
            def sleep(self, seconds: float) -> None:
                self.sleep_calls.append(seconds)
                self.current_time += seconds
            
            def time(self) -> float:
                return self.current_time
    """
    
    def sleep(self, seconds: float) -> None:
        """Sleep for the specified duration."""
        ...
    
    def time(self) -> float:
        """Get the current time."""
        ...


@runtime_checkable
class BundleBuilder(Protocol):
    """Interface for building helper bundles - replaces build_helper_bundle monkeypatching.
    
    Example fake implementation for tests:
    
        class FakeBundleBuilder:
            def build(self, project_root, test_spec, output_dir):
                return FakeBundle()
    """
    
    def build(self, project_root: Path, test_spec: str, output_dir: Path) -> Any:
        """Build a helper bundle, returning bundle info."""
        ...


@runtime_checkable
class RuntimeExecutor(Protocol):
    """Interface for runtime execution - replaces _run monkeypatching.
    
    Example fake implementation for tests:
    
        class FakeRuntimeExecutor:
            def execute(self, command, env, **options):
                self.calls.append((command, env))
                return ""
    """
    
    def execute(self, command: list[str], env: dict[str, str], **options: Any) -> str:
        """Execute a command in the runtime environment."""
        ...


# Concrete fake implementations for common test scenarios

class FakeCommandRunner:
    """Fake command runner for testing."""
    
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
    
    def run(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        self.calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, self.stderr)


class FakeToolProvider:
    """Fake tool provider for testing."""
    
    def __init__(self, tools: Optional[dict[str, str]] = None):
        self.tools = tools or {}
        self.calls: list[str] = []
    
    def get_tool(self, name: str) -> str:
        self.calls.append(name)
        return self.tools.get(name, f"/fake/tool/{name}")


class FakeBinaryFinder:
    """Fake binary finder for testing."""
    
    def __init__(self, binaries: Optional[dict[str, str]] = None):
        self.binaries = binaries or {}
        self.calls: list[str] = []
    
    def find(self, name: str) -> Optional[str]:
        self.calls.append(name)
        return self.binaries.get(name, f"/usr/bin/{name}")


class FakePortAllocator:
    """Fake port allocator for testing."""
    
    def __init__(self, base_port: int = 18488):
        self.base_port = base_port
        self.counter = 0
        self.calls: list[int] = []
    
    def allocate(self, requested: int) -> tuple[int, Reservation]:
        self.calls.append(requested)
        port = self.base_port + self.counter
        self.counter += 1
        return (port, FakeReservation())


class FakeFileSystem:
    """Fake filesystem for testing."""
    
    def __init__(self, files: Optional[dict[str, str]] = None):
        self.files = files or {}
        self.read_calls: list[Path] = []
        self.write_calls: list[tuple[Path, str]] = []
    
    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        self.read_calls.append(path)
        return self.files.get(str(path), "")
    
    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
        self.write_calls.append((path, content))
        self.files[str(path)] = content
    
    def exists(self, path: Path) -> bool:
        return str(path) in self.files
    
    def is_dir(self, path: Path) -> bool:
        # Simple heuristic: if it has no extension, treat as directory
        return path.suffix == "" and any(f.startswith(str(path) + "/") for f in self.files)


class FakeClock:
    """Fake clock for testing."""
    
    def __init__(self, start_time: float = 0.0):
        self.current_time = start_time
        self.sleep_calls: list[float] = []
    
    def sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)
        self.current_time += seconds
    
    def time(self) -> float:
        return self.current_time


class FakeHTTPClient:
    """Fake HTTP client for testing."""
    
    def __init__(self, responses: Optional[dict[str, bytes]] = None):
        self.responses = responses or {}
        self.calls: list[Any] = []
    
    def open(self, request: Any, timeout: Optional[float] = None) -> Any:
        self.calls.append(request)
        url = request if isinstance(request, str) else request.full_url
        return FakeResponse(self.responses.get(url, b""))


class FakeResponse:
    """Fake HTTP response for testing."""
    
    def __init__(self, body: bytes):
        self.body = body
    
    def read(self) -> bytes:
        return self.body


__all__ = [
    # Protocols
    "CommandRunner",
    "ToolProvider",
    "BinaryFinder",
    "PortAllocator",
    "Reservation",
    "FileSystem",
    "HTTPClient",
    "Clock",
    "BundleBuilder",
    "RuntimeExecutor",
    # Fake implementations
    "FakeCommandRunner",
    "FakeToolProvider",
    "FakeBinaryFinder",
    "FakePortAllocator",
    "FakeReservation",
    "FakeFileSystem",
    "FakeClock",
    "FakeHTTPClient",
    "FakeResponse",
]

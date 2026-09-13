"""Test configuration objects - replace environment variable monkeypatching.

This module provides configuration dataclasses that replace the need for
monkeypatching environment variables in tests. Tests can pass explicit
configuration objects instead of modifying the process environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class BrixTestConfig:
    """Configuration for BrixTest test execution.
    
    This configuration object replaces environment variable monkeypatching.
    Tests should pass explicit config objects rather than using monkeypatch.setenv.
    
    Attributes:
        oci_registry: OCI registry for container images (BRIXTEST_OCI_REGISTRY)
        oci_base_image: Base image for containers (BRIXTEST_OCI_BASE_IMAGE)
        runs_dir: Directory for test runs (BRIXTEST_RUNS)
        metrics_session: Session ID for metrics (BRIXTEST_METRICS_SESSION)
        binary_overrides_json: JSON string for binary overrides (BRIXTEST_BINARY_OVERRIDES_JSON)
        client_env_json: JSON string for client environment (BRIXTEST_CLIENT_ENV_JSON)
        search_bearer_token: Bearer token for search operations (BRIXTEST_SEARCH_BEARER_TOKEN)
        minikube_profile: Minikube profile name (BRIXTEST_MINIKUBE_PROFILE)
        minikube_cpus: Number of CPUs for Minikube (BRIXTEST_MINIKUBE_CPUS)
        minikube_memory_mb: Memory in MB for Minikube (BRIXTEST_MINIKUBE_MEMORY_MB)
        heartbeat_timeout: Heartbeat timeout in seconds (BRIXTEST_HEARTBEAT_TIMEOUT)
        unit_ambient_secret: Ambient secret for unit tests (BRIXTEST_UNIT_AMBIENT_SECRET)
        replay_binaries_json: JSON for replay binaries (BRIXTEST_REPLAY_BINARIES_ENV)
        replay_graph_fingerprint: Graph fingerprint for replay (BRIXTEST_REPLAY_GRAPH_FINGERPRINT)
        internal_key: Internal key for security (BRIXTEST_INTERNAL_KEY)
        shared_servers_json: JSON for shared servers (BRIXTEST_SHARED_SERVERS_JSON)
    """
    
    oci_registry: Optional[str] = None
    oci_base_image: Optional[str] = None
    runs_dir: Optional[Path] = None
    metrics_session: Optional[Path] = None
    binary_overrides_json: Optional[str] = None
    client_env_json: Optional[str] = None
    search_bearer_token: Optional[str] = None
    minikube_profile: Optional[str] = None
    minikube_cpus: Optional[str] = None
    minikube_memory_mb: Optional[str] = None
    heartbeat_timeout: Optional[str] = None
    unit_ambient_secret: Optional[str] = None
    replay_binaries_json: Optional[str] = None
    replay_graph_fingerprint: Optional[str] = None
    internal_key: Optional[str] = None
    shared_servers_json: Optional[str] = None
    
    @classmethod
    def from_environment(cls) -> BrixTestConfig:
        """Create configuration from environment variables.
        
        This is the default behavior when no explicit config is provided.
        Maintains backward compatibility with existing code.
        """
        return cls(
            oci_registry=os.environ.get("BRIXTEST_OCI_REGISTRY"),
            oci_base_image=os.environ.get("BRIXTEST_OCI_BASE_IMAGE"),
            runs_dir=Path(os.environ["BRIXTEST_RUNS"]) if "BRIXTEST_RUNS" in os.environ else None,
            metrics_session=Path(os.environ["BRIXTEST_METRICS_SESSION"]) if "BRIXTEST_METRICS_SESSION" in os.environ else None,
            binary_overrides_json=os.environ.get("BRIXTEST_BINARY_OVERRIDES_JSON"),
            client_env_json=os.environ.get("BRIXTEST_CLIENT_ENV_JSON"),
            search_bearer_token=os.environ.get("BRIXTEST_SEARCH_BEARER_TOKEN"),
            minikube_profile=os.environ.get("BRIXTEST_MINIKUBE_PROFILE"),
            minikube_cpus=os.environ.get("BRIXTEST_MINIKUBE_CPUS"),
            minikube_memory_mb=os.environ.get("BRIXTEST_MINIKUBE_MEMORY_MB"),
            heartbeat_timeout=os.environ.get("BRIXTEST_HEARTBEAT_TIMEOUT"),
            unit_ambient_secret=os.environ.get("BRIXTEST_UNIT_AMBIENT_SECRET"),
            replay_binaries_json=os.environ.get("BRIXTEST_REPLAY_BINARIES_ENV"),
            replay_graph_fingerprint=os.environ.get("BRIXTEST_REPLAY_GRAPH_FINGERPRINT"),
            internal_key=os.environ.get("BRIXTEST_INTERNAL_KEY"),
            shared_servers_json=os.environ.get("BRIXTEST_SHARED_SERVERS_JSON"),
        )
    
    def with_overrides(self, **overrides) -> BrixTestConfig:
        """Create a new config with specified overrides.
        
        Args:
            **overrides: Keyword arguments to override in the new config.
            
        Returns:
            New BrixTestConfig instance with overrides applied.
        """
        return dataclass_replace(self, **overrides)
    
    def apply_to_environment(self) -> None:
        """Apply this configuration to the process environment.
        
        Only sets environment variables for non-None values.
        Use this sparingly - prefer passing config objects directly.
        """
        env_mapping = {
            "BRIXTEST_OCI_REGISTRY": self.oci_registry,
            "BRIXTEST_OCI_BASE_IMAGE": self.oci_base_image,
            "BRIXTEST_RUNS": str(self.runs_dir) if self.runs_dir else None,
            "BRIXTEST_METRICS_SESSION": str(self.metrics_session) if self.metrics_session else None,
            "BRIXTEST_BINARY_OVERRIDES_JSON": self.binary_overrides_json,
            "BRIXTEST_CLIENT_ENV_JSON": self.client_env_json,
            "BRIXTEST_SEARCH_BEARER_TOKEN": self.search_bearer_token,
            "BRIXTEST_MINIKUBE_PROFILE": self.minikube_profile,
            "BRIXTEST_MINIKUBE_CPUS": self.minikube_cpus,
            "BRIXTEST_MINIKUBE_MEMORY_MB": self.minikube_memory_mb,
            "BRIXTEST_HEARTBEAT_TIMEOUT": self.heartbeat_timeout,
            "BRIXTEST_UNIT_AMBIENT_SECRET": self.unit_ambient_secret,
            "BRIXTEST_REPLAY_BINARIES_ENV": self.replay_binaries_json,
            "BRIXTEST_REPLAY_GRAPH_FINGERPRINT": self.replay_graph_fingerprint,
            "BRIXTEST_INTERNAL_KEY": self.internal_key,
            "BRIXTEST_SHARED_SERVERS_JSON": self.shared_servers_json,
        }
        
        for env_var, value in env_mapping.items():
            if value is not None:
                os.environ[env_var] = value


# Helper for dataclass replacement (Python 3.10+ has dataclasses.replace)
def dataclass_replace(instance, **changes):
    """Replace fields in a dataclass instance."""
    from dataclasses import replace
    return replace(instance, **changes)


# Convenience function for creating test configs
def test_config(**overrides) -> BrixTestConfig:
    """Create a test configuration with the given overrides.
    
    This is the preferred way to create configs in tests.
    
    Example:
        >>> config = test_config(oci_registry="registry.test/team")
        >>> config = test_config(
        ...     oci_registry="registry.test/team",
        ...     oci_base_image="python@sha256:" + "a" * 64,
        ... )
    """
    return BrixTestConfig().with_overrides(**overrides)


__all__ = [
    "BrixTestConfig",
    "test_config",
]

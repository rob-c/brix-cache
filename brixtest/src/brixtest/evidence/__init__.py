"""Unified experiment evidence, analytics, and export primitives."""

from brixtest.evidence.collectors import (
    CollectorSpec,
    plugin as collector,
    kubernetes_events,
    process_tree,
    prometheus,
    structured_logs,
)
from brixtest.evidence.model import SCHEMA_VERSION, migrate_case, normalize_session
from brixtest.evidence.analysis import session_insights

__all__ = [
    "CollectorSpec",
    "SCHEMA_VERSION",
    "collector",
    "kubernetes_events",
    "migrate_case",
    "normalize_session",
    "process_tree",
    "prometheus",
    "session_insights",
    "structured_logs",
]

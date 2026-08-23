"""Stored test output, queryable run metadata, and HTML reports."""

from brixtest.results.collector import ResultCollector, new_run_id
from brixtest.results.model import Finding, PhaseResult, RunInfo, Sample, TestRecord
from brixtest.results.store import ResultStore

__all__ = [
    "Finding",
    "PhaseResult",
    "ResultCollector",
    "ResultStore",
    "RunInfo",
    "Sample",
    "TestRecord",
    "new_run_id",
]

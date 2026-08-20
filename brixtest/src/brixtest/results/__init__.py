"""Run intelligence (features F21–F23): every test's full output and
context captured to disk, every run catalogued in a queryable store,
and a portal that renders it — turning BriXTest from a test runner
into a test/result management suite."""

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

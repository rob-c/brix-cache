"""Read explicitly re-exported PAL cases without importing platform APIs."""

import ast
from pathlib import Path


def coverage_source(test_file: Path) -> str:
    """Keep a test entry point and its case groups one coverage-report unit.

    The entry points re-export fixtures and classes with ordinary imports.
    Reading those adjacent source modules preserves decorator/test-name order
    without loading Windows DLLs or running module initialization.
    """
    content = test_file.read_text()
    companion_sources = []
    for node in ast.parse(content).body:
        if isinstance(node, ast.ImportFrom) and _is_case_module(node.module):
            companion_sources.append(
                test_file.with_name(f"{node.module}.py").read_text()
            )
    return "\n".join([content, *companion_sources])


def _is_case_module(module):
    if module is None:
        return False
    if module.startswith("pal_cases_"):
        return True
    return module in (
        "pal_integration_support", "pal_windows_support", "pal_windows_api_support"
    )

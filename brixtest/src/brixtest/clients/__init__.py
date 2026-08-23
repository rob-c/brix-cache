"""Client-side helpers for named commands, process workers and PTY runs."""

from brixtest.clients import pty
from brixtest.clients.configured import (
    ClientRegistry,
    ClientSpec,
    ConfiguredClient,
    ConfiguredTool,
)
from brixtest.clients.procworker import WorkerRunner, serve
from brixtest.clients.pty import run_pipe, run_pty

__all__ = [
    "ClientRegistry",
    "ClientSpec",
    "ConfiguredClient",
    "ConfiguredTool",
    "WorkerRunner",
    "pty",
    "run_pipe",
    "run_pty",
    "serve",
]

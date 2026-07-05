"""labkit — thin, readable helpers for the k8s-tests pytest suite.

The only place external tools (kubernetes client, helm, docker, minikube, xrd-lab)
are invoked, so individual tests stay 3-8 lines of arrange/act/assert.
"""
from .shell import run, lab, CompletedProcess  # noqa: F401

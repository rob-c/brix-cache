"""Test services (features F16–F20): the cross-cutting things every
test needs that are not about any one test — artifacts, service logs,
scratch space, waiting, payloads — each with ONE addressed way to get
it.  The grown suite answered these per-test-file (paths built from
port constants, ad-hoc log greps, `tempfile` sprinkled everywhere);
here each is a named, discoverable service reachable identically from
a test (via the ``fleet`` fixture), from the CLI, and from a REPL."""

from brixtest.services.artifacts import ArtifactCatalog
from brixtest.services.logs import LogMark, LogView
from brixtest.services.payloads import Payload, make_payload, verify_payload
from brixtest.services.waiting import wait_until
from brixtest.services.workspace import WorkspaceAllocator

__all__ = [
    "ArtifactCatalog",
    "LogMark",
    "LogView",
    "Payload",
    "WorkspaceAllocator",
    "make_payload",
    "verify_payload",
    "wait_until",
]

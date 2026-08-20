"""The suite's stub servers — the other side of the wire (F12 parity).

Eight modules moved one-to-one from ``tests/lib/`` at TS-5.  Seven are
standalone processes started by the spec catalogue or a ``cmdscripts``
driver; ``tokenconf`` is the WLCG token-conformance library twenty-six
suites import.

Nothing is imported here.  Every stub is either run as
``python -m brix_suite.servers.<name>`` or imported by name, and several
pull heavyweight third-party dependencies (``cryptography``, ``requests``)
that no importer of this package should pay for.

The designed successor to the seven grown scripts is
:class:`brixtest.stubs.StubServer`, which gives a new stub the env
contract, the refusal to bind outside its lane, uniform readiness and one
access-log shape.  These seven keep their grown behaviour verbatim — they
are pinned by suites that read their exact wire responses — so the base is
what the *next* stub is written on, not a retrofit of these.
"""

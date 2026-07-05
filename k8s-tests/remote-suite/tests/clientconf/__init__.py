"""
clientconf — client-tools conformance harness.

A small, self-contained toolkit that the ``tests/test_clientconf_*.py`` modules
use to prove the project's re-implemented XRootD client tools (``client/bin/*``)
are behaviourally compatible with the stock tools (``/usr/bin/xrd*``), while
allowing — and pinning — the project's deliberate additions.

Layers (see ``README.md`` for the full story):

  * ``diffcore``       — run a tool (stock or ours), normalize, compare.
  * ``endpoints``      — the server matrix (anon/gsi/tls/token nginx + ref xrootd).
  * ``divergence``     — the sanctioned-divergence registry (data + lookup).
  * ``flag_inventory`` — the authoritative stock flag surface, parsed from source.
  * ``cases/``         — per-tool case tables (pure data).

Design rule encoded throughout: *knob-off ⇒ differential parity with stock;
knob-on ⇒ behavioural*. An unregistered difference is a failure.
"""

"""Cache-matrix conformance plumbing (TS-5 cluster move).

Five modules that the ~thirty ``test_cachemx_*`` suites plus the partial-fill,
eviction and prefetch suites share:

* ``_cachemx`` — the private lifecycle stack (an anon posix origin plus a
  multi-plane cache matrix) and one driver per plane;
* ``_cachemx_grid`` — exposition parsing and the mixed-traffic burst the grid
  suites scrape after;
* ``_cachemx_catalog_data`` / ``_cachemx_catalog_schema`` — pure data and its
  shape checker, no imports at all;
* ``_cache_partial_helpers`` — sidecar/xattr ``.cinfo`` readers and the partial
  fill drivers.

Nothing is imported here.  ``_cachemx`` builds an ``NginxInstanceSpec`` stack
at import and every test file pins ``xdist_group("lc-cachemx")`` because the
matrix binds fixed shared-band ports from ``fleet_lifecycle_ports`` — two
concurrent drivers would move each other's counters, which is the whole reason
the suite runs against a private stack rather than the shared fleet.  Importing
the package must therefore not drag the stack in as a side effect.
"""

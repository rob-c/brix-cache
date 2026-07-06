"""Multi-user permission conformance harness.

Proves the cache-transparency invariant — an authorization verdict for (principal, path,
operation) is identical whether data is served from origin, read-cache, or stage — across
root://, WebDAV, and S3. See:
  docs/superpowers/specs/2026-07-06-multiuser-permission-conformance-design.md
  docs/superpowers/plans/2026-07-06-multiuser-permission-conformance.md
"""

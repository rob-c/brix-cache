# Executable API examples

This directory is both a tutorial and part of BriXTest's own regression suite.
Every example is a normal pytest function using the public API, and every
supporting config, script, and input lives beneath `examples/`.

Run the complete example suite from the BriXTest project root:

```console
PYTHONPATH=src python3 -m pytest examples -v
```

The numbered core catalogue progresses from small declarations to orchestration:

1. Minimal supervised managed case
2. Generated text artifact
3. Copied file artifact
4. Deterministic cryptographic-noise artifacts
5. Immutable binary capture
6. Named client and stdout capture
7. Client environment templates
8. Client stdin and expected non-zero exit
9. Gauges, counters, and tags
10. Timers and observations
11. Pytest-native metric budget
12. Native pytest properties across the helper boundary
13. Multi-file template set, captured Python binary, HTTP endpoint/probe
14. Backend-neutral server URL consumed by a reusable command client
15. Named endpoint and direct access to each captured config
16. Server-specific environment
17. Static config and immediate readiness
18. Server dependency graph
19. Explicit local placement and process isolation
20. Real nginx serving an HTML page over an allocated HTTP port

Examples 13–15 deliberately reuse one `scope="session"` HTTP origin. They show
that independent tests receive the same stable server instance and correlated
log without adding any fixture or fleet-management code. Example 13 uses the
recommended `load_template(...).fill(...)` plus `server(binary=..., args=...)`
surface; BriXTest supplies only the runtime host and port.

Example 20 uses the system `nginx` executable, captures it and its dynamic
libraries into the run, renders `configs/nginx.conf.in`, waits for the allocated
HTTP port, fetches `/`, and checks the returned HTML. It skips cleanly when
nginx is not installed.

## Authentication recipes

The compact examples in `auth/test_auth_recipes.py` demonstrate custom checksum
and signed credentials, bearer tokens, a disposable CA/CRL/host certificate,
a VOMS/GSI proxy, an isolated Kerberos realm, and backend-neutral forward/reverse
host mappings. BriXTest owns their creation, role-specific handoff, and teardown.

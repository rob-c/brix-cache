# Contributing guide

Everything a contributor is most likely to need: adding an opcode, adding a directive, meeting the code style and test bar, adding a WebDAV method, and
adding an S3 endpoint.

---

## Sub-pages

- [Extending the module](extending.md) — adding a new XRootD opcode (steps 1–7), adding a new nginx directive
- [nginx idioms for C++ reviewers](nginx-idioms-for-cpp-reviewers.md) — Rosetta Stone for C++ engineers reading this C/nginx codebase (types, return codes, pool memory, `ngx_str_t`, the module's helper/macro conventions); also the landing page of the generated Doxygen API docs (`tools/gen-docs.sh` → `docs/doxygen/html/index.html`)
- [Code style guide](code-style.md) — readability, comments, naming, error handling, pool allocation, test requirements
- [Worked examples](worked-examples.md) — dispatch routing, tracing kXR_ping, adding a WebDAV method, adding an S3 endpoint

# Unintegrated implementation drafts

| Artifact | Status |
| --- | --- |
| [darwin-aio-prototype.c.txt](darwin-aio-prototype.c.txt) | Preserved, uncompiled Darwin thread-pool AIO prototype from the macOS support branch. |

The AIO prototype was never in the module source list. Its body is preserved
unchanged here; the existing Darwin `src/platform/darwin/aio_wrapper.c` retains
its previous runtime behavior. This draft is not a supported implementation.

Before integration it needs the missing context typedef, nginx's actual task
posting API and handler signature, completion handling on the event loop,
task ownership that survives nginx's completion processing, and a shutdown
mechanism that avoids blocking the event loop. Its current wait return value
counts polling iterations rather than completed operations. Native macOS
compilation and lifecycle tests are required before enabling it.

## Unlinked integration prototypes

`copy-range-pal-prototype.c.txt` preserves the branch's unused alternate copy implementation. The production `src/core/compat/copy_range.c` retains its VFS/driver dispatch and portable fallback; replacing it requires separate validation of partial-copy offsets and backend policy.

`splice-fallback-stub-prototype.c.txt` preserves an unused macOS linkage stub. Linux already defines the real completion handler in `src/net/proxy/events_splice.c`. The prototype is not part of the module source graph; macOS integration remains unverified.

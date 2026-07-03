# Manager Mode

BriX-Cache can wear two hats as a manager or redirector. Here's what each mode does and when to use it.

- **Static map** (`brix_manager_map`) — fixed path-prefix → backend mapping. Simple, no moving parts. Covered in this document.
- **Dynamic cluster mode** (`brix_manager_mode` + `brix_cms_server`) — data servers register at runtime via the CMS protocol; the redirector picks the best server for each request. See [cluster-mode.md](cluster-management.md).

---

## Static path → backend mapping

The static map provides a fixed mapping from request path prefixes to backend
host:port endpoints. When a locate or open request matches a configured prefix
the server responds with an XRootD `kXR_redirect` response pointing the client
to the mapped backend.

Directive

- `brix_manager_map /prefix host:port;`

Behavior

- The `prefix` is normalized by the same path-normalization used by other
  policy directives (see the code comment for `brix_normalize_policy_path`).
- Lookups use longest-prefix matching — the most-specific configured mapping
  that matches the request path is selected.
- When a mapping matches, the server returns `kXR_redirect` (status 4004). The
  redirect body is formatted as a 4-byte big-endian port followed by the host
  bytes (ASCII). Clients should parse the first four bytes as the port and the
  remaining bytes as the host string.
- `locate` and `open` both consult the manager map. `locate` returns a redirect
  immediately when a map entry is found; `open` also redirects before attempting
  local resolution.

Handshake advertisement

- When `manager_map` contains at least one mapping the server advertises the
  `kXR_isManager` capability bit in the `kXR_protocol` response so clients are
  aware the server can behave as a manager/redirector.

Examples

```
stream {
    server {
        listen 127.0.0.1:11094;
        xrootd on;
        brix_manager_map /maps backend.example.org:54321;
        brix_manager_map /maps/prefix backend2.example.org:12345;
    }
}
```

Notes

- The redirect body contains no trailing NUL; parse the host using the body
  length minus four bytes.
- The static map is useful for small deployments or fixed topologies. For
  clusters where data servers register at runtime, use
  [cluster mode](cluster-management.md) instead.

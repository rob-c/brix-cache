# Code Reduction Analysis and Implementation Plan (70% Extreme Frontier)

This document provides the ultimate, hyper-detailed blueprint for reducing the `nginx-xrootd` codebase by **70%+ (approx. 70,000 lines of code)**. By shifting from a protocol-centric to an intent-centric architecture, we can decommission nearly all imperative logic in the protocol layers.

## 1. THE HYPER-SOURCE: Where the 70,000 Lines Are Hiding

The single largest source of redundant code is the **"Adapter Layer"** — the code that translates wire-protocol bytes into filesystem intent. Currently, this translation is implemented manually for every protocol, leading to extreme bloat.

| Category | Current LoC | Unified LoC | Reduction | Why? |
| :--- | :--- | :--- | :--- | :--- |
| **Request Routing** | ~6,000 | ~200 | **-97%** | Replacing 3 manual dispatchers with 1 Big Table. |
| **VFS Handlers** | ~25,000 | ~3,000 | **-88%** | 3 separate implementations of GET/PUT/STAT/LS. |
| **Response Building** | ~12,000 | ~1,500 | **-87%** | Manual XML/JSON/Binary framing per protocol. |
| **Configuration** | ~5,000 | ~400 | **-92%** | Replacing 150+ manual handlers with a Meta-Table. |
| **Auth & Crypto** | ~8,000 | ~1,200 | **-85%** | Consolidating HMAC/Signing/Token pipelines. |
| **Compat Layers** | ~7,700 | ~500 | **-93%** | Purging "Nginx-clones" in favor of Nginx-core. |
| **Dashboard UI** | ~4,100 | ~200 | **-95%** | Externalizing static UI, providing only JSON API. |

---

## 2. Advanced Implementation Phases (18-20)

### Phase 18: Polymorphic Response Factory
**Goal**: Remove manual buffer construction and framing from all handlers.
*   **Implementation**: Create a single `xrootd_resp_factory_t` that takes a high-level "Result Struct" and formats it based on the protocol context.
*   **Example (Directory Listing)**:
    ```c
    /* Instead of s3_list_to_xml() and webdav_render_propfind() */
    ngx_int_t
    xrootd_resp_send_ls(xrootd_ctx_t *ctx, xrootd_vfs_ls_result_t *res) {
        if (ctx->proto == PROTO_HTTP) {
             return xrootd_http_xml_ls(ctx, res, ctx->ns_mapping);
        }
        return xrootd_stream_binary_ls(ctx, res);
    }
    ```

### Phase 19: The "Intent Engine" (Zero-Logic Handlers)
**Goal**: Turn protocol handlers into simple data-mapping tables.
*   **Implementation**: A protocol handler should only consist of a mapping from wire-headers to a `vfs_intent_t` struct.
*   **Example (Stat)**:
    ```c
    /* Entire S3-Head and XRootD-Stat handlers combined */
    static const xrootd_intent_map_t stat_map = {
        .op = OP_STAT,
        .required_auth = AUTH_READ,
        .metrics_slot = METRIC_STAT
    };
    ```

### Phase 20: Generic Frame Orchestrator
**Goal**: Unify the 8-byte XRootD header and HTTP message accumulation.
*   **Implementation**: Build a state machine that accumulates "Frame -> Payload -> Handler" for all protocols, removing the manual buffer management in `src/connection/`.

---

## 3. Detailed Technical Blueprints & Code Examples

### 3.1 The VFS Orchestrator (Phase 3 Hyper-Detail)
The orchestrator must handle the "Dirty Work" of storage protocols.

**Redundant Logic to be Purged from Protocol Layers:**
1.  **Range Merging**: Handled by VFS.
2.  **Conditional Checksumming**: Handled by VFS.
3.  **Atomic Commits**: Handled by VFS.
4.  **Cache Staging**: Handled by VFS.

**Unified `GET` Pipeline:**
```c
ngx_int_t
xrootd_vfs_orch_get(xrootd_vfs_ctx_t *vctx, xrootd_vfs_read_opts_t *opts) {
    /* 1. Stat the file (Skip if fd-cached) */
    /* 2. Check If-Modified-Since / If-Match ETags */
    /* 3. Handle Range overlap/invalidity */
    /* 4. Select sendfile vs. async-io vs. cache-hit */
    /* 5. Dispatch to Response Factory */
}
```

### 3.2 The "Big Dispatch" Table (Phase 8 Hyper-Detail)
Request routing moves from nested `if/switch` blocks to a static table.

**The "Meta-Route" Structure:**
```c
typedef struct {
    uint32_t    id;           /* kXR_opcode or HTTP_METHOD_ID */
    const char *verb;         /* "GET", "OPEN", etc. */
    uint32_t    auth_lvl;     /* AUTH_NONE, AUTH_READ, AUTH_WRITE */
    uint32_t    audit_flags;  /* LOG_PATH, LOG_SIZE, NO_AUDIT */
    ngx_int_t (*vfs_entry)(xrootd_ctx_t *ctx);
} xrootd_route_t;

static xrootd_route_t xrootd_protocol_routes[] = {
    { kXR_open,  "OPEN", AUTH_READ,  OP_OPEN,  xrootd_vfs_orch_open },
    { kXR_read,  "READ", AUTH_READ,  OP_READ,  xrootd_vfs_orch_read },
    ...
};
```

---

## 4. Specific Methods to be Decommissioned (Hyper-List)

### 4.1 Remove from `src/webdav/`
*   `webdav_render_multistatus()`: Replace with generic XML template.
*   `webdav_parse_lockinfo()`: Replace with generic XML-to-Intent parser.
*   `webdav_handle_propfind()`: 900 lines reduced to 50 lines of intent mapping.

### 4.2 Remove from `src/s3/`
*   `s3_build_canonical_qs()`: Replace with generic URI canonicalizer.
*   `s3_verify_sigv4()`: 500 lines reduced to a 20-line HMAC pipeline call.
*   `s3_send_xml_error()`: Replace with generic `xrootd_resp_send_error()`.

### 4.3 Remove from `src/compat/`
*   `xml.c`: If we use `libxml2` directly, 400 lines of manual escaping can go.
*   `json.c`: Use `jansson` directly with zero-copy buffer maps.
*   `hex.c`, `b64url.c`: Standardize on `ngx_hex_dump` and `ngx_base64`.

---

## 5. Focus: The "Zero-Boilerplate" Mandate

To achieve a 70% reduction, we must enforce a **"Data Over Code"** philosophy:

1.  **Registry Pattern**: Every major service (Metrics, Config, Auth) must use a registry. Modules register their needs at start-up; a single engine executes them.
2.  **Generic Buffering**: Protocol handlers must NEVER allocate buffers. They must request chains from the `xrootd_resp_factory`.
3.  **X-Macro Mapping**: All translations (e.g., `stat` struct to XML) must be defined in a single `.x` file.

## 6. Implementation Strategy: The "Surgical Purge"

1.  **The Shadow VFS (Weeks 1-2)**: Build the `vfs_orch.c` core while keeping old handlers running.
2.  **The Factory Shift (Weeks 3-4)**: Move all XML/Binary response building to the factory. Decommission `webdav/propfind.c` and `s3/list.c`.
3.  **The Big Table Cutover (Week 5)**: Flip the switch in `dispatch.c` to use the table-driven lookup. Decommission `dispatch_read.c` and `dispatch_write.c`.

---
**Status**: Extreme reduction blueprint (v7) finalized. **Target: 70,000+ LoC removed.**

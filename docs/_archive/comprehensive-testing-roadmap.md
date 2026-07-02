# Roadmap: Zero-Mock Full-Stack Interoperability Testing

This document defines the requirements and implementation plan for transforming the `nginx-xrootd` test infrastructure into a production-grade validation suite. The goal is to eliminate all non-protocol-compliant mock components and implement a complete interoperability matrix where `nginx-xrootd` and `xrootd` are interchangeable in every role of a multi-server stack.

---

## 1. The "Gold Standard" Principle

All tests must be benchmarked against a **Pure XRootD Reference Stack**. 
*   **Behavioral Reference:** The behavior of the latest XRootD release (e.g., 5.x) is the expected standard.
*   **Source Truth:** If behavior is ambiguous or a bug is suspected in the reference server, the source code in `/tmp/xrootd-src/src/XProtocol/` and related subsystems is the final authority.
*   **Zero Mocks:** No Python-based socket simulators, silent stubs, or ad-hoc frame parsers are permitted. Every component in the test must be a real `nginx` or `xrootd` binary.
*   **Version Pinning:** All reference tests must record the exact version of the `xrootd` binary used to ensure that protocol changes in XRootD itself are accounted for.

## 2. Test Infrastructure Lifecycle

As of June 2026, the test infrastructure lifecycle has been optimized for stability and performance:

*   **Persistent Session-Level Lifecycle**: All required test services (nginx, xrootd reference servers, HA clusters, CMS managers) are launched **exactly once** at the beginning of the `pytest` session using `tests/conftest.py` (`pytest_sessionstart`).
*   **Centralized Shutdown**: Servers are terminated only once after all tests have finished using `pytest_sessionfinish`. 
*   **Elimination of Transient Servers**: This replaces the previous module-level fixture approach that frequently created and destroyed server instances, causing race conditions and port conflicts.
*   **Primary Entry Point**: `tests/manage_test_servers.sh start-all` is the canonical command for launching the full test suite environment, ensuring consistent port allocation and data root preparation for all tests.
*   **Test Environment**: Tests should no longer attempt to start or stop services manually; they must assume the environment managed by the session fixtures is available.

---

## 3. Mock Replacement Inventory (Updated for Persistent Servers)

| Current Mock | Role | Replacement Strategy | Technical Implementation |
| :--- | :--- | :--- | :--- |
| `_run_mock_cms_select_server` | CMS Manager | Real `xrootd` daemon + `cmsd` in manager mode. | Start `xrootd` with `all.role manager` and a single registered data server. |
| `_run_mock_cms_try_server` | CMS Manager | Real `xrootd` daemon + `cmsd` in manager mode. | Start `xrootd` with `all.role manager` and 2+ registered data servers. |
| `_run_silent_cms_stub` | Delayed CMS | Real `xrootd` manager with empty registry. | Start `xrootd` manager but block `cmsd` traffic or use an empty `oss.localroot`. |
| `_mock_cms_connect_and_register` | DS Simulator | Real `nginx-xrootd` instance. | Use a dedicated Nginx instance in DS mode with `xrootd_cms_manager` set. |
| `TestKyrGone` socket | Deregistration | Trigger real `kYR_gone`. | Call `xrdadmn -c /path/to/config drop path /path` on a running data server. |

---

## 3. Stack Interoperability Matrix (Core Permutations)

### A. Proxy Permutations (Data Plane)
1.  **Nginx Perimeter (The "WLCG Gateway" Scenario):**
    *   **Path:** `xrdcp (Token/GSI)` ──► `nginx (proxy)` ──► `xrootd (data, Anon)`
    *   **Logic:** Nginx terminates perimeter security. Backend is unauthenticated.
2.  **Nginx Internal (The "Storage Bridge" Scenario):**
    *   **Path:** `xrdcp` ──► `xrootd (proxy)` ──► `nginx (data)`
    *   **Logic:** Tests compatibility with `ofs.forward` and `pss`.
3.  **Full Nginx Stack (The "Pure Nginx" Scenario):**
    *   **Path:** `xrdcp` ──► `nginx (proxy)` ──► `nginx (data)`

### B. Management / Cluster Permutations (Control Plane)
1.  **Nginx Manager:** `client` ──► `nginx (manager)` ──► 3 `xrootd (data)` nodes.
2.  **Nginx Data Node:** `xrootd (manager)` receiving registration from `nginx (data)`.
3.  **Multi-Tier Escalation:** `client` ──► `nginx (sub-manager)` ──► `xrootd (meta-manager)`.
4.  **Space & Quota Relay:** Verify `kYR_space` relaying and space-aware redirection.

---

## 4. Advanced HEP Deployment Scenarios (The Heterogeneous Network)

These scenarios represent common architectural patterns deployed across the Worldwide LHC Computing Grid (WLCG).

### A. The "XCache alternative" (Read-Through Caching)
*   **Topology:** `Client ──► Nginx (with xrootd_cache) ──► XRootD (Origin)`.
*   **Goal:** Verify that Nginx correctly caches data blocks from an XRootD origin and serves subsequent requests for the same block from local disk without hitting the backend.
*   **Validation:**
    1.  Measure `bytes_received` from backend on first read (should match file size).
    2.  Measure `bytes_received` from backend on second read (should be zero).
    3.  Verify checksum consistency between the original file and the cached copy.

### B. Federated Redirection (WAN/Global Namespace)
*   **Topology:** `Client ──► Local Nginx Mgr ──► Regional XRootD Redirector ──► Remote Data Server`.
*   **Goal:** Verify that Nginx correctly escalates queries to a higher-level "meta-manager" when a path is not found locally, and then correctly relays the WAN-scoped redirect back to the client.
*   **Validation:** Use `xrdcp` to fetch a file located in a different "site" (simulated by a separate port group) and ensure the redirect chain completes.

### C. The "Credential Translation Bridge"
*   **Topology:** `Legacy GSI Client ──► Nginx (Proxy/Bridge) ──► Modern Token-only Backend`.
*   **Goal:** Act as a migration path for legacy experiments. Nginx verifies the GSI proxy and then injects a short-lived WLCG Bearer Token to authorize the request on a modern backend.
*   **Validation:** Check backend logs to ensure the request is authenticated via `Bearer <token>` and that the `sub` field matches the mapped DN from the GSI proxy.

### D. S3-to-XRootD Gateway (Cloud Interop)
*   **Topology:** `S3 Client (Boto3/rclone) ──► Nginx (S3 Module) ──► XRootD (Backend)`.
*   **Goal:** Expose XRootD storage to cloud-native applications. Nginx translates S3 REST API calls (PUT/GET/LIST) into XRootD binary or WebDAV operations.
*   **Validation:** Upload a file via S3 and download it via `xrdcp`. Verify data integrity and metadata (e.g. `Content-Type`) preservation.

### E. Site-Entry High-Availability (HA) Stack
*   **Topology:** `Client ──► Load Balancer (HAProxy) ──► {Nginx-1, Nginx-2} ──► {XRootD-DS1...DS100}`.
*   **Goal:** Verify that Nginx instances can share a common backend registry or operate correctly when clients are balanced across multiple gateway nodes.
*   **Validation:** Force Nginx-1 to stop mid-transfer and ensure the client can resume via Nginx-2 (if the protocol/client supports it) or that a new connection is handled seamlessly.

### F. Write-Through (WT) Cache in Heterogeneous Meshes
This scenario tests the synchronous data propagation and consistency guarantees of the `nginx-xrootd` write-through logic when integrated into multi-vendor storage hierarchies.

1.  **Nginx-to-XRootD Write-Through:**
    *   **Topology:** `Client ──► Nginx (WT Cache) ──► XRootD (Origin)`.
    *   **Goal:** Verify that a `kXR_write` from the client is synchronously relayed by Nginx to the XRootD origin. The client must not receive a success code until the data is safely committed to the origin.
    *   **Validation:**
        1.  Induce a disk-full error on the XRootD origin.
        2.  Verify the client's `write` operation fails immediately on the Nginx cache.
        3.  Verify `kXR_sync` propagation: a sync request on Nginx must trigger a synchronous sync on the XRootD origin.

2.  **Chained Write-Through (Multi-Hop Heterogeneity):**
    *   **Topology:** `Client ──► Nginx (Edge WT) ──► XRootD (Proxy WT) ──► Nginx (Archive Origin)`.
    *   **Goal:** Ensure 64-bit offsets and write flags (e.g., `kXR_append`) are preserved through multiple proxy/cache layers of different vendors.
    *   **Validation:** Write a 5GB file using `xrdcp` through the entire chain. Verify the checksum on the final Archive Origin matches the client-side original.

3.  **Conflict Handling & Lock Relay:**
    *   **Scenario:** Two clients attempt to write to the same file through different Nginx WT caches pointing to the same XRootD origin.
    *   **Requirement:** Verify that the XRootD origin's file-locking/locking-state is correctly relayed back through the Nginx layers, returning `kXR_NotAuthorized` or `kXR_Conflict` to the second client.

---

## 5. Technical Implementation Details

### A. Handle Collision & Translation Stability
*   **Stress Test:** 100 concurrent clients, 10 files each.
*   **Handle Leak Detection:** Monitor `/proc/$(pgrep nginx)/fd` for leaks.

### B. CMS Discovery Timing & Race Conditions
*   **Wait-for-CMS Logic:**
    ```bash
    wait_cms_ready() {
        local port=$1; local expected=$2
        for i in {1..30}; do
            local count=$(xrdfs root://localhost:$port query stats | grep "num_servers" | awk '{print $2}')
            if [[ "$count" == "$expected" ]]; then return 0; fi
            sleep 1
        done
        return 1
    }
    ```

### C. Protocol Translation Deep-Dive (Opcode Relay)
Nginx must correctly relay every field in the XRootD request header:
*   **`kXR_open`**: Relay `mode` and `options` (e.g. `kXR_async`, `kXR_compress`).
*   **`kXR_read`**: Verify 64-bit offset preservation.
*   **`kXR_stat`**: Relay extended attribute payloads.

---

## 6. Data Integrity & Checksumming Matrix

### A. End-to-End Checksumming
*   **Test:** Client uploads 1GB file with `adler32`. Proxy must relay `kXR_query cksum` to backend and return identical string.

### B. Inline Checksum Validation (pgread/pgwrite)
*   **Requirement:** Nginx must relay CRC32c frames verbatim for page-level verification.

### C. Write-Through Checksumming Consistency
*   **Scenario:** Client writes through Nginx WT cache to XRootD origin.
*   **Requirement:** Verify that the checksum calculation on the XRootD origin (done after the write completes) matches a local checksum calculated by the Nginx cache *before* it clears its internal buffer.
*   **Test:** Induce a bit-flip on the wire between Nginx and XRootD. The XRootD origin's checksum validation should fail, and this failure must be propagated back to the client through the Nginx WT layer as a `kXR_IOError` or `kXR_ArgInvalid`.

---

## 7. Security-Negative Testing Matrix

1.  **Path Traversal:** `root://proxy//../../etc/passwd` confinement.
2.  **Credential Leakage:** Strip `Authorization` in anonymous upstream mode.
3.  **Frame Fuzzing:** Send malformed frames to the proxy.
4.  **TLS MITM:** Expired certs on backend must drop connection.

---

## 8. Third-Party Copy (TPC) Interoperability

1.  **Nginx as Source:** `xrdcp root://nginx/file root://xrootd/file`.
2.  **Nginx as Destination:** `xrdcp root://xrootd/file root://nginx/file`.
3.  **Delegated Auth:** Proxy `kXR_authmore` during TPC handshake.

---

## 9. Observability & Diagnostics

*   **Unified Tracing:** Use `streamid` for correlation.
*   **Wireshark/Tcpdump:** `tcpdump -i lo -w /tmp/xrd-test/capture.pcap`.
*   **Audit Logging:** WLCG-compliant fields (IP, User, File, Action, Result).

---

## 10. Implementation Roadmap (Phased)

### Phase 1: Reference Infrastructure (Weeks 1-2)
*   Standardize `manage_test_servers.sh` for all XRootD roles.
*   100% replacement of Python sockets.

### Phase 2: Interoperability Matrix (Weeks 3-4)
*   `test_e2e_proxy_matrix.py` (Nginx/XRootD permutations).
*   `test_e2e_cluster_matrix.py` (Heterogeneous clusters).
*   Verified TPC with delegated auth.

### Phase 3: Advanced HEP Scenarios (Weeks 5-6)
*   Caching (XCache style) and Credential Translation tests.
*   Write-Through (WT) synchronous propagation and error handling tests.
*   Federated Redirection (WAN) simulation.
*   S3 Gateway Interop.

### Phase 4: Stability & Performance (Weeks 7-8)
*   Load Benchmarking and HA Failover validation.
*   WLCG Audit Log Verification.

---

## 12. The "Chaos Mesh": Maximal Code-Path Coverage Scenario

This scenario is designed to exercise the largest possible number of internal `nginx-xrootd` subsystems in a single end-to-end flow. It specifically targets the state machines for handle translation, protocol bridging, and heterogeneous redirection.

### A. The "Pathological" Topology
```text
[Client: xrdcp -S 4]
       │
       ▼
[Tier 1: Nginx Perimeter Gateway]
  - Role: Manager + Binary Proxy
  - Auth: JWT (Edge) -> SSS (Internal)
       │
       ├─► [Tier 2: Nginx Regional Cache]
       │     - Role: Read-Through/Write-Through Cache
       │     - Config: xrootd_cache on, xrootd_proxy on
       │          │
       │          └─► [Tier 3: Nginx Storage Node]
       │                - Role: Data Server
       │                - Protocols: Binary, WebDAV, S3 (simultaneous)
       │
       └─► [Tier 2b: XRootD Origin]
             - Role: Pure XRootD Reference Node
```

### B. The "Widest Coverage" Operation Sequence
1.  **Identity Shifting:** Client connects via `root://` using a WLCG Token. Tier 1 validates the token and maps it to a site-internal `SSS` key for Tier 2 access.
2.  **Delayed Discovery:** Tier 1 (Manager) is started *after* Tier 3. Verify that the registry correctly populates via retroactive `kYR_login`.
3.  **Multi-Stream TPC with Protocol Bridging:**
    *   Initiate an `xrdcp` TPC where the **Source** is Tier 3 via the **S3 REST API**, and the **Destination** is Tier 1 via **Binary root://**.
    *   This forces Nginx to:
        1.  Parse S3 headers in `src/s3/`.
        2.  Translate to internal I/O.
        3.  Launch a TPC task in `src/tpc/`.
        4.  Bridge the data into a Binary `root://` stream with handle translation in `src/net/proxy/`.
4.  **Synchronous Conflict:** During the TPC, a separate client performs a `kXR_open(kXR_new)` on the same file through the Tier 2 Write-Through cache. Verify that the lock-contention from Tier 3 is bubbled up correctly through all tiers.
5.  **Chaos Injection:** Mid-transfer, send `SIGHUP` (reload) to Tier 2. Verify that Nginx's "graceful shutdown" preserves the proxy handles and that the client transfer continues without `kXR_IOError`.

### C. Specific Code Paths Exercised
*   **`src/session/signing.c`**: SSS internal auth.
*   **`src/net/proxy/handle_table.c`**: Mapping handles across a 3-tier NAT-like hierarchy.
*   **`src/fs/cache/eviction.c`**: Triggered by writing a file larger than the Tier 2 cache disk partition.
*   **`src/tpc/bridge.c`**: Moving data between the HTTP/S3 and Binary state machines.
*   **`src/connection/fd_table.c`**: High-pressure FD usage with multi-stream TPC.

---

## 13. Implementation Guidance: The "Stress Script"

To implement the Chaos Mesh, `manage_test_servers.sh` must be updated with a "Super-Group" launcher:

1.  **Dynamic Config Generation:** Use a Python script to generate the `nginx.conf` and `xrootd.cfg` files with chained ports (Tier 1 points to Tier 2, Tier 2 to Tier 3).
2.  **The "Big Bang" Start:** Launch all 5+ nodes in background subshells.
3.  **The "Chaos Loop":**
    ```bash
    # While xrdcp is running...
    while pgrep xrdcp; do
        kill -HUP $(cat /tmp/xrd-test/logs/tier2.pid) # Trigger reload
        sleep 2
        ls -l /tmp/xrd-test/data/tier2/cache/ # Check disk usage
    done
    ```

---

## 14. Success Criteria (Final)
1.  **Zero Python Threads.**
2.  **Complete Matrix Coverage.**
3.  **Chaos Resilience:** 100% of files transferred correctly despite reloads and lock contention.
4.  **Handle Leak Detection:** `/proc/net/tcp` shows zero "orphaned" handles after the 1000th operation.
5.  **Audit Match:** The `Requuid` in the S3 logs matches the `streamid` in the Binary logs.

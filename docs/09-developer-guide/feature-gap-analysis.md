# Feature Gap Analysis: nginx-xrootd vs. XRootD

This document outlines the remaining feature gaps between the `nginx-xrootd` module and a canonical XRootD implementation suitable for WLCG Tier-2 disk-only and tape-backed sites.

## Summary of Feature Gaps

| Feature | Gap | Effort Estimate | Priority |
|:---|:---|:---|:---|
| **Tape Backend Dispatch** | Lack of recall trigger and staging status tracking. | 2–3 weeks | High |
| **Outbound TLS Auth** | Origin connections cannot handle `kXR_authmore` / `kXR_gotoTLS`. | 1–2 weeks | High |
| **Multi-hop GSI Delegation**| Complex proxy-delegation chains in TPC are not supported. | 1–2 weeks | Medium |
| **Lock Persistence** | Locks are lost on `nginx -s reload`. | 1 week | Medium |
| **Third-party Macaroons** | Cannot validate tokens requiring external discharge (VID). | 1 week | Medium |
| **Parallel Write Streams** | Bound handle sharing is read-only. | 1–2 weeks | Low |
| **OCSP Support** | No OCSP responder querying for cert revocation. | 1–2 weeks | Low |

---

## Detailed Gap Descriptions

### 1. Tape Backend Dispatch (`kXR_prepare` / `kXR_stage`)
The current module recognizes the `kXR_prepare` opcode but treats it as a simple path validation. Sites with tape backends (CASTOR, EOS tape, dCache) require a mechanism to dispatch these requests to a tape-recall service.

*   **Files to Modify:**
    *   `src/query/prepare.c`: Implement backend dispatch logic.
    *   `src/query/query_internal.h`: Add data structures for pending recalls.
*   **Work Required:** Create a dispatcher for tape recall commands. Update the `kXR_QPrep` query implementation to report recall status (pending, recalled, error).

### 2. Outbound TLS Auth (`kXR_authmore` / `kXR_gotoTLS`)
Outbound connections initiated by the nginx node (for read-through cache fill or native TPC pull) fail if the source requires an auth challenge.

*   **Files to Modify:**
    *   `src/upstream/bootstrap.c`: Implement `kXR_authmore` and `kXR_gotoTLS` handling.
*   **Work Required:** Modify the bootstrapping code to handle authentication challenges during the initial handshake with upstream servers.

### 3. Lock Persistence
WebDAV locks are maintained in process-local memory. A reload causes these locks to disappear.

*   **Files to Modify:**
    *   `src/webdav/lock.c`: Add serialization logic to flush locks to a file before shutdown and reload them on startup.
*   **Work Required:** Design a simple binary file format for lock state and implement read/write hooks.

### 4. Multi-hop GSI Delegation
TPC transfers involving multiple network hops fail when the delegation of a GSI proxy cert is required beyond the initial hop.

*   **Files to Modify:**
    *   `src/tpc/bootstrap.c`: Enhance GSI delegation logic.
*   **Work Required:** Implement a second-hop delegation handshake in the TPC outbound pull client.

### 5. Parallel Write Streams (Write Sharing)
`kXR_bind` handle sharing allows multiple streams to read from a single handle, but the handle table explicitly prohibits binding to write handles.

*   **Files to Modify:**
    *   `src/read/open.c`, `src/handshake/policy.c`: Adjust policies for `XROOTD_XFER_DIR_WRITE`.
*   **Work Required:** Allow sharing of write handles; ensure concurrent write operations to the same handle are safely serialized by the stream handlers.

### 6. OCSP Support
TLS certificate verification is currently limited to CRL files.

*   **Files to Modify:**
    *   `src/crypto/pki_check.c`: Add OCSP stapling and responder query logic.
*   **Work Required:** Integrate OpenSSL OCSP validation into the existing PKI/TLS validation flow.

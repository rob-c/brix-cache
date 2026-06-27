# Hybrid Two-Tier Cross-Backend Mesh — Design Spec

**Date:** 2026-06-27
**Status:** Approved (design) — ready for implementation planning
**Author:** Rob Currie (with Claude Code)

## 1. Purpose

Add a complex, dedicated, **two-tier hybrid mesh** to the test fleet that mixes
nginx-xrootd and stock XRootD in *every* role (redirector, read/write-through
proxy, data server) within a single storage graph. The mesh exists to prove four
things end-to-end:

1. **Cross-backend equivalence** — nginx and stock XRootD are interchangeable in
   every role; identical content is served byte-for-byte (and checksum-for-checksum)
   regardless of which backend serves a given hop.
2. **Write-through correctness** — a write entering through one proxy lands in the
   storage cluster and is consistently readable through the *other* proxy.
3. **Resilience / failover** — killing a proxy or a data server reroutes via the
   appropriate redirector; the client still completes.
4. **Full conformance through the topology** — the existing conformance suite,
   run unchanged through the whole 7-node graph, stays green.

The mesh also exercises the **hardest CMS-wire interop in the codebase**: an nginx
CMS manager accepting a *stock XRootD* proxy registration, and a stock XRootD
`cmsd` manager accepting an *nginx* data-server registration — both directions,
in one graph, live.

## 2. Architecture

Seven dedicated nodes, two redirector tiers, deliberately symmetric so each
redirector backend accepts a data node of the *other* backend.

```
                         client
                           │ root:// / davs:// / S3
                           ▼
              ┌───────────────────────────┐
   TIER 1     │  a) nginx redirector       │   (nginx CMS manager)
   entry/     │     CMS manager            │
   cache      └───────────┬───────────────┘
              registers ►  │  ◄ registers
                  ┌────────┴────────┐
                  ▼                 ▼
        b) nginx proxy        c) XRootD proxy (PSS)
           (r/w-through)         (r/w-through)
                  └────────┬────────┘
                           │ origin = tier-2 redirector g
                           ▼
              ┌───────────────────────────┐
   TIER 2     │  g) XRootD redirector       │  (stock cmsd+xrootd manager)
   storage    │     cmsd manager            │
   cluster    └───────────┬───────────────┘
                  ┌────────┼─────────┐
                  ▼        ▼         ▼
            d) XRootD   e) XRootD   f) nginx
               data        data        data
               server      server      server
```

### 2.1 Role / backend matrix

| Node | Backend | Role | Registers with | Notes |
|------|---------|------|----------------|-------|
| `a` | nginx | tier-1 CMS manager (redirector) | — | client entry; redirects to `b`/`c` |
| `b` | nginx | read/write-through proxy | `a` (cms) | origin → `g` |
| `c` | **stock XRootD** | PSS read/write-through proxy | `a` (cms) | `pss.origin` → `g`; **xrootd-DS → nginx-cmsd** interop |
| `g` | **stock XRootD** | tier-2 `cmsd` manager (redirector) | — | locates files across `d`/`e`/`f` |
| `d` | stock XRootD | data server | `g` (cmsd) | independent storage |
| `e` | stock XRootD | data server | `g` (cmsd) | independent storage |
| `f` | nginx | data server | `g` (cmsd) | **nginx-DS → xrootd-cmsd** interop |

The two interop linchpins (must work for the mesh to form):
- `c` (stock XRootD proxy) registers into `a`'s **nginx** CMS manager.
- `f` (nginx data server) registers into `g`'s **stock** `cmsd` manager.

## 3. Data flow

### 3.1 Per-protocol carriage

| Protocol | Path through mesh | Coverage |
|----------|-------------------|----------|
| `root://` | `a` → (`b` \| `c`) → `g` → (`d`\|`e`\|`f`) | **Full** — every node, both tiers; native CMS redirect at `a` and `g`; PSS at `c` |
| WebDAV / `davs://` | `a` (307) → (`b`\|`c`) → `g` (307) → (`d`\|`e`\|`f`) | **Full** — HTTP listeners on all nodes; stock nodes (`c`,`g`,`d`,`e`) load `libXrdHttp` |
| S3 REST | `client → a → b → f` (ingest), then any protocol reads it back via the cluster | **Ingest path** — see §3.3 |

### 3.2 Data layout — independent storage (true cluster)

- Each tier-2 DS (`d`, `e`, `f`) has its **own** data directory; `g` locates a
  file on whichever DS holds it. This is what makes the design a *real* cluster
  rather than a shared-disk illusion.
- One common logical namespace (`/mesh/...`) is exported by `d`/`e`/`f`.
- **Two fixture classes**, because two goals need opposite data setups:
  - *Cluster fixtures* (write-through, conformance, failover, S3 ingest): created
    **through the cluster**; land on one DS; located by `g` on read-back.
  - *Equivalence fixtures* (cross-backend equivalence): identical bytes
    **pre-staged directly** into `d`, `e`, and `f`'s data dirs, then read by
    addressing **each DS's own direct port**, so the comparison pins which
    backend serves the bytes. (Through `g`, the locate is non-deterministic, so
    direct addressing is the only way to compare backends.)

### 3.3 S3 cross-protocol ingest (refined semantics)

S3 is the **write/ingest** path, not an isolated nginx-only island:

1. An S3 `PUT` (`client → a → b → f`) writes the object into the **cluster
   namespace** on `f` — `s3://bucket/key` maps to logical `/mesh/bucket/key` in
   `f`'s store.
2. Because `f` is a registered tier-2 DS, `g` immediately **locates** that path.
3. The object is therefore readable by **every other protocol** through the
   cluster: `root://` and `davs://` GETs (`a → b|c → g → locate → f`) return the
   same bytes + checksum.

The S3 write "registers" the file into the cluster for pickup by root/WebDAV.
This is a first-class consistency test (see §5).

### 3.4 Write-through consistency

Write a file via `b` (nginx proxy) → `g` creates it on a DS → read it back via
`c` (xrootd proxy) → bytes + checksum must match. Symmetric: write via `c`,
read via `b`.

## 4. Provisioning & `start-all` integration

- **Launcher:** new `tests/hybrid_mesh_servers.py` + `tests/hybrid_mesh_lib.py`,
  modeled on `tests/cms_mesh_servers.py` / `tests/cms_mesh_lib.py` and **reusing
  `cms_mesh_lib.Mesh`**:
  - `Mesh.xrootd_node(role="manager")` builds node `g` (real `cmsd`+`xrootd`).
  - `Mesh.xrootd_node(role="server")` builds nodes `d` and `e`.
  - nginx config builders (`cfg_manager`, `cfg_proxy`, `cfg_datanode`) build
    nodes `a`, `b`, `f`.
  - **Two small builder additions:**
    1. An xrootd **PSS-proxy-that-registers** config for `c`:
       `all.role server` + `all.manager = a`'s CMS port + `pss.origin = g`.
    2. HTTP (`libXrdHttp`) enabled on the stock nodes (`c`, `g`, `d`, `e`) for
       the WebDAV path.
- **Hook into `start-all`:** `manage_test_servers.sh start-all` invokes
  `hybrid_mesh_servers.py start` (exactly as it already invokes
  `cms_mesh_servers.py`), backgrounded alongside the CMS mesh so it overlaps
  cluster convergence. `stop-all` / `force-stop` call `... stop`. If stock
  binaries are missing, `start` is a no-op and tests skip on closed ports.
- **Dedicated exclusive port band:** a fresh contiguous block (proposed
  `11300–11320`), every port env-overridable (`HYBRID_REDIR_PORT`,
  `HYBRID_PROXY_NGINX_PORT`, `HYBRID_PROXY_XRD_PORT`, `HYBRID_TIER2_REDIR_PORT`,
  `HYBRID_DS_D_PORT`, `HYBRID_DS_E_PORT`, `HYBRID_DS_F_PORT`, plus matching CMS
  ports). The exact band is verified collision-free against the fleet
  (`11094–11123`), cluster (`~11160–12600`), and CMS-mesh bands during planning.
  No node is shared with any other test.
- **Readiness gate:** `hybrid_mesh_lib.wait_ready()` probes a `locate` through
  the full stack — a redirect proves `d`/`e`/`f` registered with `g` **and**
  `b`/`c` registered with `a` (both interop linchpins live) before tests run.

## 5. Test plan

New `tests/test_hybrid_mesh.py` (skips if binaries missing / ports closed),
grouped to the four goals plus S3 ingest:

| Group | What it does | Asserts |
|-------|--------------|---------|
| Cross-backend equivalence | direct-address `d`,`e`,`f` for an identical pre-staged fixture | byte-identical + checksum equal across xrootd `d`/`e` vs nginx `f` |
| Write-through correctness | write via `b`, read via `c` (and reverse) through the cluster | bytes + checksum match across entry paths |
| S3 cross-protocol ingest | `PUT` via S3 (`a→b→f`); GET via `root://` and `davs://` through the cluster | same object located by `g` & served by all protocols; checksum match |
| Resilience / failover | kill DS `d` mid-cluster → `g` reroutes to `e`/`f`; kill proxy `c` → `a` redirects to `b` | reads/writes still succeed; killed node **re-provisioned in teardown** |
| Full conformance | run conformance suite as a subprocess with `CONFORMANCE_NGINX_URL` = `a` | green = whole 7-node graph preserves wire conformance (mirrors `test_conformance_topologies.py`) |

Per the project test rule, each behavioural change carries three tests
(success + error + security-negative) where applicable.

## 6. Failure handling & teardown discipline

- Because the nodes are **persistent fleet members**, every failover test that
  kills a node **re-provisions it** in its fixture finalizer (self-healing), so a
  later test run finds the mesh intact. This matches the existing
  `resilience_dedicated_instances` pattern.
- `force-stop` must reliably tear down all 7 nodes (stock `cmsd`+`xrootd` via
  `pkill -f <cfg>`, nginx via pid file), leaving no orphans on the dedicated
  band.
- Startup is gated on an active `locate` redirect (not a blind settle-sleep) so a
  slow cluster convergence fails loudly rather than producing flaky tests.

## 7. Non-goals (YAGNI)

- **No inter-DS replication.** Storage is independent per DS; failover is proven
  at the connection/locate level (kill a DS, the cluster routes around it), not
  by replicating bytes across DSs.
- **No auth.** The mesh runs **anonymous** end-to-end to isolate topology
  behaviour from auth. GSI/token variants are out of scope for this spec (and
  native TPC-over-GSI is known-broken — see memory `native_tpc_gsi_broken`).
- **No native S3 on XRootD nodes.** XRootD has no native S3; S3 is intentionally
  an nginx-side ingest path (§3.3) rather than a per-hop protocol.

## 8. Implementation building blocks (existing, reused)

- `tests/cms_mesh_lib.py` — `Mesh` launcher (`xrootd_node` real `cmsd`+`xrootd`,
  `nginx`), nginx config builders, `wait_ready()` locate-probe pattern.
- `tests/cms_mesh_servers.py` — `start`/`stop` invoked from `start-all`.
- `tests/lib/dedicated.sh`, `tests/lib/refxrootd.sh` — dedicated-instance
  conventions and reference-xrootd helpers.
- `tests/test_conformance_topologies.py` — pattern for running the conformance
  suite as a subprocess through a provisioned front.
- `tests/manage_test_servers.sh` — `start-all` / `stop-all` / `force-stop`
  integration point.

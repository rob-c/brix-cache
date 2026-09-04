# Final port-ladder segments, continued from port_ladder_offsets.py.
# Loaded into port_ladder.py's namespace so public constant imports are stable.

# 2026-08-19: 205 -> 211 for the six-port root_readonly_gateway block (origin +
# read-only gateway + allow_write-override gateway + writable control +
# data-substreams gateway + read_only_public gateway).  The config-time
# role-conflict check needs no port: it listens on a unix socket, because
# `nginx -t` opens the listening sockets and a TCP port would race the lane.
# 2026-09-03: 211 -> 213 for cvmfs_verify's mock Stratum-1 and cache-front
# listeners.  It previously used absolute ports, defeating per-run isolation.
CMDSCRIPTS_OFFSET, CMDSCRIPTS_WIDTH = 1314, 213
CMS_MESH_OFFSET, CMS_MESH_WIDTH = 1527, 83
HYBRID_MESH_OFFSET, HYBRID_MESH_WIDTH = 1610, 23
PLACEHOLDERS_OFFSET, PLACEHOLDERS_WIDTH = 1633, 2

# CVMFS conformance mock-Stratum-1 + nginx port blocks (cvmfs/conformance_common.py
# PORT_BLOCKS): 26 files x a 20-port block. Anchored into the ladder so every
# port stays within TEST_PORT_START+2000 and a second suite on a different
# TEST_PORT_START draws a disjoint range (replaces the old absolute 13100+ tiling).
# 27 file blocks x 20 ports = 540, plus a 48-port matrix sub-range for the
# concurrent fuse-trust mock origins (see conformance_common.matrix_port).
CVMFS_CONFORMANCE_OFFSET, CVMFS_CONFORMANCE_WIDTH = 1635, 588

# Differential-interop per-file fixed ports (official_interop_lib.worker_port):
# one slot per distinct conformance base (65 today), anchored here so they stay
# in the contiguous ladder within TEST_PORT_START+3000 instead of the old
# absolute 30000-49925 per-worker band. The owning module is pinned to one xdist
# worker, so a fixed port per file suffices.
# 2026-08-26: 61 -> 65 — four conformance bases were registered in
# _INTEROP_BASES without the matching width bump (caught by
# test_fleet_ports.py: worker slots 12216-12219 fell past PORT_LAST).
INTEROP_WORKER_OFFSET, INTEROP_WORKER_WIDTH = 2223, 65

# 2026-08-31 (phase-106): shared lane +5 for the five nginx-integration nodes;
# every lane below shifts by 5. Packed ladder — an intentional compatibility
# event, per the note above.
# 2026-09-01/02 (phase-107): shared lane +34, PORT_COUNT 2225 -> 2259. The C7
# +8 first landed width-only — the shared/exclusive overlap the 2026-08-16
# band check exists for; every lane re-summed 2026-09-02.
# 2026-09-02 (phase-109 merge): shared lane +3 for lc-walk-offload,
# PORT_COUNT 2259 -> 2262 (running sum re-applied across both waves).
# 2026-09-03 (phase-105 W4.3): shared lane +2 for the WebDAV+S3
# HTTP JWKS-refresh parity worker.
# 2026-09-04 (phase-81): shared lane +12 for the ordinary-fixture close-out.
# 2026-09-04 (phase-91): +7 for the FTP origin, two gateway listeners and the
# VOMS carry lab's origin plus three WebDAV fronts.
PORT_COUNT = 2288

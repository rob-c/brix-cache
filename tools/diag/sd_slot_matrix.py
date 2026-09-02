#!/usr/bin/env python3
"""Regenerate the storage-driver slot matrix in
docs/09-developer-guide/storage-driver-slot-matrix.md.

WHAT: census every registered ``brix_sd_*_driver`` against the function-pointer
      slots of ``struct brix_sd_driver_s`` and emit the markdown table, one
      verdict per cell.
WHY:  the matrix is the map of what each backend can and cannot do; a hand-kept
      copy of it goes stale the day a slot lands. The IMPLEMENTED half is read
      out of the source, so only the verdicts for the EMPTY cells are editorial —
      and every one of them must be spelled out below or this script exits 1.
HOW:  run from the repo root:

          python3 tools/diag/sd_slot_matrix.py \\
              docs/09-developer-guide/_slot-matrix-table.md

      then paste the table into §1 of the doc (or diff it against what is there).
      Two invariants are enforced: no empty cell without a verdict code, and no
      verdict code for a cell the source actually implements — the second is what
      catches a verdict left behind after the slot it excused was written.
"""
import re, pathlib, sys
root = pathlib.Path("src/fs/backend")
drv = {}
for f in sorted(root.rglob("*.c")):
    t = f.read_text(errors="replace")
    for m in re.finditer(r'brix_sd_([a-z0-9_]+)_driver\s*=\s*\{', t):
        sym = m.group(1); i = m.end(); j = t.find("\n};", i)
        drv[sym] = set(x.strip(". =") for x in re.findall(r'\.[a-z0-9_]+\s*=', t[i:j]))
h = (root/"sd.h").read_text()
i = h.index("struct brix_sd_driver_s {"); j = h.index("\n};", i)
slots, seen = [], set()
for m in re.finditer(r'\(\s*\*\s*([a-z0-9_]+)\s*\)\s*\(', h[i:j]):
    s = m.group(1)
    if s not in seen: seen.add(s); slots.append(s)
order = ["posix","pblock","block","mirage","ceph","cephfs_ro","frm","http",
         "remote","xroot","cache","stage"]
short = {"cephfs_ro":"cfs-ro","mirage":"mir"}

CRED = [s for s in slots if s.endswith("_cred")]
V = {}
def put(d, ss, code):
    for s in ss.split():
        V[(d, s)] = code

put("posix", "truncate_path space query_checksum", "seam")
put("posix", "recall residency", "np")
# C2: the online copy is the ONLY copy (sd.h evict contract) - evicting a
# flat export is a delete wearing a different verb, so the slot stays NULL.
put("posix", "evict", "nil")
# C4: the kernel has no batch unlink; the VFS per-key loop issues the
# same n unlinkat(2) calls a slot would, so there is nothing to amortize.
put("posix", "unlink_many", "np")
put("posix", "enumerate", "ns")
for s in CRED: V[("posix", s)] = "id"

put("pblock", "truncate_path truncate_path_cred query_checksum", "seam")

put("block", "cleanup", "nil")
put("block", "copy_range query_checksum", "seam")
put("block", "ftruncate unlink unlink_many mkdir rename exchange server_copy setattr truncate_path "
             "sync_publish "
             "getxattr listxattr setxattr removexattr staged_open staged_write "
             "staged_commit staged_abort staged_path", "flat")
put("block", "recall residency", "np")
put("block", "evict", "flat")
put("block", "enumerate", "ns")
for s in CRED: V[("block", s)] = "id"

put("ceph", "copy_range", "seam")
put("ceph", "read_advise server_copy server_copy_cred recall residency "
            "recall_cred "
            "sync_publish "
            "reserve", "np")
# C2: RADOS holds the only copy (sd.h evict contract), same as posix.
put("ceph", "evict evict_cred", "nil")  # librados has no preallocation call
# C6: librados has no atomic two-name swap (rename itself is copy+delete
# there); SS3.5 forbids emulating one, so the slot stays honestly absent.
put("ceph", "exchange exchange_cred", "np")
put("ceph", "staged_path", "path")
put("ceph", "staged_open_cred mkdir_cred rename_cred", "scope")

put("cephfs_ro", "pwrite copy_range ftruncate fsync unlink unlink_many mkdir rename "
                 "server_copy setattr truncate_path setxattr removexattr "
                 "sync_publish reserve "
                 "staged_open staged_write staged_commit staged_abort "
                 "staged_path", "ro")
put("cephfs_ro", "exchange", "ro")
put("cephfs_ro", "preadv2 query_checksum", "seam")
put("cephfs_ro", "read_sendfile_fd read_advise recall residency", "np")
put("cephfs_ro", "evict", "ro")
put("cephfs_ro", "enumerate", "ns")
for s in CRED: V[("cephfs_ro", s)] = "ro"

put("frm", "init cleanup", "nil")
put("frm", "staged_path", "path")
put("frm", "enumerate", "np")
put("frm", "pwrite preadv preadv2 copy_range read_sendfile_fd ftruncate fsync "
           "read_advise unlink unlink_many rename server_copy setattr truncate_path "
           "getxattr listxattr setxattr removexattr "
           "space query_checksum", "tier")
# C5: frm's own staged_open reserves on the posix shell (sd_frm_staged.c),
# so the object-keyed slot is carried by the staged plane, not missing.
put("frm", "reserve", "sup")
for s in CRED:
    if s != "recall_cred":               # C2: implemented (tape-ledger attribution)
        V[("frm", s)] = "id"

put("http", "init cleanup", "nil")
put("http", "pwrite preadv2 read_sendfile_fd ftruncate fsync read_advise "
            "truncate_path truncate_path_cred sync_publish "
            "reserve", "np")  # no HTTP/WebDAV verb preallocates space
put("http", "copy_range", "sup")
# C2: the Tape REST release verb is reqid-scoped (POST /release/{id}), so a
# path-keyed evict cannot name the pin to drop - no honest wire mapping.
put("http", "evict evict_cred", "np")
# C4: neither HTTP nor WebDAV defines a batch DELETE verb.
put("http", "unlink_many unlink_many_cred", "np")
# C6: WebDAV MOVE is single-name; no wire verb swaps two names atomically
# and SS3.5 forbids the two-MOVE emulation.
put("http", "exchange exchange_cred", "np")
put("http", "staged_path", "path")
put("http", "enumerate", "ns")

put("remote", "init cleanup", "nil")
put("remote", "pwrite preadv2 read_sendfile_fd ftruncate fsync read_advise "
              "truncate_path truncate_path_cred space sync_publish", "np")
put("remote", "copy_range", "sup")
# C2: a GLACIER restore expires on its own (RestoreObject Days); S3 has no
# verb to drop the restored copy early.
put("remote", "evict evict_cred", "np")
# C5: staged_open(declared_size) carries the declaration - it sizes the
# multipart parts (sd_remote_part_size), which is S3's whole reserve story.
put("remote", "reserve", "sup")
# C6: S3 has no rename, let alone an atomic two-name swap.
put("remote", "exchange exchange_cred", "np")
put("remote", "staged_path", "path")

put("xroot", "init cleanup", "nil")
put("xroot", "copy_range", "sup")
# C5: staged_open(declared_size) forwards the declaration as oss.asize on
# the remote kXR open (sd_xroot_staged.c) - the origin runs its own reserve.
put("xroot", "reserve", "sup")
put("xroot", "preadv2 read_sendfile_fd read_advise sync_publish", "np")
# C4: the kXR wire has one kXR_rm per request - no batch form.
put("xroot", "unlink_many unlink_many_cred", "np")
# C6: kXR_mv is single-pair with no exchange option; SS3.5 forbids emulation.
put("xroot", "exchange exchange_cred", "np")
put("xroot", "staged_path", "path")
put("xroot", "enumerate", "ns")

put("cache", "init cleanup", "nil")
put("cache", "pwrite preadv preadv2 copy_range ftruncate fsync", "dec")
put("cache", "staged_path", "path")
put("cache", "recall recall_cred residency query_checksum enumerate", "walk")

put("stage", "init cleanup", "nil")
put("stage", "preadv preadv2 copy_range read_sendfile_fd read_advise", "dec")
put("stage", "staged_path", "path")
put("stage", "recall recall_cred residency query_checksum enumerate", "walk")

put("mirage", "cleanup", "nil")
put("mirage", "pwrite copy_range ftruncate fsync unlink unlink_many mkdir rename exchange "
              "server_copy setattr truncate_path setxattr removexattr "
              "sync_publish "
              "staged_open staged_write staged_commit staged_abort "
              "staged_path", "syn")
put("mirage", "evict", "syn")
put("mirage", "preadv2 read_sendfile_fd read_advise opendir readdir closedir "
              "getxattr listxattr recall residency space query_checksum "
              "reserve", "syn")
put("mirage", "enumerate", "syn")
for s_ in CRED: V[("mirage", s_)] = "syn"

# Commit-time content dedup (phase-88 W1) is a CACHE-STORE verb: gcas.c calls it
# on cs->store->driver, never down a decorator chain, so only a driver that can
# BE a brix_cache_store is ever asked. posix publishes into the /.gcas hardlink
# farm; pblock folds byte-identical blobs through F10 refs, whose refcount also
# reaps the alias — dedup_gc NULL is the contract, not an omission (sd.h).
put("pblock", "dedup_gc", "refc")
for d_ in ("block", "mirage", "ceph", "cephfs_ro", "frm", "http", "remote",
           "xroot", "cache", "stage"):
    put(d_, "dedup_publish dedup_gc", "cas")

miss = [(d, s) for d in order for s in slots if s not in drv[d] and (d, s) not in V]
extra = [(d, s) for (d, s) in V if s in drv[d]]
if miss or extra:
    print("UNCODED:", miss, file=sys.stderr)
    print("CODED-BUT-PRESENT:", extra, file=sys.stderr)
    sys.exit(1)

GAP = "**⚠**"
rows = ["| op | " + " | ".join(short.get(d, d) for d in order) + " |",
        "|---|" + "---|" * len(order)]
for s in slots:
    cells = []
    for d in order:
        cells.append("✅" if s in drv[d] else (GAP if V[(d, s)] == "GAP" else V[(d, s)]))
    rows.append("| `%s` | " % s + " | ".join(cells) + " |")
tot = {d: sum(1 for s in slots if s in drv[d]) for d in order}
rows.append("| **implemented** | " + " | ".join("**%d**" % tot[d] for d in order) + " |")
gaps = sum(1 for k, v in V.items() if v == "GAP")
rows.append("")
rows.append("_%d slots x %d drivers = %d cells: %d implemented, %d open gaps (marked ⚠)._"
            % (len(slots), len(order), len(slots)*len(order), sum(tot.values()), gaps))
pathlib.Path(sys.argv[1]).write_text("\n".join(rows) + "\n")
print("\n".join(rows[-2:]))

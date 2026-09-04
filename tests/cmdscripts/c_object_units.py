"""Python ports for C unit runners that link built module objects."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run
from cmdscripts.command_results import print_results

# Honour NGX_SRC (mirroring c_regression_units.py) so the unit runners link
# against whichever configured build tree the caller points at — the shared
# /tmp/nginx-1.28.3 by default, or a private tree during concurrent-session work.
def _expression_1(spec):
    return (
        [str(path) for path in spec.required if not path.is_file()]
    )

def _expression_2(name, built):
    return (
        [result(False, f"compile {name} failed: {(built.stderr or built.stdout)[-3000:]}")]
    )

def _expression_3(ran, name):
    return (
        [result(ran.returncode == 0, f"{name} exited {ran.returncode}: {(ran.stderr or ran.stdout)[-3000:]}")]
    )


NGX_SRC = Path(os.environ.get("NGX_SRC", "/tmp/nginx-1.28.3"))
OBJS = NGX_SRC / "objs"


@dataclass(frozen=True)
class ObjectUnitSpec:
    name: str
    binary: str
    required: tuple[Path, ...]
    args: tuple[str, ...]


def addon(path: str) -> Path:
    return OBJS / "addon" / path


def _inc(*dirs) -> tuple[str, ...]:
    """Interleave ``-I`` flags for `dirs` (Paths or strings), in order."""
    flags: list[str] = []
    for d in dirs:
        flags += ["-I", str(d)]
    return tuple(flags)


# The nginx header sets the object-linked units compile against, in the same
# order the build tree uses; HTTP adds the stream/http trees for specs whose
# structs reach past them.
_NGX_CORE_INC = (NGX_SRC / "src/core", NGX_SRC / "src/event",
                 NGX_SRC / "src/event/modules", NGX_SRC / "src/event/quic",
                 NGX_SRC / "src/os/unix")
_NGX_HTTP_INC = (NGX_SRC / "src/stream", NGX_SRC / "src/http",
                 NGX_SRC / "src/http/modules")
# ngx_string/palloc/alloc: the three libngx objects ngx_link_stubs.c leans on.
_NGX_LIB_OBJS = (str(NGX_SRC / "objs/src/core/ngx_string.o"),
                 str(NGX_SRC / "objs/src/core/ngx_palloc.o"),
                 str(NGX_SRC / "objs/src/os/unix/ngx_alloc.o"))


SPECS: dict[str, ObjectUnitSpec] = {
    "cache_admit": ObjectUnitSpec(
        "cache_admit",
        "test_cache_admit",
        (addon("cache/cache_admit.o"),),
        ("-O", "-Wall", "tests/c/test_cache_admit.c", str(addon("cache/cache_admit.o"))),
    ),
    "cache_storage": ObjectUnitSpec(
        "cache_storage",
        "test_cache_storage",
        (addon("cache/cache_key.o"),),
        ("-O", "-Wall", "tests/c/test_cache_storage.c", str(addon("cache/cache_key.o"))),
    ),
    "cinfo": ObjectUnitSpec(
        "cinfo",
        "test_cinfo",
        (
            addon("cache/cinfo.o"),
            addon("meta/xmeta.o"),
            addon("meta/xmeta_path.o"),
            addon("meta/xmeta_decode.o"),
            addon("meta/xmeta_encode.o"),
            addon("meta/xmeta_carrier.o"),
            addon("compat/crc32c.o"),
            addon("compat/crc32c_hw.o"),
        ),
        (
            "-O",
            "-Wall",
            "tests/c/test_cinfo.c",
            str(addon("cache/cinfo.o")),
            str(addon("meta/xmeta.o")),
            str(addon("meta/xmeta_path.o")),
            str(addon("meta/xmeta_decode.o")),
            str(addon("meta/xmeta_encode.o")),
            str(addon("meta/xmeta_carrier.o")),
            str(addon("compat/crc32c.o")),
            str(addon("compat/crc32c_hw.o")),
        ),
    ),
    "slice": ObjectUnitSpec(
        "slice",
        "test_slice",
        (addon("cache/slice.o"), addon("cache/meta.o")),
        ("-O", "-Wall", "tests/c/test_slice.c", str(addon("cache/slice.o")), str(addon("cache/meta.o"))),
    ),
    # POSC crash-orphan reaper policy (ofs.persist analog, §1.9). Links the real
    # tmp_path.o; the test stubs the 3 non-libc symbols it names but never drives.
    "tmp_reap": ObjectUnitSpec(
        "tmp_reap",
        "test_tmp_reap",
        (addon("compat/tmp_path.o"),),
        ("-O", "-Wall", "tests/c/test_tmp_reap.c", str(addon("compat/tmp_path.o"))),
    ),
    # Per-worker (sessid,pathid)->conn offload map (§1.1 slice 1). Pure C, no deps.
    "offload_registry": ObjectUnitSpec(
        "offload_registry",
        "test_offload_registry",
        (addon("session/offload_registry.o"),),
        ("-O", "-Wall",
         "-I", str(REPO_ROOT / "src/protocols/root/session"),
         "tests/c/test_offload_registry.c",
         str(addon("session/offload_registry.o"))),
    ),
    # The live-prefix mark on the SHM session registry.  registry_slots.o names
    # five cross-TU symbols (the two ratelimit key formatters, the metrics
    # accessor, the handle-table unpublish, ngx_worker); the test supplies each
    # as a spy, so the battery links the one real object and stays hermetic.
    "session_registry_high_water": ObjectUnitSpec(
        "session_registry_high_water",
        "test_session_registry_high_water",
        (addon("session/registry_slots.o"),),
        ("-O", "-Wall", "-D_GNU_SOURCE",   # in6_pktinfo, as the real build does
         *_inc(REPO_ROOT / "src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC,
               *_NGX_HTTP_INC),
         "tests/c/test_session_registry_high_water.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("session/registry_slots.o")),
         *_NGX_LIB_OBJS),
    ),
    # Round 15's registry slot hint. Unlike the high_water unit above — which
    # models register/unregister locally against registry_slots.o — this one
    # links the REAL registry.o so brix_session_unregister_hinted() itself is
    # under test, including the divergence that makes the hint safer than the
    # scan it replaces (a stale hint must not destroy a re-registration).
    "session_unregister_hint": ObjectUnitSpec(
        "session_unregister_hint",
        "test_session_unregister_hint",
        (addon("session/registry.o"), addon("session/registry_slots.o"),
         addon("compat/shm_slots.o"), OBJS / "src/core/ngx_shmtx.o"),
        ("-O", "-Wall", "-D_GNU_SOURCE",   # in6_pktinfo, as the real build does
         *_inc(REPO_ROOT / "src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC,
               *_NGX_HTTP_INC),
         "tests/c/test_session_unregister_hint.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("session/registry.o")),
         str(addon("session/registry_slots.o")),
         str(addon("compat/shm_slots.o")),
         str(OBJS / "src/core/ngx_shmtx.o"),
         *_NGX_LIB_OBJS, "-pthread"),
    ),
    "cstore_scan_enumerate": ObjectUnitSpec(
        "cstore_scan_enumerate",
        "test_cstore_scan_enumerate",
        (addon("cache/cstore_scan.o"),),
        ("-O", "-Wall",
         *_inc(REPO_ROOT / "src", REPO_ROOT / "src/fs/cache",
               REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC),
         "tests/c/test_cstore_scan_enumerate.c",
         str(addon("cache/cstore_scan.o"))),
    ),
    # The catalog verb's decorator walk. vfs_walk.o's cross-TU closure is small
    # enough (resolve/fill_stat/*_beneath/*_confined_canon) that the harness
    # stubs it outright and links the ONE real object, keeping the enumeration
    # hermetic — no pool, no backend registry, no filesystem.
    "vfs_enumerate_decorator": ObjectUnitSpec(
        "vfs_enumerate_decorator",
        "test_vfs_enumerate_decorator",
        (addon("vfs/vfs_walk.o"),),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC),
         "tests/c/test_vfs_enumerate_decorator.c",
         str(addon("vfs/vfs_walk.o"))),
    ),
    # Phase-105 K.4: the five real VFS mutation TUs on top of the real policy
    # kernel, with their whole cross-TU closure supplied as counting stubs — the
    # namespace layer, the confined-path syscalls, the leaf/credential resolvers
    # and the cache evictor. That closure is what makes "no mutating slot was
    # reached" observable at all; a wire test can only see the response. The
    # nginx string/pool objects come along for ngx_snprintf, the one libngx
    # symbol the mutation TUs name.
    "vfs_read_only_spy": ObjectUnitSpec(
        "vfs_read_only_spy",
        "test_vfs_read_only_spy",
        (
            addon("vfs/vfs_mkdir.o"),
            addon("vfs/vfs_unlink.o"),
            addon("vfs/vfs_rename.o"),
            addon("vfs/vfs_copy.o"),
            addon("vfs/vfs_xattr.o"),
            addon("vfs/vfs_policy.o"),
            addon("vfs/vfs_authz.o"),
        ),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC),
         "tests/c/test_vfs_read_only_spy.c",
         # ngx_string/palloc/alloc reference these two globals; the shared
         # stub file is the sanctioned way to satisfy them.
         "tests/c/ngx_link_stubs.c",
         str(addon("vfs/vfs_mkdir.o")),
         str(addon("vfs/vfs_unlink.o")),
         str(addon("vfs/vfs_rename.o")),
         str(addon("vfs/vfs_copy.o")),
         str(addon("vfs/vfs_xattr.o")),
         str(addon("vfs/vfs_policy.o")),
         str(addon("vfs/vfs_authz.o")),
         "tests/c/vfs_phase108_link_stubs.c",
         *_NGX_LIB_OBJS),
    ),
    # Phase-108 C12: the real backstop evaluator shell with identity/rule,
    # metric and policy dependencies supplied as deterministic spies. Covers
    # success, observe/enforce refusal, no-rules/unbound distinction, two-name
    # mapping, read authorization and the EROFS-before-EACCES ordering tape.
    "vfs_authz_backstop": ObjectUnitSpec(
        "vfs_authz_backstop",
        "test_vfs_authz_backstop",
        (addon("vfs/vfs_authz.o"),),
        ("-O", "-Wall", "-Wextra", "-Werror",
         *_inc("src", REPO_ROOT / "shared", OBJS,
               *_NGX_CORE_INC, *_NGX_HTTP_INC),
         "tests/c/test_vfs_authz_backstop.c",
         str(addon("vfs/vfs_authz.o"))),
    ),
    # The phase-107 W2/W3 verbs (recall/evict/delete_many) over the real policy
    # kernel, with the §3.4 ordering assertion (vfs_order_spy.h) wired in:
    # dispatch DIRECTION (recall descends, evict stays on top), the C4
    # one-batch-call-per-window rule, and EROFS-before-ENOTSUP/EACCES with a
    # zero-sink, policy-only ordering tape on refusal. vfs_unlink.o rides along
    # because vfs_unlink_many.o's rmtree dispatch and its per-key walk are
    # mutually referential across the two TUs.
    "vfs_new_mutator_gate": ObjectUnitSpec(
        "vfs_new_mutator_gate",
        "test_vfs_new_mutator_gate",
        (
            addon("vfs/vfs_recall.o"),
            addon("vfs/vfs_unlink_many.o"),
            addon("vfs/vfs_unlink.o"),
            addon("vfs/vfs_sync.o"),
            addon("vfs/vfs_policy.o"),
            addon("vfs/vfs_authz.o"),
        ),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC),
         "tests/c/test_vfs_new_mutator_gate.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("vfs/vfs_recall.o")),
         str(addon("vfs/vfs_unlink_many.o")),
         str(addon("vfs/vfs_unlink.o")),
         str(addon("vfs/vfs_sync.o")),
         str(addon("vfs/vfs_policy.o")),
         str(addon("vfs/vfs_authz.o")),
         "tests/c/vfs_phase108_link_stubs.c",
         *_NGX_LIB_OBJS),
    ),
    # The handle-plane release/durability dispatch: the real vfs_open_handle.o
    # + vfs_sync.o over the real policy kernel, with a counting spy driver and
    # a spy executor. Pins the fix for the memory-served close leak (a root://
    # write handle surviving its committed STOR) and the fd-less fsync dispatch.
    "vfs_handle_close_dispatch": ObjectUnitSpec(
        "vfs_handle_close_dispatch",
        "test_vfs_handle_close_dispatch",
        (
            addon("vfs/vfs_open_handle.o"),
            addon("vfs/vfs_sync.o"),
            addon("vfs/vfs_policy.o"),
        ),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC,
               *_NGX_HTTP_INC),
         "tests/c/test_vfs_handle_close_dispatch.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("vfs/vfs_open_handle.o")),
         str(addon("vfs/vfs_sync.o")),
         str(addon("vfs/vfs_policy.o"))),
    ),
    # Phase-107 W1 (C8/C9): the typed storage-domain assert. The real
    # vfs_policy_domain.o over the real kernel; the denial metric AND
    # ngx_log_error_core are counting spies, so the crit log line the
    # wrong-domain refusal promises is asserted, not assumed.
    "vfs_service_domain": ObjectUnitSpec(
        "vfs_service_domain",
        "test_vfs_service_domain",
        (
            addon("vfs/vfs_policy_domain.o"),
            addon("vfs/vfs_policy.o"),
        ),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC),
         "tests/c/test_vfs_service_domain.c",
         str(addon("vfs/vfs_policy_domain.o")),
         str(addon("vfs/vfs_policy.o"))),
    ),
    # Phase-107 W2 (C1): the writer's reorder-spill engine. The real
    # vfs_writer_spill.o with its whole cross-TU closure supplied as spies —
    # the backend-registry spill lookup, the owned-temp namer, the staged
    # write/abort sinks (the staged spy ASSERTS sequential offsets: the drain
    # contract IS the assertion) and the three spill metrics as counters.
    # pread/pwrite_full are real loops over the scratch fd, so the reverse-order
    # drain case proves byte-exactness against a reference buffer.
    "vfs_writer_spill": ObjectUnitSpec(
        "vfs_writer_spill",
        "test_vfs_writer_spill",
        (addon("vfs/vfs_writer_spill.o"),),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC,
               *_NGX_HTTP_INC),
         "tests/c/test_vfs_writer_spill.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("vfs/vfs_writer_spill.o")),
         *_NGX_LIB_OBJS),
    ),
    # The phase-105 mutation-policy kernel. vfs_policy.o names exactly ONE
    # cross-TU symbol (brix_metric_vfs_mutation_denied), which the test supplies
    # as a spy, so the battery links the one real object and stays hermetic —
    # and the denial counter is observed directly rather than inferred.
    "vfs_mutation_policy": ObjectUnitSpec(
        "vfs_mutation_policy",
        "test_vfs_mutation_policy",
        (addon("vfs/vfs_policy.o"),),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC),
         "tests/c/test_vfs_mutation_policy.c",
         str(addon("vfs/vfs_policy.o"))),
    ),
    "vfs_caps": ObjectUnitSpec(
        "vfs_caps",
        "test_vfs_caps",
        (addon("backend/sd_registry.o"),),
        ("-O", "-Wall",
         *_inc("src", *_NGX_CORE_INC, OBJS),
         "tests/c/test_vfs_caps.c",
         str(addon("backend/sd_registry.o"))),
    ),
    # phase-107 C2 (W6): the startup advisor probe on synthetic chains — the
    # unstageable shape (CAP_NEARLINE, no recall slot) is unconstructible from a
    # live config (every shipped nearline driver has the slot), so the probe's
    # truth table is only reachable here. Links the real vfs_recall.o.
    "vfs_nearline_probe": ObjectUnitSpec(
        "vfs_nearline_probe",
        "test_vfs_nearline_probe",
        (addon("vfs/vfs_recall.o"),),
        ("-O", "-Wall",
         *_inc("src", *_NGX_CORE_INC, OBJS),
         "tests/c/test_vfs_nearline_probe.c",
         str(addon("vfs/vfs_recall.o"))),
    ),
    # Pelican OriginAdvertiseV2 payload builders (build_ad / caps_json / rfc3339)
    # linked against the real object; -ljansson for the document, -lcurl/-lcrypto
    # resolve pelican_register.o's own libcurl + OpenSSL references (the advertise
    # path is stubbed out in the harness but the object still names them).
    "pelican_ad": ObjectUnitSpec(
        "pelican_ad",
        "test_pelican_ad",
        (addon("origin/pelican_register.o"),),
        (
            "-O",
            "-Wall",
            # The advertise sub-struct sits past feature-gated fields in
            # ngx_stream_brix_srv_conf_t, so the harness MUST see the same
            # BRIX_HAVE_* defines the object was compiled with or the struct
            # layout skews and field reads land on the wrong offsets.
            "-DBRIX_HAVE_LIBXML2=1",
            "-DBRIX_HAVE_JANSSON=1",
            "-DBRIX_HAVE_KRB5=1",
            "-DBRIX_HAVE_SECCOMP=1",
            "-DBRIX_HAVE_ZLIB=1",
            "-DBRIX_HAVE_ZSTD=1",
            "-DBRIX_HAVE_LZMA=1",
            "-DBRIX_HAVE_BROTLI=1",
            "-DBRIX_HAVE_BZIP2=1",
            "-DBRIX_HAVE_LZ4=1",
            "-DBRIX_HAVE_SQLITE=1",
            *_inc("/usr/include/libxml2", "src", *_NGX_CORE_INC,
                  NGX_SRC / "src/http", NGX_SRC / "src/http/modules",
                  NGX_SRC / "src/stream", OBJS),
            "tests/c/pelican_ad_test.c",
            str(addon("origin/pelican_register.o")),
            "-ljansson",
            "-lcurl",
            "-lcrypto",
        ),
    ),
    # Phase-107 C3 durable-publish barrier: the REAL staged_file.o + beneath.o
    # (the confined-fd machinery IS the security case), with fsync interposed
    # via --wrap so "one dirsync, on the PARENT of the published path" is
    # asserted by inode. Spies: the impersonation broker (inactive), the tmp/
    # resume namers, and a switchable brix_vfs_backend_durable.
    "publish_dirsync": ObjectUnitSpec(
        "publish_dirsync",
        "test_publish_dirsync",
        (addon("compat/staged_file.o"), addon("path/beneath.o")),
        ("-O", "-Wall",
         *_inc("src", OBJS, *_NGX_CORE_INC),
         "-Wl,--wrap=fsync",
         "tests/c/test_publish_dirsync.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("compat/staged_file.o")),
         str(addon("path/beneath.o"))),
    ),
    # Phase-107 C6 atomic two-name exchange: the REAL namespace_ops.o +
    # beneath.o (renameat2(RENAME_EXCHANGE) through the confined rootfd).
    # No protocol verb reaches brix_vfs_exchange yet (OCI tag flip is
    # phase-108), so this unit is the verb's only behavior coverage: inode-swap
    # atomicity witness, both-must-exist ENOENT, EXDEV confinement (either
    # name, plus the prefix-boundary trap), file<->dir type-agnosticism.
    "vfs_exchange": ObjectUnitSpec(
        "vfs_exchange",
        "test_vfs_exchange",
        (addon("compat/namespace_ops.o"), addon("path/beneath.o")),
        ("-O", "-Wall",
         *_inc("src", OBJS, *_NGX_CORE_INC),
         "tests/c/test_vfs_exchange.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("compat/namespace_ops.o")),
         str(addon("path/beneath.o"))),
    ),
    # The metadata-hot-path syscall reductions: ns_delete_fast (probe-free
    # non-recursive delete classified from the unlinkat errno), the borrowed
    # persistent-rootfd entry points brix_ns_delete_at/brix_ns_mkdir_at (the
    # handed-in fd must survive every call, including the single-component
    # root-borrow arm of beneath_open_parent), and brix_realpath_existing
    # (realpath(3) parity via one open(O_PATH) + /proc/self/fd readback —
    # including the escaping-symlink case the stat fallback's prefix check
    # depends on). REAL namespace_ops.o + beneath.o + canonical.o; the
    # brix_fs_dir_is_empty abort stub proves no getdents pre-probe runs.
    "ns_fastpath": ObjectUnitSpec(
        "ns_fastpath",
        "test_ns_fastpath",
        (
            addon("compat/namespace_ops.o"),
            addon("path/beneath.o"),
            addon("path/canonical.o"),
        ),
        ("-O", "-Wall",
         *_inc("src", OBJS, *_NGX_CORE_INC),
         "tests/c/test_ns_fastpath.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("compat/namespace_ops.o")),
         str(addon("path/beneath.o")),
         str(addon("path/canonical.o"))),
    ),
    # The shared handle table's high-water mark: every scan (publish/lookup/
    # unpublish/unpublish_all) is bounded by the peak LIVE population instead
    # of walking all 4096 ~4KB shm slots (25% of worker CPU on open-heavy
    # loads pre-fix). REAL handles.o + shm_slots.o + ngx_shmtx.o; the unit
    # reads tbl->high_water directly across the whole lifecycle, including
    # full-table refusal and the stale-hint revocation security case.
    "handle_high_water": ObjectUnitSpec(
        "handle_high_water",
        "test_handle_high_water",
        (
            addon("session/handles.o"),
            addon("compat/shm_slots.o"),
            OBJS / "src/core/ngx_shmtx.o",
        ),
        ("-O", "-Wall",
         *_inc("src", OBJS, *_NGX_CORE_INC, *_NGX_HTTP_INC),
         "tests/c/test_handle_high_water.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("session/handles.o")),
         str(addon("compat/shm_slots.o")),
         str(OBJS / "src/core/ngx_shmtx.o"),
         *_NGX_LIB_OBJS,
         "-pthread"),
    ),
    # Round 14: the publish-time slot hint that turns the per-handle teardown
    # from an O(live prefix) scan under the cross-worker handle mutex into an
    # O(1) direct clear. At disconnect that scan ran AFTER the session's entries
    # were already cleared, so it was guaranteed to find nothing — a cost that
    # grew with concurrency instead of backing off. The hint is authoritative
    # (entries are cleared in place, never relocated), so the unit's security
    # case is the one that matters: a stale hint whose slot was REUSED by
    # another session must not clear that session's entry.
    "handle_unpublish_hint": ObjectUnitSpec(
        "handle_unpublish_hint",
        "test_handle_unpublish_hint",
        (
            addon("session/handles.o"),
            addon("compat/shm_slots.o"),
            OBJS / "src/core/ngx_shmtx.o",
        ),
        ("-O", "-Wall",
         *_inc("src", OBJS, *_NGX_CORE_INC, *_NGX_HTTP_INC),
         "tests/c/test_handle_unpublish_hint.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("session/handles.o")),
         str(addon("compat/shm_slots.o")),
         str(OBJS / "src/core/ngx_shmtx.o"),
         *_NGX_LIB_OBJS,
         "-pthread"),
    ),
    # Phase-107 C7: the cross-protocol lock gate's four expiry states (absent /
    # live-owned / live-foreign / expired-unreaped), ancestor coverage rules,
    # the three enforcement modes, and strict's fail-closed on an unreadable
    # record. Links the REAL gate + the REAL record codec; the quiet xattr
    # read, registry mode lookup and refusal metric are counting stubs — which
    # is what makes "OFF reads nothing" and "expired is not reaped" observable.
    "vfs_lock_gate": ObjectUnitSpec(
        "vfs_lock_gate",
        "test_vfs_lock_gate",
        (addon("vfs/vfs_lock_gate.o"), addon("compat/lock_record.o")),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC,
               *_NGX_HTTP_INC),
         "tests/c/test_vfs_lock_gate.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("vfs/vfs_lock_gate.o")),
         str(addon("compat/lock_record.o")),
         *_NGX_LIB_OBJS),
    ),
    # Phase-107 C6: the publish-precondition evaluator every stat-grammar
    # commit path shares (seven callsites across posix/frm/pblock and the VFS
    # compat arm). The evaluator formats its own tag instead of calling the
    # generator, so the REAL http/etag.o is linked and the two grammars are
    # compared rather than assumed — plus the refusal edges (prefix, length-vs-
    # NUL, bare W/, NULL tag, untaught kind) that decide whether If-Match is a
    # guarantee or a formality. Header-inline body + an ngx-free object, so the
    # unit links exactly the two real bodies and nothing else.
    "sd_precond": ObjectUnitSpec(
        "sd_precond",
        "test_sd_precond",
        (addon("http/etag.o"),),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC),
         "tests/c/test_sd_precond.c",
         str(addon("http/etag.o"))),
    ),
    # Phase-107 C4: the RECURSIVE arm of bulk delete — the per-level rmtree
    # chunker and its accumulation window — over a fake in-memory namespace.
    # test_vfs_new_mutator_gate covers the flat brix_vfs_delete_many entry; the
    # walk's correctness is an ORDERING property between two driver slots across
    # recursion levels (children gone before their directory) that a wire test
    # cannot observe, plus the window split ON the constant and the ECANCELED
    # pre-fill that keeps an untried key from ever reading as deleted.
    "vfs_bulk_chunker": ObjectUnitSpec(
        "vfs_bulk_chunker",
        "test_vfs_bulk_chunker",
        (addon("vfs/vfs_unlink_many.o"),),
        ("-O", "-Wall",
         *_inc("src", REPO_ROOT / "shared", OBJS, *_NGX_CORE_INC,
               *_NGX_HTTP_INC),
         "tests/c/test_vfs_bulk_chunker.c",
         "tests/c/ngx_link_stubs.c",
         str(addon("vfs/vfs_unlink_many.o")),
         *_NGX_LIB_OBJS),
    ),
}


def coverage_flags(required: tuple[Path, ...]) -> list[str]:
    """``--coverage`` iff the module objects were compiled with it.

    A tree configured for gcov (the coverage lane) emits a ``.gcno`` beside every
    object and leaves ``__gcov_init``/``__gcov_merge_add`` references in it. The
    unit harness links those objects directly, so without the gcov runtime the
    link dies on undefined ``__gcov_*`` — a failure of the BUILD TREE's flags,
    not of the code under test. Keyed off the ``.gcno`` so a normal tree links
    exactly as before.
    """
    return ["--coverage"] if any(obj.with_suffix(".gcno").is_file()
                                 for obj in required) else []


def run_one(name: str, base: Path) -> list[tuple[bool, str]]:
    spec = SPECS[name]
    missing = _expression_1(spec)
    if missing:
        return [result(True, f"SKIP {name}: build required object(s) first: {', '.join(missing)}")]
    binary = base / spec.binary
    built = compile_binary(binary, list(spec.args) + coverage_flags(spec.required),
                           cwd=REPO_ROOT)
    if built.returncode != 0:
        return _expression_2(name, built)
    # detect_leaks=0: an object-linked unit that inherits -fsanitize=address from
    # a contaminated tree must not fail on LeakSanitizer's exit report; real heap
    # errors still abort.
    ran = run([str(binary)], cwd=REPO_ROOT, env={"ASAN_OPTIONS": "detect_leaks=0"})
    return _expression_3(ran, name)


def run_checks(base: Path, names: list[str] | None = None) -> list[tuple[bool, str]]:
    selected = names or sorted(SPECS)
    results: list[tuple[bool, str]] = []
    for name in selected:
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.extend(run_one(name, work))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    names = argv or sorted(SPECS)
    with tempfile.TemporaryDirectory(prefix="c_object_units.") as tmp:
        results = run_checks(Path(tmp), names=names)
    return print_results(results, "c_object_units")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))

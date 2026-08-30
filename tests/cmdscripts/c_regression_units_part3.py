"""Python ports for object-linked C regression shell runners."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

from cmdscripts.compile_run import REPO_ROOT, result, run
from cmdscripts.command_results import print_results


DEFAULT_NGX_SRC = Path(os.environ.get(
    "NGX_SRC",
    "/tmp/nginx-1.28.3" if Path("/tmp/nginx-1.28.3/src/core/ngx_config.h").exists()
    else "/tmp/nginx-1.24.0",
))
TEST_C = REPO_ROOT / "tests" / "c"


def sd_remote_server_copy(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->server_copy -> sd_remote_server_copy -> sd_s3_copy -> transport.
    # Same object closure as sd_remote_wrongkind (the copy path lives in
    # sd_remote_meta.o + sd_s3_meta.o and signs via sd_s3_sign.o); sd_s3_list.o
    # is pulled in transitively by sd_remote.o's dir slots.
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_server_copy",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_server_copy.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_opendir(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->opendir/readdir/closedir -> sd_remote_opendir -> sd_s3_list_page ->
    # transport. Same object closure as sd_remote_server_copy PLUS sd_s3_list.o
    # (the ListObjectsV2 pager + XML scanner) which the dir slots delegate to.
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_opendir",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_opendir.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_opendir_cred(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->opendir_cred -> sd_remote_dir.o, whose lazily-fetched pages are
    # signed by sd_s3_sign.o -- which is what makes the per-page signing identity
    # observable to the fake transport. Same object closure as sd_remote_opendir.
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_opendir_cred",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_opendir_cred.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_enumerate(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->enumerate -> sd_remote_enum.o -> sd_s3_list_flat.o (the UNDELIMITED
    # pager) over the sd_s3_list_scan.o request/XML kernels both listers share.
    # Same object closure as sd_remote_opendir.
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_enumerate",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_enumerate.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_rename(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->mkdir/rename/rename_cred/unlink + directory-aware stat -> the
    # sd_remote namespace-mutation slots (sd_remote_meta.o + sd_remote_write.o)
    # over sd_s3_copy/delete/open_write (sd_s3_meta.o + sd_s3_write.o) and the
    # empty-vs-non-empty child probe (sd_s3_list.o). Same object closure as
    # sd_remote_opendir.
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_rename",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_rename.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_setattr(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->setxattr/removexattr/setattr (+ _cred) -> the sd_remote metadata-
    # mutation slots (sd_remote_xattr.o) which read-merge-write the S3 user-meta
    # set via sd_s3_list_meta/get_meta/set_meta (sd_s3_meta.o) and patch the
    # advisory blob (meta_advisory.o). Same object closure as sd_remote_rename
    # plus sd_remote_xattr.o.
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_setattr",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_setattr.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_xattr_cred(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->getxattr_cred/listxattr_cred -> the sd_remote metadata READ slots
    # (sd_remote_meta.o) over sd_s3_get_meta/list_meta (sd_s3_meta.o), signed by
    # sd_s3_sign.o -- which is what makes the signing identity observable to the
    # fake transport. Same object closure as sd_remote_setattr.
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_xattr_cred",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_xattr_cred.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_checksum(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->query_checksum -> sd_remote_query_checksum (sd_remote_checksum.o),
    # which reads the digest the S3 store already holds off ONE signed HEAD
    # (sd_s3_get_checksum in sd_s3_meta.o, signed by sd_s3_sign_ext.o) and
    # normalises it through the shared RFC-3230 grammar (digest_header.o ->
    # nginx's base64 kernel, which is why the closure carries ngx_string.o).
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_checksum",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_checksum.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_http_dir(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->opendir/readdir/closedir (+ opendir_cred) -> sd_http_opendir
    # (sd_http_dir.o) which issues a WebDAV PROPFIND Depth:1 via sd_http_request_fo
    # (sd_http_select.o) and parses the 207 Multistatus. The driver table + create
    # live in sd_http.o; the cred gate/resolver in sd_http_read.o; the staged-PUT
    # slots the table references in sd_http_write.o (its Content-MD5 path pulls
    # EVP_* -> libcrypto). The ngx logging seam is stubbed in the test (instances
    # built log=NULL, so sd_http_live_log short-circuits and nothing logs).
    # The whole closure -- including the objects the driver TABLE names but this
    # test never calls -- is SD_HTTP_OBJS.
    objs = _sd_http_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_http_dir",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_dir.c"), *objs, *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_http_mutate(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->mkdir/rename -> sd_http_mkdir (WebDAV MKCOL) / sd_http_rename (MOVE)
    # in sd_http_write.o, wired into the driver table (sd_http.o) in phase-92 so an
    # http:// export advertises CAP_DIRS_WRITE + CAP_HARD_RENAME. Same link set as
    # sd_http_dir (SD_HTTP_OBJS; write.o pulls EVP_* -> libcrypto); the ngx logging
    # seam is stubbed in the test (instances built log=NULL, sd_http_live_log
    # short-circuits).
    objs = _sd_http_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_http_mutate",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_mutate.c"), *objs, *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_http_copy(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->server_copy/server_copy_cred -> sd_http_server_copy (sd_http_mutate.o),
    # a WebDAV COPY over the same absolute-Destination request MOVE uses, so an
    # intra-origin copy never round-trips the bytes through this host. Same link
    # set as sd_http_mutate (SD_HTTP_OBJS); the byte count comes from the stat in
    # sd_http_read.o.
    objs = _sd_http_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_http_copy",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_copy.c"), *objs, *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_http_digest(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->query_checksum -> sd_http_query_checksum (sd_http_digest.o): one
    # RFC-3230 `Want-Digest:` HEAD via sd_http_request_fo (sd_http_select.o),
    # answered from the origin's `Digest:` reply through the shared grammar
    # (digest_header.o), instead of dragging the whole object across the network
    # to hash it. Same closure as sd_http_dir (SD_HTTP_OBJS), which is where the
    # base64 decode's nginx objects come from -- the test therefore stubs no
    # ngx_string.c function of its own.
    objs = _sd_http_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_http_digest",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_digest.c"), *objs, *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_http_space(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->space -> sd_http_space (sd_http_space.o): the ORIGIN's RFC-4331
    # quota pair over one Depth:0 named-prop PROPFIND, so kXR_statvfs/Qspace/
    # QFSinfo/SRR stop reporting the statvfs of the gateway's own (empty) export
    # directory. Shares sd_http_dir.o's PROPFIND issuer and tag scanner, hence
    # the same SD_HTTP_OBJS closure as the other sd_http units.
    objs = _sd_http_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_http_space",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_space.c"), *objs, *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_http_readv(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->preadv -> sd_http_preadv (sd_http_readv.o): one coalesced ranged GET
    # per vector read, scattered across the caller's iovecs. Without the slot
    # brix_sd_obj_preadv falls back to one driver->pread per iovec, so a kXR_readv
    # or pgread batch became one HTTP round trip per 4 KiB. Same SD_HTTP_OBJS
    # closure as the other sd_http units (the driver table names every slot).
    objs = _sd_http_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_http_readv",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_readv.c"), *objs, *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_http_xattr(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->getxattr/listxattr/setxattr/removexattr (+ the _cred twins) ->
    # sd_http_xattr.o (read, PROPFIND) + sd_http_xattr_write.o (write,
    # PROPPATCH): xattrs on an http origin as RFC 4918 §15 dead properties, one
    # per xattr, name AND value hex-encoded. The hex is what the unit pins hard:
    # it is the reason a name or value of remote-chosen bytes cannot inject
    # markup into the request body. Same SD_HTTP_OBJS closure as the other
    # sd_http units, which now includes both new objects.
    objs = _sd_http_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_http_xattr",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_xattr.c"), *objs, *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_xroot_setattr(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->setattr/setattr_cred -> sd_xroot_setattr (sd_xroot_ns.o) ->
    # sd_xroot_setattr_cred (sd_xroot_ns_cred.o) -> brix_cache_origin_chmod
    # (origin_ns.o) -> the kXR_chmod body packer (wire_codec_ns.o). Without the
    # slot brix_vfs_chmod reported success without telling the origin anything,
    # so the unit pins the whole path down to the wire bytes: only the session
    # bootstrap and the two io primitives are stubbed. ngx_cpystrn comes from
    # nginx's own string kernel (SD_HTTP_NGX_OBJS + ngx_link_stubs.c), never a
    # local stub.
    objs: list[str] = []
    # wire_codec_session.o joined the closure when origin_ns.c grew the
    # kXR_prepare(kXR_stage) sender that drives sd_xroot's nearline recall: the
    # prepare body packer lives there, and origin_ns.o is linked whole.
    for name in ["sd_xroot_ns.o", "sd_xroot_ns_cred.o", "origin_ns.o",
                 "wire_codec_ns.o", "wire_codec_meta.o",
                 "wire_codec_session.o"]:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(str(obj))
    for rel in SD_HTTP_NGX_OBJS:
        obj = _need_obj(ngx_src, rel)
        if isinstance(obj, str):
            return result(True, obj)
        objs.append(str(obj))
    objs.append(str(TEST_C / "ngx_link_stubs.c"))
    return _compile_and_run(
        base / "test_sd_xroot_setattr",
        # -D_GNU_SOURCE: the stream include chain reaches ngx_event_udp.h, whose
        # struct in6_pktinfo is only declared under it.
        ["-O", "-Wall", "-D_GNU_SOURCE", str(TEST_C / "test_sd_xroot_setattr.c"), *objs,
         *_nginx_includes(ngx_src, http=True, stream=True), "-lssl", "-lcrypto"],
    )


def sd_xroot_query(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # The four root:// slots that ASK the origin something instead of moving
    # bytes: space (kXR_query/kXR_Qspace), query_checksum (kXR_Qcksum),
    # residency (kXR_stat + kXR_offline) and recall (kXR_prepare/kXR_stage).
    # query_checksum is file-static in sd_xroot.c, so the unit reaches all four
    # through the REAL vtable from brix_sd_xroot_create — which means the whole
    # driver is linked, not just the two files the slots live in: the table names
    # every slot, so sd_xroot.o's .rodata references the io, staged, ns, ns_cred
    # and ns_dir objects whether or not this unit calls one. origin_protocol.o
    # (the kXR_query client) joins origin_ns.o (kXR_stat, kXR_prepare) below it,
    # and only the socket is stubbed.
    objs: list[str] = []
    for name in ["sd_xroot.o", "sd_xroot_io.o", "sd_xroot_staged.o",
                 "sd_xroot_ns.o", "sd_xroot_ns_cred.o", "sd_xroot_ns_dir.o",
                 "sd_xroot_nearline.o",
                 "origin_ns.o", "origin_ns_dirlist.o", "origin_protocol.o",
                 "wire_codec_ns.o", "wire_codec_meta.o",
                 "wire_codec_session.o", "wire_codec_file.o"]:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(str(obj))
    for rel in SD_HTTP_NGX_OBJS:
        obj = _need_obj(ngx_src, rel)
        if isinstance(obj, str):
            return result(True, obj)
        objs.append(str(obj))
    objs.append(str(TEST_C / "ngx_link_stubs.c"))
    return _compile_and_run(
        base / "test_sd_xroot_query",
        # -D_GNU_SOURCE: as for the setattr unit, the stream include chain
        # reaches ngx_event_udp.h and its struct in6_pktinfo.
        ["-O", "-Wall", "-D_GNU_SOURCE", str(TEST_C / "test_sd_xroot_query.c"), *objs,
         *_nginx_includes(ngx_src, http=True, stream=True), "-lssl", "-lcrypto"],
    )


def sd_block_space(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # The block driver's capacity report. sd_block_space lives in the namespace
    # plane (sd_block_ns.o), which needs an nginx pool and so compiles only in the
    # module build — the ngx-free unity unit in tests/unit that #includes
    # sd_block.c cannot reach it. Linking the objects instead costs three nginx
    # core files and two stubs: sd_block.o's vtable names the POSIX driver it
    # delegates its opens to, and nothing here opens an extent.
    objs: list[str] = []
    for name in ["sd_block.o", "sd_block_ns.o"]:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(str(obj))
    for rel in SD_HTTP_NGX_OBJS:
        obj = _need_obj(ngx_src, rel)
        if isinstance(obj, str):
            return result(True, obj)
        objs.append(str(obj))
    objs.append(str(TEST_C / "ngx_link_stubs.c"))
    return _compile_and_run(
        base / "test_sd_block_space",
        ["-O", "-Wall", str(TEST_C / "test_sd_block_space.c"), *objs,
         *_nginx_includes(ngx_src)],
    )


def digest_header(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # The shared RFC-3230 Digest grammar (core/compat/digest_header.o -> hex.o),
    # parsed in both directions: a client's asserted PUT digest and an origin's
    # reply to the sd_http checksum offload. It is pool-free but decodes base64
    # with nginx's own ngx_decode_base64, so the nginx string kernel and its
    # allocator closure come along (SD_HTTP_NGX_OBJS).
    objs: list[str] = []
    for name in ["digest_header.o", "hex.o"]:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(str(obj))
    for rel in SD_HTTP_NGX_OBJS:
        obj = _need_obj(ngx_src, rel)
        if isinstance(obj, str):
            return result(True, obj)
        objs.append(str(obj))
    return _compile_and_run(
        base / "test_digest_header",
        ["-O", "-Wall", str(TEST_C / "test_digest_header.c"), *objs, *_nginx_includes(ngx_src, http=True)],
    )


def integrity_seed(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # brix_integrity_seed_fd (core/compat/integrity_info.o) — the producer side of
    # the checksum cache a cache fill uses to hand over a digest it already
    # proved. Links the real xattr-cache layer plus the real algorithm parser
    # (checksum.o), so the canonicalisation and staleness policies under test are
    # the shipping ones. checksum_core.o is deliberately NOT linked: its compute
    # kernels are stubbed to abort() in the test, which is what turns "answered
    # from cache" into an assertion instead of a coincidence (and keeps the crc,
    # zlib, EVP and sd_posix_driver closure out). The VFS xattr seam and the §8.2
    # record fallback are stubbed too — both are ours, not nginx's.
    objs: list[str] = []
    for name in ["integrity_info.o", "checksum.o"]:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(str(obj))
    for rel in SD_HTTP_NGX_OBJS:
        obj = _need_obj(ngx_src, rel)
        if isinstance(obj, str):
            return result(True, obj)
        objs.append(str(obj))
    return _compile_and_run(
        base / "test_integrity_seed",
        ["-O", "-Wall", str(TEST_C / "test_integrity_seed.c"), *objs,
         *_nginx_includes(ngx_src)],
    )


def sd_mkdir_cred_forward(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # brix_sd_mkdir_maybe_cred (src/fs/backend/sd_cred_forward.h) — the mkdir
    # credential-forwarding dispatch that makes the xroot driver's new mkdir_cred
    # slot reachable. Header-only inline over a fake driver: no origin, no network,
    # so it links with no addon objects (only the nginx include path for the SD
    # struct + ngx_inline). Exercises cred+slot -> cred slot, NULL/allow-mode
    # fallback -> plain slot, and the deny-mode security property (fallback_deny +
    # no cred slot -> EACCES, plain never called).
    return _compile_and_run(
        base / "test_sd_mkdir_cred_forward",
        ["-O", "-Wall", str(TEST_C / "test_sd_mkdir_cred_forward.c"), *_nginx_includes(ngx_src)],
    )


def decorator_cred_forward(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # The cache and stage DECORATORS must publish a *_cred twin for every plain
    # namespace slot they publish: brix_sd_<op>_maybe_cred decides on the instance
    # it is called on, so a decorator missing the twin looks like a driver with no
    # per-user support and the credential is erased one tier above the source.
    # Links the real forwarders (sd_cache_forward.o for the cache half, sd_stage.o
    # for the stage half, dispatched through its real vtable) over a fake source;
    # only the cstore lookups, the write-back/staged slots and ngx_cpystrn are
    # stubbed — no nginx object is linked, so stubbing ngx_cpystrn is safe here.
    objs: list[str] = []
    for name in ["sd_cache_forward.o", "sd_stage.o"]:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(str(obj))
    return _compile_and_run(
        base / "test_decorator_cred_forward",
        ["-O", "-Wall", "-D_GNU_SOURCE",
         str(TEST_C / "test_decorator_cred_forward.c"), *objs,
         *_nginx_includes(ngx_src, http=True, stream=True)],
    )


def reservation(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # XrdBwm bandwidth-reservation engine (reservation.o) wired in phase-92 to the
    # root:// read-open path. Pure C over libc (snprintf/strcmp) — no ngx runtime —
    # so it links with no stubs. Exercises grant/byte-precise-release, over-budget
    # refusal, and the no-over-commit / no-inflation security properties.
    obj = _find_obj(ngx_src, "reservation.o")
    if obj is None:
        return result(True, "SKIP: build first; missing reservation.o")
    return _compile_and_run(
        base / "test_reservation",
        ["-O", "-Wall", str(TEST_C / "test_reservation.c"), str(obj), *_nginx_includes(ngx_src)],
    )


SRC_GSIFTP = REPO_ROOT / "src" / "fs" / "backend" / "gsiftp"


def gftp_parse(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # Outbound gsiftp:// control-channel reply parser + MLSx fact-line parser
    # (phase-91 Wave-A protocol kernels). Pure C over libc, no ngx runtime and no
    # live server, so it links with no objects/stubs. Exercises single/multiline
    # reply framing, the SSRF-relevant 227/229 address decoders (out-of-range
    # octet + short delimiter-run reject), and MLSx traversal/control-byte name
    # rejection + overflow-size drop.
    return _compile_and_run(
        base / "gftp_parse_test",
        [
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(SRC_GSIFTP),
            str(TEST_C / "gftp_parse_test.c"),
            str(SRC_GSIFTP / "gftp_reply.c"),
            str(SRC_GSIFTP / "gftp_mlsx.c"),
        ],
    )


CLIENT = REPO_ROOT / "client"


def cvmfs_url_rewrite(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # The CVMFS mirror URL builders (client/apps/fs/brixcvmfs_transport.c), unit-
    # tested by including the TU and stubbing its ten project externals — no
    # network, no curl handle is ever initialised. Locks in the -Wformat-truncation
    # fix two ways: -Werror under -O2 -D_FORTIFY_SOURCE=2 (the exact shape that
    # warned) makes the warning itself a build failure, and the assertions pin the
    # semantics — a rewrite that would not fit reports "not rewritten" instead of
    # emitting a shortened URL, which would name a different object.
    return _compile_and_run(
        base / "cvmfs_url_rewrite_test",
        [
            "-std=c11",
            "-O2",
            "-D_FORTIFY_SOURCE=2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_GNU_SOURCE",
            "-DXRDPROTO_NO_NGX",
            "-DBRIX_HAVE_KRB5",
            "-DBRIX_HAVE_LIBURING",
            "-I",
            str(CLIENT),
            "-I",
            str(CLIENT / "lib"),
            "-I",
            str(REPO_ROOT / "src"),
            "-I",
            str(REPO_ROOT / "shared"),
            "-I",
            "/usr/include/fuse3",
            str(TEST_C / "cvmfs_url_rewrite_test.c"),
            "-lcurl",
            "-lpthread",
        ],
    )


def oci_parse(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """Compile the standalone OCI challenge, URL, and authority parser contract."""
    del ngx_src
    oci = REPO_ROOT / "shared" / "oci"
    return _compile_and_run(
        base / "oci_parse_test",
        [
            "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I", str(REPO_ROOT / "shared"),
            str(TEST_C / "oci_parse_test.c"),
            str(oci / "challenge.c"),
            str(oci / "url.c"),
            str(oci / "authority.c"),
        ],
    )


RUNNERS = {
    "cache_lock_reclaim": cache_lock_reclaim,
    "flush_deadletter": flush_deadletter,
    "shm_mutex_recovery": shm_mutex_recovery,
    "ratelimit_gauge_reset": ratelimit_gauge_reset,
    "delegation_store": delegation_store,
    "pblock": pblock,
    "mu_unit": mu_unit,
    "chunk_geometry": chunk_geometry,
    "staged_commit_contract": staged_commit_contract,
    "staged_contract_tiers": staged_contract_tiers,
    "staged_contract_origin": staged_contract_origin,
    "shared_thread_pool": shared_thread_pool,
    "fd_kind": fd_kind,
    "stage_reconcile": stage_reconcile,
    "compression": compression,
    "sreq_compat": sreq_compat,
    "stage_bearer_thread": stage_bearer_thread,
    "sd_remote_wrongkind": sd_remote_wrongkind,
    "sd_remote_server_copy": sd_remote_server_copy,
    "sd_remote_opendir": sd_remote_opendir,
    "sd_remote_opendir_cred": sd_remote_opendir_cred,
    "sd_remote_enumerate": sd_remote_enumerate,
    "sd_remote_rename": sd_remote_rename,
    "sd_remote_setattr": sd_remote_setattr,
    "sd_remote_xattr_cred": sd_remote_xattr_cred,
    "sd_remote_checksum": sd_remote_checksum,
    "sd_http_dir": sd_http_dir,
    "sd_http_mutate": sd_http_mutate,
    "sd_http_copy": sd_http_copy,
    "sd_http_digest": sd_http_digest,
    "sd_http_space": sd_http_space,
    "sd_http_readv": sd_http_readv,
    "sd_http_xattr": sd_http_xattr,
    "sd_xroot_setattr": sd_xroot_setattr,
    "sd_xroot_query": sd_xroot_query,
    "sd_block_space": sd_block_space,
    "digest_header": digest_header,
    "integrity_seed": integrity_seed,
    "sd_mkdir_cred_forward": sd_mkdir_cred_forward,
    "decorator_cred_forward": decorator_cred_forward,
    "reservation": reservation,
    "gftp_parse": gftp_parse,
    "cvmfs_url_rewrite": cvmfs_url_rewrite,
    "oci_parse": oci_parse,
    "frm_stage_metrics": frm_stage_metrics,
    "tpc_progress_total": tpc_progress_total,
    "tpc_xfr_cap": tpc_xfr_cap,
    "tier_s3_creds": tier_s3_creds,
}


def run_checks(base: Path, names: Iterable[str] | None = None) -> list[tuple[bool, str]]:
    results = []
    for name in list(names or RUNNERS):
        runner = RUNNERS.get(name)
        if runner is None:
            results.append(result(False, f"unknown C regression runner: {name}"))
            continue
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.append(runner(work))
    return results


def entry(argv: list[str]) -> int:
    selected = argv or list(RUNNERS)
    with tempfile.TemporaryDirectory(prefix="c_regression.") as tmp:
        results = run_checks(Path(tmp), selected)
    return print_results(results, "c_regression_units")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))

"""Table-driven ports for small standalone C unit shell runners."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cmdscripts.compile_run import (REPO_ROOT, compile_binary, pal_storage_link_args,
                                    pal_xattr_sources, result, run)
from cmdscripts.command_results import print_results


@dataclass(frozen=True)
class CUnitSpec:
    name: str
    output: str
    args: tuple[str, ...]


SPECS: dict[str, CUnitSpec] = {
    "ssi_service": CUnitSpec(
        "ssi_service", "test_ssi_service",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/protocols/ssi/ssi_service_unittest.c", "src/protocols/ssi/ssi_service.c"),
    ),
    "ssi_rrinfo": CUnitSpec(
        "ssi_rrinfo", "test_ssi_rrinfo",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/protocols/ssi/ssi_rrinfo_unittest.c", "src/protocols/ssi/ssi_rrinfo.c"),
    ),
    "ssi_reply": CUnitSpec(
        "ssi_reply", "test_ssi_reply",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/protocols/ssi/ssi_reply_unittest.c", "src/protocols/ssi/ssi_reply.c",
         "src/protocols/ssi/ssi_rrinfo.c"),
    ),
    "ssi_session": CUnitSpec(
        "ssi_session", "test_ssi_session",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src", "-DSSI_UT_STANDALONE",
         "src/protocols/ssi/session_unittest.c", "src/protocols/ssi/session.c"),
    ),
    "ssi_registry": CUnitSpec(
        "ssi_registry", "test_ssi_registry",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src", "-DSSI_UT_STANDALONE",
         "src/protocols/ssi/registry_unittest.c", "src/protocols/ssi/registry.c"),
    ),
    "ssi_respbuf": CUnitSpec(
        "ssi_respbuf", "test_ssi_respbuf",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src", "-DSSI_UT_STANDALONE",
         "src/protocols/ssi/respbuf_unittest.c", "src/protocols/ssi/respbuf.c"),
    ),
    "ssi_protobuf_wire": CUnitSpec(
        "ssi_protobuf_wire", "test_ssi_protobuf_wire",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/protocols/ssi/svc_cta/pb_wire_unittest.c",
         "src/protocols/ssi/svc_cta/pb_wire.c"),
    ),
    "ssi_cta_codec": CUnitSpec(
        "ssi_cta_codec", "test_ssi_cta_codec",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/protocols/ssi/svc_cta/cta_pb_unittest.c",
         "src/protocols/ssi/svc_cta/cta_pb.c", "src/protocols/ssi/svc_cta/pb_wire.c"),
    ),
    "root_wire_codec": CUnitSpec(
        "root_wire_codec", "test_root_wire_codec",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/protocols/root/protocol/codec/wire_codec_unittest.c",
         "src/protocols/root/protocol/codec/wire_codec_meta.c",
         "src/protocols/root/protocol/codec/wire_codec_file.c",
         "src/protocols/root/protocol/codec/wire_codec_ns.c",
         "src/protocols/root/protocol/codec/wire_codec_session.c"),
    ),
    "cms_meter": CUnitSpec(
        "cms_meter", "test_cms_meter",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src", "-I", "shared",
         "src/net/cms/meter_unittest.c", "src/net/cms/meter.c"),
    ),
    "cms_rrdata": CUnitSpec(
        "cms_rrdata", "test_cms_rrdata",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/net/cms/rrdata_unittest.c", "src/net/cms/rrdata.c"),
    ),
    "cms_router": CUnitSpec(
        "cms_router", "test_cms_router",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/net/cms/router_unittest.c", "src/net/cms/router.c"),
    ),
    "cms_node_ops": CUnitSpec(
        "cms_node_ops", "test_cms_node_ops",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/net/cms/node_ops_unittest.c", "src/net/cms/node_ops.c"),
    ),
    "token_ini": CUnitSpec(
        "token_ini", "test_token_ini",
        ("-O", "-Wall", "-Wextra", "-Werror", "-I", "src",
         "src/auth/token/ini_unittest.c", "src/auth/token/ini.c"),
    ),
    "metabench": CUnitSpec(
        "metabench", "test_metabench",
        ("-O", "-Wall", "-Wextra", "-Werror",
         "client/lib/observability/metabench/metabench_unittest.c",
         "client/lib/observability/metabench/metabench.c"),
    ),
    "error_mapping": CUnitSpec(
        "error_mapping",
        "test_error_mapping",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DXRDPROTO_NO_NGX",
            "-I",
            "src",
            "tests/c/test_error_mapping.c",
            "src/core/compat/error_mapping.c",
        ),
    ),
    "fs_usage": CUnitSpec(
        "fs_usage",
        "test_fs_usage",
        ("-O", "-Wall", "-Werror", "tests/c/test_fs_usage.c"),
    ),
    "meta_advisory": CUnitSpec(
        "meta_advisory",
        "test_meta_advisory",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "tests/c/test_meta_advisory.c",
            "src/fs/backend/meta_advisory.c",
        ),
    ),
    "csi_scrub": CUnitSpec(
        "csi_scrub",
        "test_csi_scrub",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DXRDPROTO_NO_NGX",
            "-I",
            "src",
            "tests/c/test_csi_scrub.c",
            "src/fs/backend/csi_scrub.c",
            "src/fs/backend/csi_tagstore.c",
            "src/fs/backend/csi_verify.c",
            "src/fs/meta/xmeta.c",
            "src/fs/meta/xmeta_path.c",
            *pal_storage_link_args(),
            "src/fs/meta/xmeta_decode.c",
            "src/fs/meta/xmeta_encode.c",
            "src/core/compat/crc32c.c",
            "src/core/compat/crc32c_hw.c",
            *pal_xattr_sources(),
        ),
    ),
    "site_n2n": CUnitSpec(
        "site_n2n",
        "test_site_n2n",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/test_site_n2n.c",
            "src/fs/path/site_n2n.c",
        ),
    ),
    "stage_admit": CUnitSpec(
        "stage_admit",
        "test_stage_admit",
        ("-O", "-Wall", "-Werror", "tests/c/test_stage_admit.c"),
    ),
    "sd_ceph_compat": CUnitSpec(
        "sd_ceph_compat",
        "test_sd_ceph_compat",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "tests/c/test_sd_ceph_compat.c",
            "src/fs/backend/rados/sd_ceph_compat.c",
        ),
    ),
    "pathres": CUnitSpec(
        "pathres",
        "test_pathres_units",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DBRIX_PATH_OP_PATH_H",
            "-DBRIX_PATH_BENEATH_NO_NGX",
            "-I",
            "src",
            "-include",
            "tests/c/pathres_shim.h",
            "tests/c/test_pathres_units.c",
            "src/core/compat/path.c",
        ),
    ),
    "seccomp": CUnitSpec(
        "seccomp",
        "test_seccomp",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_GNU_SOURCE",
            "-DBRIX_HAVE_SECCOMP=1",
            "-I",
            "src",
            "tests/c/test_seccomp.c",
            "src/core/seccomp/seccomp_core.c",
            "-lseccomp",
        ),
    ),
    "opaque_schema": CUnitSpec(
        "opaque_schema",
        "test_opaque_schema",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/test_opaque_schema.c",
            "src/protocols/root/path/opaque_validate.c",
        ),
    ),
    "negcache": CUnitSpec(
        "negcache",
        "test_negcache",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/test_negcache.c",
            "src/core/negcache/negcache_core.c",
        ),
    ),
    "wverify": CUnitSpec(
        "wverify",
        "test_wverify",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/test_wverify.c",
            "src/core/compat/wverify.c",
            "-lz",
            "-lcrypto",   # W3: the in-order SHA-256 identity (EVP)
        ),
    ),
    "cred_stage": CUnitSpec(
        "cred_stage",
        "test_cred_stage",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_GNU_SOURCE",
            "-I",
            "src",
            "-include",
            "tests/c/cred_stage_scope.h",
            "tests/c/test_cred_stage.c",
            "src/core/compat/cred_stage.c",
            "-ldl",  # dlsym(RTLD_NEXT) for the fsync-ordering interposer
        ),
    ),
    "tpc_cred_renew": CUnitSpec(
        "tpc_cred_renew",
        "test_tpc_cred_renew",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/test_tpc_cred_renew.c",
            "src/tpc/common/cred_renew.c",
        ),
    ),
    "sesslog": CUnitSpec(
        "sesslog",
        "brix_sesslog_ut",
        (
            "-O1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/sesslog_unittest.c",
            "src/observability/sesslog/sesslog.c",
            "src/observability/sesslog/sesslog_err.c",
        ),
    ),
}


def run_one(name: str, base: Path) -> list[tuple[bool, str]]:
    spec = SPECS[name]
    binary = base / spec.output
    built = compile_binary(binary, list(spec.args), cwd=REPO_ROOT)
    if built.returncode != 0:
        return [result(False, f"compile {name} failed: {(built.stderr or built.stdout)[-2000:]}")]
    ran = run([str(binary)], cwd=base if name == "cred_stage" else REPO_ROOT)
    return [result(ran.returncode == 0, f"{name} exited {ran.returncode}: {(ran.stderr or ran.stdout)[-2000:]}")]


def run_checks(base: Path, names: list[str] | None = None) -> list[tuple[bool, str]]:
    selected = names or sorted(SPECS)
    results: list[tuple[bool, str]] = []
    for name in selected:
        results.extend(run_one(name, base / name))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    names = argv or sorted(SPECS)
    with tempfile.TemporaryDirectory(prefix="c_simple_units.") as tmp:
        base = Path(tmp)
        _prepare_unit_dirs(base, names)
        results = run_checks(base, names=names)
    return print_results(results, "c_simple_units")


def _prepare_unit_dirs(base, names):
    for name in names:
        (base / name).mkdir()


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))

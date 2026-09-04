"""Structural pins for Phase 105 W7 stream field-home convergence."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text()


def _all_native_sources() -> str:
    paths = list((ROOT / "src").rglob("*.c"))
    paths.extend((ROOT / "src").rglob("*.h"))
    return "".join(path.read_text() for path in paths)


def test_stream_common_contains_only_the_shared_preamble():
    header = _read("src/core/config/stream_common.h")
    block = header.split("typedef struct {", 1)[1].split("}", 1)[0]
    assert "brix_shared_conf_t  common;" in block
    assert block.count(";") == 1


def test_protocol_configs_embed_shared_preamble_without_adopt_shims():
    gridftp = _read("src/protocols/gridftp/ftp_gateway.h")
    sources = _all_native_sources()
    assert "brix_shared_conf_t common;" in gridftp
    assert "brix_stream_common_adopt_gsi" not in sources
    assert "brix_stream_common_adopt_vo_rules" not in sources


def test_root_security_and_tpc_directives_target_common_fields():
    auth = _read("src/protocols/root/stream/directives_auth.h")
    tpc = _read("src/protocols/root/stream/directives_tpc.h")
    assert "common.acc.format" in auth
    assert "common.token_jwks" in auth
    assert "common.tpc_outbound_token_endpoint" in tpc
    assert "ngx_stream_brix_srv_conf_t, token_jwks" not in auth
    assert "ngx_stream_brix_srv_conf_t, tpc_outbound_" not in tpc

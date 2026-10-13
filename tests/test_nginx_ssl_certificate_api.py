"""Build-contract checks for distro nginx SSL certificate API variants."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def test_config_detects_downstream_passphrase_dialog_api():
    config = (REPO / "config").read_text(encoding="utf-8")

    assert "grep -q 'ngx_ssl_ppdialog_conf_t'" in config
    assert "-DBRIX_NGX_SSL_CERTIFICATE_HAS_PPDIALOG=1" in config


def test_tls_config_supplies_downstream_dialog_argument():
    source = (REPO / "src/protocols/root/session/tls_config.c").read_text(
        encoding="utf-8"
    )

    guarded = source.split(
        "#if defined(BRIX_NGX_SSL_CERTIFICATE_HAS_PPDIALOG)", 1
    )[1].split("#else", 1)[0]
    assert "NULL, NULL) != NGX_OK" in guarded


def test_upstream_api_does_not_receive_extra_argument():
    source = (REPO / "src/protocols/root/session/tls_config.c").read_text(
        encoding="utf-8"
    )

    fallback = source.split(
        "#if defined(BRIX_NGX_SSL_CERTIFICATE_HAS_PPDIALOG)", 1
    )[1].split("#else", 1)[1].split("#endif", 1)[0]
    assert "NULL) != NGX_OK" in fallback
    assert "NULL, NULL) != NGX_OK" not in fallback

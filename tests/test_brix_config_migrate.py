"""Standalone XRootD-to-BriX configuration suggestion tool.

Run with:
    PYTHONPATH=tests pytest tests/test_brix_config_migrate.py -v
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "brix_config_migrate.py"


def _load():
    spec = importlib.util.spec_from_file_location("brix_config_migrate", TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load()


def _convert(text, **overrides):
    options = tool.ConvertOptions(**overrides)
    return tool.convert(tool.parse_config(text), options)


class TestParser:

    def test_continuation_comments_and_quotes_are_tokenized(self):
        """Success: common continuation syntax produces one directive."""
        parsed = tool.parse_config(
            'sec.protocol gsi \\\n -cert:"/etc/grid security/host.pem" # comment\n')
        assert parsed == [tool.Directive(
            "sec.protocol", ("gsi", "-cert:/etc/grid security/host.pem"), 1)]

    def test_unterminated_quote_reports_the_source_line(self):
        """Error: malformed source is rejected with its line number."""
        with pytest.raises(ValueError, match="line 2"):
            tool.parse_config("xrd.port 1094\noss.localroot '/broken\n")

    def test_control_bytes_are_rejected_before_rendering(self):
        """Security negative: config controls cannot reach generated nginx."""
        with pytest.raises(ValueError, match="control byte"):
            tool.parse_config("xrd.port 1094\x1bhidden\n")


class TestCoreAndAuth:

    def test_posix_gsi_voms_xrdacc_and_tpc_are_mapped(self):
        """Success: a representative storage endpoint maps coherently."""
        source = """
xrd.port 1094
oss.localroot /srv/xrootd
all.export / r/o
sec.protocol gsi -cert:/etc/hostcert.pem -key:/etc/hostkey.pem \\
 -certdir:/etc/grid-security/certificates -vomsdir:/etc/grid-security/vomsdir
sec.protbind * gsi
ofs.authorize
acc.authdb /etc/xrootd/authdb
acc.audit deny
ofs.tpc streams 4 ttl 300 600
"""
        result = _convert(source, require_vo=["/atlas=atlas"])
        rendered = tool.render(result, "xrootd.cfg")
        expected = (
            "listen 1094;", "brix_storage_backend posix:/srv/xrootd;",
            "brix_allow_write off;", "brix_auth gsi;",
            "brix_vomsdir /etc/grid-security/vomsdir;",
            "brix_authdb_engine xrdacc;", "brix_tpc_streams 4;",
            "brix_require_vo /atlas atlas;",
        )
        assert all(line in rendered for line in expected), rendered

    def test_missing_storage_is_a_visible_review_placeholder(self):
        """Error: absent storage never silently becomes an arbitrary root."""
        result = _convert("xrd.port 1094\n")
        rendered = tool.render(result, "minimal.cfg")
        assert "brix_storage_backend posix:REVIEW_DATA_ROOT;" in rendered
        assert "# REVIEW" in rendered

    def test_argument_with_nginx_syntax_is_quoted(self):
        """Security negative: an XRootD value cannot inject a directive."""
        result = _convert(
            'xrd.port 1094\noss.localroot "/srv/data; brix_auth none"\n'
            "all.export / r/o\n")
        rendered = tool.render(result, "hostile.cfg")
        assert 'posix:/srv/data; brix_auth none";' in rendered
        assert rendered.count("brix_auth none;") == 1, rendered

    def test_xrdacc_selector_colons_are_normalized_without_reformatting(self):
        """Success: standard XrdAcc identity selectors become BriX-readable."""
        source = "# users\n= atlas o: atlas r: production  # keep\nx atlas / a\n"
        expected = "# users\n= atlas o atlas r production  # keep\nx atlas / a\n"
        assert tool.convert_authdb(source) == expected

    def test_authdb_control_bytes_are_rejected(self):
        """Error: malformed companion input cannot be written as policy."""
        with pytest.raises(ValueError, match="control byte on line 2"):
            tool.convert_authdb("= atlas o: atlas\n= ops o:\x1b ops\n")

    def test_quoted_selector_text_is_not_rewritten(self):
        """Security negative: values and comments resembling selectors stay inert."""
        source = '= alias o: "atlas r: production" # g: unchanged\n'
        assert tool.convert_authdb(source) == (
            '= alias o "atlas r: production" # g: unchanged\n')

    def test_gsi_crl_try_uses_explicit_crl_directory(self):
        """Success: common GSI revocation policy reaches both protocol planes."""
        result = _convert(
            "sec.protocol gsi -certdir:/ca -crldir:/crls -crl:1\n")
        assert result.values["brix_crl"] == [("/crls",)]
        assert result.values["brix_crl_mode"] == [("try",)]
        result.http_port = "8443"
        rendered = tool.render(result, "crl.cfg")
        assert rendered.count("brix_crl /crls;") == 2

    def test_unknown_gsi_crl_level_requires_review(self):
        """Error: an unknown revocation level is never weakened by guessing."""
        result = _convert("sec.protocol gsi -certdir:/ca -crl:future\n")
        assert "brix_crl_mode" not in result.values
        assert any("unknown GSI CRL" in item.message
                   for item in result.findings)

    def test_gsi_crl_without_a_directory_is_not_activated(self):
        """Security negative: CRL enforcement never points at an invented path."""
        result = _convert("sec.protocol gsi -crl:3\n")
        assert "brix_crl" not in result.values
        assert any("needs -crldir" in item.message for item in result.findings)


class TestPfcAndPss:

    def test_common_proxy_cache_controls_are_mapped(self):
        """Success: PSS/PFC becomes a remote backend plus local cache tier."""
        source = """
xrd.port 1094
ofs.osslib libXrdPss.so
pss.origin origin.example:1094
oss.localroot /var/cache/xrootd
all.export / r/w
pfc.blocksize 1m
pfc.prefetch 4
pfc.diskusage 0.80 0.90 purgeinterval 5m
pfc.purgecoldfiles 7d
pfc.uvkeep 30m
pfc.onlyifcached off
pfc.writethrough on
"""
        rendered = tool.render(_convert(source), "cache.cfg")
        expected = (
            "brix_storage_backend root://origin.example:1094;",
            "brix_cache on;",
            "brix_cache_store posix:/var/cache/xrootd;",
            "brix_cache_slice_size 1m;", "brix_cache_prefetch 4;",
            "brix_cache_prefetch_window 4194304;",
            "brix_cache_low_watermark 0.80;",
            "brix_cache_high_watermark 0.90;",
            "brix_cache_reap_interval 5m;", "brix_cache_cold_max_age 7d;",
            "brix_cache_uvkeep 30m;", "brix_write_through on;",
            "brix_wt_origin origin.example:1094;",
        )
        assert all(line in rendered for line in expected), rendered

    def test_plain_pss_does_not_invent_a_cache(self):
        """Error: a PSS proxy without PFC remains an uncached backend."""
        result = _convert(
            "ofs.osslib libXrdPss.so\npss.origin root://origin:1094\n"
            "oss.localroot /unused\nall.export / r/o\n")
        assert "brix_cache_store" not in result.values

    def test_unknown_pfc_policy_remains_reviewable(self):
        """Security negative: a decision plugin is never treated as equivalent."""
        result = _convert(
            "pss.origin origin:1094\npfc.decisionlib /tmp/site-policy.so\n")
        findings = [(item.directive, item.severity) for item in result.findings]
        assert ("pfc.decisionlib", "review") in findings

    def test_token_companion_policy_is_never_invented(self):
        """Security negative: issuer/JWKS policy remains an explicit review."""
        result = _convert("sec.protocol ztn\noss.localroot /srv/data\n")
        assert any(item.directive == "sec.protocol" and item.severity == "review"
                   for item in result.findings)


class TestCeph:

    def test_xrdceph_operator_values_select_librados_backend(self):
        """Success: explicit pool, config, prefix and N2N policy are rendered."""
        source = """
xrd.port 1094
ofs.osslib /usr/lib64/libXrdCeph.so
all.export / r/o
ceph.namelib /usr/lib64/libSiteN2N.so
"""
        options = dict(ceph_pool="atlas", ceph_conf="/etc/ceph/ceph.conf",
                       ceph_key_prefix="/store/", n2n_scheme="cephfs_path",
                       n2n_prefix="/store/")
        rendered = tool.render(_convert(source, **options), "ceph.cfg")
        assert ("brix_storage_backend ceph:atlas@/etc/ceph/ceph.conf?/store/;"
                in rendered)
        assert "brix_n2n_scheme cephfs_path;" in rendered
        assert "brix_n2n_prefix /store/;" in rendered

    def test_xrdceph_without_pool_is_not_presented_as_finished(self):
        """Error: an uninferable pool is an active, unmistakable placeholder."""
        result = _convert("ofs.osslib libXrdCeph.so\nall.export / r/o\n")
        assert result.values["brix_storage_backend"] == [("ceph:REVIEW_POOL",)]
        assert any(item.severity == "review" for item in result.findings)

    def test_namelib_is_never_executed_or_claimed_equivalent(self, tmp_path):
        """Security negative: plugin paths are inert input and require review."""
        marker = tmp_path / "would-have-run"
        result = _convert(
            f"ofs.osslib libXrdCeph.so\nceph.namelib {marker}\n",
            ceph_pool="pool")
        assert not marker.exists()
        assert any(item.directive == "ceph.namelib"
                   and item.severity == "review" for item in result.findings)


class TestCliAndHttp:

    def test_read_timeout_and_keepalive_are_mapped(self):
        """Success: common connection controls retain their source units."""
        result = _convert("xrd.timeout read 10\nxrd.network keepalive\n")
        rendered = tool.render(result, "runtime.cfg")
        assert "brix_read_timeout 10s;" in rendered
        assert "brix_tcp_keepalive on;" in rendered

    def test_malformed_read_timeout_requires_review(self):
        """Error: a non-numeric timeout is not emitted as nginx syntax."""
        result = _convert("xrd.timeout read tomorrow\n")
        assert "brix_read_timeout" not in tool.render(result, "runtime.cfg")
        assert result.findings[0].severity == "review"

    def test_compound_timeout_is_not_partially_applied(self):
        """Security negative: appended policy cannot hide behind a known key."""
        result = _convert("xrd.timeout read 10 kill 0\n")
        assert "brix_read_timeout" not in tool.render(result, "runtime.cfg")
        assert result.findings[0].severity == "review"

    def test_xrdhttp_emits_certificate_backed_webdav_suggestion(self):
        """Success: common XrdHttp TLS/VOMS settings reach the HTTP block."""
        source = """
xrd.protocol XrdHttp:8443 /usr/lib64/libXrdHttp.so
http.cert /etc/hostcert.pem
http.key /etc/hostkey.pem
http.httpsmode auto
http.cadir /etc/grid-security/certificates
http.secxtractor libXrdHttpVOMS.so
oss.localroot /srv/data
all.export / r/o
"""
        rendered = tool.render(_convert(source), "http.cfg")
        assert "listen 8443 ssl;" in rendered
        assert "ssl_certificate /etc/hostcert.pem;" in rendered
        assert "brix_trusted_ca_dir /etc/grid-security/certificates;" in rendered
        assert "brix_webdav_proxy_certs on;" in rendered
        assert "brix_storage_backend posix:/srv/data;" in rendered
        mode = next(item for item in _convert(source).findings
                    if item.directive == "http.httpsmode")
        assert mode.severity == "translated"

    def test_unknown_xrdhttp_https_mode_requires_review(self):
        """Error: an HTTPS policy with different semantics is not guessed."""
        result = _convert("http.httpsmode manual\n")
        mode = next(item for item in result.findings
                    if item.directive == "http.httpsmode")
        assert mode.severity == "review"

    def test_xrdhttp_auto_https_without_certificates_requires_review(self):
        """Error: auto mode cannot silently produce a plaintext listener."""
        result = _convert("http.httpsmode auto\n")
        mode = next(item for item in result.findings
                    if item.directive == "http.httpsmode")
        assert mode.severity == "review"

    def test_xrdhttp_https_mode_rejects_extra_tokens(self):
        """Security negative: appended tokens cannot weaken HTTPS policy."""
        result = _convert("http.httpsmode auto off\n")
        mode = next(item for item in result.findings
                    if item.directive == "http.httpsmode")
        assert mode.severity == "review"

    def test_lancaster_style_aliases_and_plugins_are_mapped(self):
        """Success: deployed port/HTTP/SciTokens spellings map directly."""
        source = """
xrootd.port 2094
all.export /cephfs/grid nolock
sec.protocol /usr/lib64 gsi \\
\u00a0 -cert:/etc/hostcert.pem -key:/etc/hostkey.pem
xrd.protocol http:8443 /usr/lib64/libXrdHttp.so
ofs.authlib ++ libXrdAccSciTokens.so config=/etc/xrootd/scitokens.cfg
macaroons.secretkey /etc/xrootd/macaroon-secret
"""
        rendered = tool.render(_convert(source), "site.cfg")
        assert "listen 2094;" in rendered
        assert "listen 8443 ssl;" in rendered
        assert "brix_storage_backend posix:/cephfs/grid;" in rendered
        assert "brix_token_config /etc/xrootd/scitokens.cfg;" in rendered
        assert "brix_macaroon_secret /etc/xrootd/macaroon-secret;" in rendered

    def test_matching_port_alias_is_not_reported_as_unsupported(self):
        """Success: equivalent deployed listener aliases are deduplicated."""
        result = _convert("xrd.port 1095\nxrootd.port 1095\n")
        alias = next(item for item in result.findings
                     if item.directive == "xrootd.port")
        assert alias.severity == "ignored"

    def test_conflicting_port_aliases_require_review(self):
        """Error: disagreement between listener aliases is never hidden."""
        result = _convert("xrd.port 1094\nxrootd.port 1095\n")
        assert any(item.directive == "xrootd.port" and item.severity == "review"
                   for item in result.findings)

    def test_shared_xrootd_http_port_uses_private_handoff(self):
        """Success: one public port dispatches HTTP to loopback WebDAV."""
        result = _convert(
            "xrd.port 1094\nxrd.protocol http:1094 libXrdHttp.so\n"
            "all.export /srv/data r/o\n")
        rendered = tool.render(result, "multiplex.cfg")
        assert "listen 1094;" in rendered
        assert "brix_http_handoff 127.0.0.1:1095;" in rendered  # net-literal-allow: generated loopback handoff
        assert "brix_http_handoff_connect_timeout 5s;" in rendered
        assert "brix_http_handoff_idle_timeout 75s;" in rendered
        assert "listen 127.0.0.1:1095;" in rendered  # net-literal-allow: generated loopback listener
        assert "listen 1095;" not in rendered
        finding = next(item for item in result.findings
                       if item.directive == "xrd.protocol")
        assert finding.severity == "translated"

    def test_shared_port_override_remains_loopback_only(self):
        """Security negative: an override cannot expose the private listener."""
        result = _convert(
            "xrd.port 1094\nxrd.protocol http:1094 libXrdHttp.so\n",
            http_port="19095", http_connect_timeout="2s",
            http_idle_timeout="10m")
        rendered = tool.render(result, "multiplex.cfg")
        assert "brix_http_handoff 127.0.0.1:19095;" in rendered  # net-literal-allow: generated loopback handoff
        assert "listen 127.0.0.1:19095;" in rendered  # net-literal-allow: generated loopback listener
        assert "listen 19095;" not in rendered
        assert "brix_http_handoff_connect_timeout 2s;" in rendered
        assert "brix_http_handoff_idle_timeout 10m;" in rendered

    def test_strict_cli_writes_report_and_returns_three(self, tmp_path, capsys):
        """Error: unresolved input is machine-detectable and auditable."""
        source = tmp_path / "xrootd.cfg"
        report = tmp_path / "report.json"
        source.write_text("xrd.port 1094\nsite.magic on\n")
        rc = tool.main([str(source), "--strict", "--report", str(report)])
        captured = capsys.readouterr()
        assert rc == 3
        assert "# REVIEW line 2 site.magic" in captured.out
        payload = json.loads(report.read_text())
        assert payload["findings"][-1]["directive"] == "site.magic"

    def test_cli_converts_explicit_authdb_and_repoints_config(self, tmp_path,
                                                               capsys):
        """Success: an explicitly named companion authdb is emitted and used."""
        source = tmp_path / "xrootd.cfg"
        authdb = tmp_path / "authdb"
        output = tmp_path / "brix-authdb"
        source.write_text("xrd.port 1094\nacc.authdb /etc/xrootd/authdb\n")
        authdb.write_text("= atlas o: atlas\n")
        rc = tool.main([str(source), "--authdb-input", str(authdb),
                        "--authdb-output", str(output)])
        assert rc == 0
        assert f"brix_authdb {output};" in capsys.readouterr().out
        assert output.read_text() == "= atlas o atlas\n"

    def test_cli_rejects_unpaired_authdb_option(self, tmp_path, capsys):
        """Error: conversion cannot silently ignore one companion path."""
        source = tmp_path / "xrootd.cfg"
        source.write_text("xrd.port 1094\n")
        rc = tool.main([str(source), "--authdb-input", str(tmp_path / "authdb")])
        assert rc == 2
        assert "must be used together" in capsys.readouterr().err

    def test_include_is_reported_but_never_opened(self, tmp_path):
        """Security negative: an input include cannot escape the chosen file."""
        included = tmp_path / "included.cfg"
        included.write_text("oss.localroot /secret\n")
        result = _convert(f"include {included}\nxrd.port 1094\n")
        assert result.values["brix_storage_backend"] == [
            ("posix:REVIEW_DATA_ROOT",)]
        assert any(item.directive == "include" and item.severity == "unsupported"
                   for item in result.findings)

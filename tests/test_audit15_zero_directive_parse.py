"""
test_audit15_zero_directive_parse.py — `nginx -t` accept/reject coverage for
the zero-coverage directive long tail (audit §A1/A3/A4,
testsuite-combinatorial-coverage-audit 2026-08-15).

The high-value clusters got LIVE tests in their own audit-15 files (throttle
open-files, read_only, guard knobs, macaroon rotation).  This file gives the
remaining zero-coverage names their first coverage at the config-parse tier:

  * one combined stream-server config and one combined WebDAV-location config
    that set EVERY swept directive at once — proving each name parses with a
    realistic value AND that the whole set co-exists (a rendered config is the
    unit operators actually deploy, not one directive at a time);
  * targeted rejects for the setters that validate: a typo must die at
    nginx -t, because each of these silently defaulting would weaken a
    security or DoS bound.

Live behavioral coverage for these knobs (SSI/CTA, TPC lifetime kill-switches,
WT staging, introspection, dashboard auth...) remains open in the audit doc.
"""

from test_phase25_ratelimit import _parse_fail, _http_values, _stream_values

# _parse_fail is misnamed for half these uses: it renders the template, runs
# `nginx -t` and returns (returncode, output) either way — accept asserts 0.


# One SSS keytab entry in the exact text shape the parser reads (the format
# xrdsssadmin-brix mints): `<off> u:<user> g:<group> N:<id> k:<64 hex> n:<name>`.
_KEYTAB_LINE = f"0 u:anon g:users N:1 k:{'a' * 64} n:anon\n"


def _stream_t(tmp_path, knobs):
    return _parse_fail(tmp_path, "nginx_rl_stream.conf",
                       _stream_values(knobs, ""))


def _http_t(tmp_path, knobs):
    return _parse_fail(tmp_path, "nginx_rl_http.conf", _http_values(knobs))


def test_stream_zero_directive_surface_parses(tmp_path):
    """Success path: every swept stream-server directive parses with a
    realistic value, all in one server block."""
    keytab = tmp_path / "sss.keytab"
    keytab.write_text(_KEYTAB_LINE)
    keytab.chmod(0o600)  # the setter refuses group/world-readable keytabs
    knobs = f"""
        brix_virtual_redirector on;
        brix_session_log on;
        brix_signing_policy require;
        brix_csi_block 64k;
        brix_backend_sss_keytab {keytab};
        brix_backend_s3_sts_role arn:aws:iam::123456789012:role/brix-test;
        brix_zip_cd_max_bytes 1m;
        brix_zip_stage_max_bytes 8m;
        brix_ckscan_depth 3;
        brix_ckscan_max_files 100;
        brix_tcp_congestion cubic;
        brix_tpc_max_transfer_secs 60;
        brix_tpc_transfer_max_age 3600;
        brix_pmark_domain local;
        brix_pmark_firefly on;
        brix_pmark_firefly_origin on;
        brix_pmark_flowlabel on;
        brix_wt_allow_prefix /ok;
        brix_wt_deny_prefix /no;
        brix_cache_lock_timeout 5s;
        brix_io_uring_panic_file {tmp_path}/uring-panic;
        brix_io_uring_restrict on;
        brix_ssi_request_max 4k;
        brix_ssi_response_max 64k;
        brix_ssi_cta_executor test;
        brix_ssi_cta_journal {tmp_path}/cta-journal;
        brix_manager_stale_after 30s;
        brix_acc_gidlifetime 3600;
        brix_acc_nisdomain example.org;
        brix_acc_spacechar _;
        brix_cms_fxhold 10s;
        brix_cms_vnid brix-test-vnid;
        brix_tap_proxy_login_user fixed:monitor;
        brix_tap_proxy_audit_log {tmp_path}/tap-audit.log;
        brix_tap_proxy_upstream_tls_name backend.example.org;
"""
    rc, out = _stream_t(tmp_path, knobs)
    assert rc == 0, out


def test_webdav_zero_directive_surface_parses(tmp_path):
    """Success path: every swept WebDAV/http-location directive parses with a
    realistic value, all in one location."""
    knobs = """
            brix_verify_depth 3;
            brix_token_introspect_url https://idp.example.org/introspect;
            brix_token_introspect_ttl 30;
            brix_webdav_lock_timeout 30;
            brix_zip_cd_max_bytes 1m;
            brix_webdav_open_file_cache max=64 inactive=10s;
            brix_webdav_open_file_cache_valid 30s;
            brix_webdav_open_file_cache_min_uses 2;
            brix_webdav_open_file_cache_errors on;
            brix_webdav_open_file_cache_events off;
            brix_webdav_redirect_scheme https;
            brix_mirror_token mirror-bearer-secret;
            brix_s3_mpu_max_age 3600;
            brix_token_clock_skew 60;
            brix_srr_id https://site.example.org/srr;
            brix_dashboard_scan_max_files 1000;
            brix_acc_gidlifetime 3600;
            brix_acc_nisdomain example.org;
            brix_acc_spacechar _;
            brix_tcp_congestion cubic;
            brix_pmark_domain remote;
"""
    rc, out = _http_t(tmp_path, knobs)
    assert rc == 0, out


# --------------------------------------------------------------------------- #
# Targeted rejects — each validated setter must refuse a typo at nginx -t     #
# --------------------------------------------------------------------------- #

def test_signing_policy_rejects_unknown_mode(tmp_path):
    rc, out = _stream_t(tmp_path, "        brix_signing_policy bogus;\n")
    assert rc != 0 and "invalid value" in out, out


def test_pmark_domain_rejects_unknown_domain(tmp_path):
    rc, out = _stream_t(tmp_path, "        brix_pmark_domain bogus;\n")
    assert rc != 0 and "invalid brix_pmark_domain" in out, out


def test_zip_cd_max_bytes_rejects_garbage_size(tmp_path):
    rc, out = _stream_t(tmp_path, "        brix_zip_cd_max_bytes lots;\n")
    assert rc != 0 and "invalid value" in out, out


def test_webdav_token_clock_skew_bounded(tmp_path):
    rc, out = _http_t(tmp_path,
                      "            brix_token_clock_skew 9999;\n")
    assert rc != 0, out
    assert "brix_token_clock_skew is capped at 300s" in out, out


def test_webdav_revoke_cache_requires_declared_kv_zone(tmp_path):
    rc, out = _http_t(tmp_path,
                      "            brix_webdav_revoke_cache zone=nope;\n")
    assert rc != 0, out
    assert 'unknown zone "nope"' in out, out


def test_backend_sss_keytab_rejects_lax_permissions(tmp_path):
    # A world-readable shared secret must be refused at nginx -t, not at the
    # first authentication attempt.
    keytab = tmp_path / "sss.keytab"
    keytab.write_text(_KEYTAB_LINE)
    keytab.chmod(0o644)
    rc, out = _stream_t(
        tmp_path, f"        brix_backend_sss_keytab {keytab};\n")
    assert rc != 0 and "unsafe permissions" in out, out


def test_webdav_redirect_scheme_rejects_unknown_scheme(tmp_path):
    rc, out = _http_t(tmp_path,
                      "            brix_webdav_redirect_scheme gopher;\n")
    assert rc != 0 and "invalid value" in out, out

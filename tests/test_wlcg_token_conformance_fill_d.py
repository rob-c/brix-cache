from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_fill_helpers")

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_qt_08_query_no_scope_token_reject():
    """FIL-QT-08: ?authz=<no-scope token> on WebDAV 8446 → reject (rule 112).

    WHAT: A token with no scope claim delivered via query parameter.
    WHY:  Rule 112 — storage access requires an explicit storage.* scope; the
          absence of scope must cause rejection regardless of the transport method.
    """
    tok = _forge().no_scope()
    result = webdav_query_token(tok, path="/test.txt",
                                param="authz",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "reject"

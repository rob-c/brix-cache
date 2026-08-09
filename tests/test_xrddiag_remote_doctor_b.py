from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrddiag_remote_doctor_helpers")

def test_authsuite_pii_free(token_server):
    """The auth-suite must never echo a token, scope, issuer, or path."""
    issuer = token_server["issuer"]
    port = token_server["port"]
    env = {k: v for k, v in _CLEAN_ENV.items()}
    env["BEARER_TOKEN"] = issuer.generate(scope="storage.read:/")
    p = subprocess.run([XRDDIAG, "remote-doctor", f"root://{HOST}:{port}//probe.txt",
                        "--auth-suite", "--json", "--metrics-port", "0",
                        "--probe-timeout", "8000"],
                       capture_output=True, text=True, env=env, timeout=60)
    doc = json.loads(p.stdout)["remote_doctor"]
    for d in doc["endpoints"][0]["diagnosis"]:
        joined = d["cause"] + " " + d["remedy"]
        for leak in ("eyJ", "storage.read", "test.example.com", "probe.txt",
                     "BEARER", "xrddiag-az"):
            assert leak not in joined, f"auth-suite leak: {leak} in {d}"

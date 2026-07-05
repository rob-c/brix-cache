# Scenario catalog schema

`scenarios/catalog.yaml` maps each dedicated single-node scenario to the data
needed to render and verify it. One entry per scenario:

```yaml
scenarios:
  <name>:
    configKey: <key>          # selects charts/topology-role/configs/<key>.conf
    ports:                    # one or more listen ports
      - { name: <n>, port: <p> }
    auth:                     # optional; resolved by tools/scenario-render.sh
      caBundle: CA_BUNDLE     # -> <release>-ca-bundle
      hostCertSecret: PKI_SECRET   # -> <release>-pki
      crlUrl: CRL_URL         # -> http://<release>-grid-ca:8080/crl/test-user.crl.pem
      jwksUrl: JWKS_URL       # -> http://<release>-token-issuer:8080/certs/jwks.json
    check: <keyword>          # client-observable verification xrd-lab knows how to run:
                              #   write-rejected  — an xrdcp write must fail (read-only gate)
                              #   anon-roundtrip  — xrdcp put+get must be byte-identical
    tests: <pytest-selection> # OPTIONAL: the pytest module(s) that exercise this
                              # scenario. Running these in-cluster needs the conftest
                              # local-fleet-attach wiring (see docs) and is a follow-on.
```

The literal tokens (`CA_BUNDLE`, `PKI_SECRET`, `CRL_URL`, `JWKS_URL`) are
placeholders substituted at deploy time by `tools/scenario-render.sh`.

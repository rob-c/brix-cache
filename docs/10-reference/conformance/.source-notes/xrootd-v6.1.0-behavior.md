# XRootD v6.1.0 GSI/x509 behavior — source analysis (P3 working notes)

Source: /tmp/xrootd-src (git tag v6.1.0). Behavioral analysis for the conformance
write-up. Key divergences vs our nginx module (our module is STRICTER in every
case below; XRootD is stricter in none):

1. signing_policy: XRootD does NOT parse/enforce signing_policy or namespaces
   files at all (zero grep matches in src/XrdSecgsi). CA loading is plain chain
   matching; gridmap is DN->user only (XrdSecgsiGMAPFunDN.cc:91-161). Ours: enforced.
2. Limited-proxy monotonicity: XRootD detects legacy CN=proxy/CN=limited proxy
   (XrdCryptosslX509.cc:423) but does NOT enforce that a limited proxy cannot
   sign a full proxy. Ours: enforced (brix_proxy_chain_ok).
3. CRL expiry: XRootD warns but does NOT fail on expired nextUpdate
   (XrdCryptosslX509Crl.cc:573-576, DEBUG log only). CRL strictness is config
   levels 0-3 (XrdSecgsiOpts.hh:105-120): crlIgnore/crlTry(default)/crlUse/
   crlRequire. Ours: crl_mode try/require, expired CRL is FATAL under try.
4. keyUsage keyCertSign on CA: XRootD does NOT check it during chain verify.
   Ours: OpenSSL X509_verify_cert enforces it by default.
5. Signature algorithm: XRootD uses raw X509_verify(); does NOT reject MD5/SHA1
   (X509.cc:782-812). Ours: to add an explicit alg policy in P2.
6. DN comparison: XRootD raw byte strcmp, no encoding normalization
   (XrdCryptoX509Chain.cc:622; DN render XrdCryptosslAux.cc:736-746 via
   X509_NAME_print_ex XN_FLAG_SEP_MULTILINE, or oneline if USEX509NAMEONELINE).
7. XrdHttp client certs: TLS-layer verification ONLY (SSL_get_verify_result,
   XrdHttpSecurity.cc:96); does NOT run XrdCryptogsiX509Chain::Verify, so NO
   signing_policy, NO GSI proxy validation, CRL only via TLS ctx
   (http.allowmissingcrl, XrdHttpProtocol.cc:1143). root:// DOES run full GSI
   chain verify. Ours: davs:// and root:// share brix_gsi_verify_chain.

Aligned: basicConstraints CA flag (both), validity windows (both), proxyCertInfo
critical requirement (both — X509.cc:393,416), pcPathLenConstraint extract+
decrement+enforce (both — XrdCryptogsiX509Chain.cc:176-194).

Proxy OIDs: gsiProxyCertInfo 1.3.6.1.5.5.7.1.14 + old 1.3.6.1.4.1.3536.1.222
(XrdCryptoFactory.hh:93-94). Issuer selection: subject-name + hash, AKID not
used (X509Chain.cc:558,622) — same rationale as our proxy-tolerant check_issued.

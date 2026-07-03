[← PKI overview](pki-config.md)

## GSI authentication over root://

The XRootD GSI handshake: how the Diffie-Hellman exchange works, what each side proves, and how BriX-Cache implements it.
symmetric session key, then encrypts the proxy certificate chain with that key.
It takes three request/response round-trips after the initial login.

### Full Sequence Diagram

```
Client                                                    Server
──────                                                    ──────

═══ Phase 1: Capability negotiation ═══

kXR_protocol                                    ──────>
  clientpv=0x520, kXR_secreqs set
                                                <──────  kXR_protocol response
                                                           flags: kXR_isServer
                                                           SecurityInfo: method=gsi
                                                           [+ kXR_haveTLS if configured]

[optional: TLS upgrade happens here if kXR_gotoTLS set]

═══ Phase 2: Login and challenge ═══

kXR_login                                       ──────>
  username="alice"
                                                <──────  kXR_login response
                                                           16-byte session ID
                                                           + "&P=gsi,v:10000,c:ssl,ca:AABBCCDD"
                                                             │                   │  └─ CA hash (8 hex digits)
                                                             │                   └─── cipher: ssl = AES-CBC
                                                             └─────────────────────── auth plugin: gsi

═══ Phase 3: DH key exchange (step kXGC_certreq = 1000) ═══

kXR_auth                                        ──────>
  step kXGC_certreq
  payload: random 20-byte nonce (client challenge)

                                                <──────  kXR_auth response (kXR_authmore)
                                                           kXRS_puk bucket:
                                                             [ffdhe2048 DH parameters PEM]
                                                             ---BPUB---
                                                             [server DH public key, hex bignum]
                                                             ---EPUB--
                                                           kXRS_cipher bucket:  "aes-128-cbc"
                                                           kXRS_rtag bucket:
                                                             HMAC-SHA1 of client nonce
                                                             signed by server's private key
                                                             → proves server identity

═══ Phase 4: Proxy delivery (step kXGC_cert = 1001) ═══

kXR_auth                                        ──────>
  step kXGC_cert
  payload (AES-CBC encrypted with DH session key, IV=0):
    kXRS_x509 bucket:
      [proxy certificate PEM]
      [user certificate PEM]      ← chain completing proxy → CA
    kXRS_puk bucket:
      [client DH public key, same format as server's]

                                                <──────  kXR_ok
                                                           auth complete
                                                           session fully established
```

### DH Session Key Derivation

The shared session key is derived from the DH exchange using OpenSSL's `EVP_PKEY_derive`, with unpadded output:

```
shared_secret   = EVP_PKEY_derive(server_dh_priv, client_dh_pub)
                    ← EVP_PKEY_CTX_set_dh_pad(ctx, 0) is REQUIRED
                       (XRootD uses raw unpadded DH, unlike PKCS#3)

session_key     = shared_secret[0 : EVP_CIPHER_key_length(aes_128_cbc)]
                = shared_secret[0 : 16]

IV              = 0x00 * 16   ← all zeros for AES-CBC
```

The session key encrypts the proxy certificate chain from client to server.
Nothing from the server is encrypted with this key — the server's identity is
proven only by its HMAC-signed nonce.

### What is Verified and When

```
At step kXGC_certreq response:
  Server sends its host certificate + HMAC of client nonce.
  ┌─ Client verifies:
  │    • server cert chain: server_cert → CA (X509_verify_cert)
  │    • nonce HMAC: proves the private key matches the cert
  └─ If this fails: client rejects the server ("server cert not trusted")

At step kXGC_cert (server receives proxy):
  Server decrypts proxy chain with DH session key.
  ┌─ Server verifies:
  │    • proxy cert chain: proxy → user_cert → CA (X509_verify_cert)
  │    •   with X509_V_FLAG_ALLOW_PROXY_CERTS set on both store and ctx
  │    • [optional] VOMS AC: libvomsapi checks AC signature against vomsdir
  │    • [optional] CRL: each cert in chain checked against loaded CRL
  └─ If this fails: server returns kXR_NotAuthorized
```

The proxy chain is sent **encrypted** — the CA bundle on the server is used to
verify the decrypted chain, not to check the TLS transport.  The TLS session
(if any) uses a separate handshake with the host certificate.

---

## Proxy Certificate Authentication over https://

WebDAV authentication is built on top of nginx's standard HTTPS stack.  The
proxy certificate arrives as the TLS client certificate, not inside an
encrypted application-layer payload.

### Full Sequence Diagram

```
Client                                                        nginx (WebDAV)
──────                                                        ──────────────

TCP connect

═══ TLS Handshake (standard TLS 1.2/1.3) ═══

ClientHello                                         ──────>
                                                    <──────  ServerHello
                                                             Certificate
                                                               [host cert PEM]
                                                               [CA cert PEM]    ← chain
                                                             CertificateRequest  ← if ssl_verify_client set

Certificate (client sends proxy chain)              ──────>
  [proxy cert PEM]                                           nginx buffers this in
  [user cert PEM]                                            r->connection->ssl
  CertificateVerify (signature of handshake hash)
Finished                                            ──────>
                                                    <──────  Finished
                                                             TLS established

═══ HTTP Request ═══

GET /data/cms/file.root HTTP/1.1                    ──────>

═══ WebDAV auth decision (src/protocols/webdav/auth_cert.c) ═══

                                         webdav_verify_proxy_cert()
                                         │
                                         ├─ 1. Check connection cache
                                         │     SSL_get_ex_data(ssl, conn_cache_idx)
                                         │     → if same conf/store: reuse DN, skip verify
                                         │
                                         ├─ 2. Check session cache
                                         │     SSL_SESSION_get_ex_data(sess, sess_cache_idx)
                                         │     → if same conf/store: reuse DN, skip verify
                                         │
                                         ├─ 3. Nginx fast path
                                         │     SSL_get_verify_result() == X509_V_OK
                                         │     AND webdav CA config == nginx ssl CA config
                                         │     → trust nginx's already-verified result
                                         │
                                         └─ 4. Manual verification (full path)
                                               leaf  = SSL_get_peer_certificate()
                                               chain = SSL_get_peer_cert_chain()
                                               vctx  = X509_STORE_CTX_new()
                                               X509_STORE_CTX_init(vctx, ca_store, leaf, chain)
                                               X509_STORE_CTX_set_flags(vctx,
                                                   X509_V_FLAG_ALLOW_PROXY_CERTS)
                                               X509_verify_cert(vctx)
                                               → extract DN from leaf cert subject

                                         DN stored in request ctx
                                         Auth result cached on SSL + SSL_SESSION

                                    <──  HTTP 200 OK (or 403 Forbidden)
```

### Why nginx Needs a Non-Default ssl_verify_client Setting

Standard nginx HTTPS client authentication is configured with:

```nginx
ssl_verify_client on;        # reject if no cert or chain fails
ssl_verify_depth 10;
ssl_client_certificate /path/to/ca.pem;
```

This works for normal X.509 end-entity certificates.  For RFC 3820 proxy
certificates it fails silently: nginx's OpenSSL context does not have
`X509_V_FLAG_ALLOW_PROXY_CERTS` set, so the proxy cert chain is always
rejected as "invalid".

The module works around this by setting:

```nginx
ssl_verify_client optional_no_ca;   # accept the cert chain even if verification fails
                                     # (the module re-verifies it with proxy-cert flags)
```

The `optional_no_ca` setting makes nginx buffer the peer certificate chain in
the connection without rejecting it outright.  The module then re-runs chain
verification using its own `X509_STORE` (built from `brix_webdav_cadir` or
`brix_webdav_cafile`) with `X509_V_FLAG_ALLOW_PROXY_CERTS` set on both the
store and the context.

---

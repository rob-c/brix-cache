#!/usr/bin/env python3
"""fwd_mint_proxy.py — mint a CA-signed EEC + RFC-3820 proxy for one identity.

Used by the credential-forwarding matrix suite (tests/lib/fwd_matrix.sh) to
create DISTINCT proxy identities (userA / userB / svc) off the shared test CA
so a backend-observed DN unambiguously identifies which principal reached the
origin.  A hand-rolled cert+key concat is NOT accepted by XrdSecGSI — it
requires the id-pe-proxyCertInfo extension (OID 1.3.6.1.5.5.7.1.14), the same
extension utils/make_proxy.py emits.  The DER helpers here are lifted verbatim
from that script.

Usage:
    fwd_mint_proxy.py <ca_cert> <ca_key> <CN> <out_proxy.pem>

Writes a single PEM (proxy cert + proxy key + EEC chain) at <out_proxy.pem>,
mode 0600, whose leaf DN is /DC=test/DC=xrootd/CN=<CN>/CN=<serial>.
"""
import datetime
import os
import sys

from cryptography import x509
from cryptography.x509 import CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def encode_oid(oid_str):
    parts = [int(x) for x in oid_str.split(".")]
    encoded = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        if part == 0:
            encoded.append(0)
            continue
        chunks = []
        while part > 0:
            chunks.append(part & 0x7F)
            part >>= 7
        chunks.reverse()
        for i in range(len(chunks) - 1):
            chunks[i] |= 0x80
        encoded.extend(chunks)
    return bytes(encoded)


def der_length(length):
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def der_tlv(tag, value):
    return bytes([tag]) + der_length(len(value)) + value


def der_sequence(value):
    return der_tlv(0x30, value)


def der_oid(oid_str):
    return der_tlv(0x06, encode_oid(oid_str))


def main():
    if len(sys.argv) != 5:
        sys.stderr.write(
            "usage: fwd_mint_proxy.py <ca_cert> <ca_key> <CN> <out.pem>\n"
        )
        return 2
    ca_cert_path, ca_key_path, cn, out_path = sys.argv[1:5]

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    now = datetime.datetime.now(datetime.timezone.utc)

    # ---- end-entity certificate (the proxy issuer), signed by the CA --------
    eec_key = rsa.generate_private_key(65537, 2048, default_backend())
    eec_subject = Name(
        [
            NameAttribute(NameOID.DOMAIN_COMPONENT, "test"),
            NameAttribute(NameOID.DOMAIN_COMPONENT, "xrootd"),
            NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    eec = (
        CertificateBuilder()
        .subject_name(eec_subject)
        .issuer_name(ca_cert.subject)
        .public_key(eec_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # ---- RFC-3820 proxy, signed by the EEC ----------------------------------
    proxy_serial = 12346
    proxy_subject = Name(
        list(eec.subject) + [NameAttribute(NameOID.COMMON_NAME, str(proxy_serial))]
    )
    id_ppl_inherit_all = "1.3.6.1.5.5.7.21.1"
    proxy_cert_info = der_sequence(der_sequence(der_oid(id_ppl_inherit_all)))
    proxy_key = rsa.generate_private_key(65537, 2048, default_backend())
    proxy = (
        CertificateBuilder()
        .subject_name(proxy_subject)
        .issuer_name(eec.subject)
        .public_key(proxy_key.public_key())
        .serial_number(proxy_serial)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.5.5.7.1.14"), proxy_cert_info
            ),
            critical=True,
        )
        # keyUsage(digitalSignature) on the PROXY LEAF: the TPC-delegation flow
        # (brix_tpc_delegate) has the client SIGN the destination's kXGS_pxyreq
        # with this proxy; XrdSecGSI (and brix's signer check) rejects a signer
        # whose keyUsage forbids digitalSignature ("signer lacks keyUsage").
        # Harmless for the normal-access matrix, which never signs a proxy req.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(eec_key, hashes.SHA256(), default_backend())
    )

    pem = (
        proxy.public_bytes(serialization.Encoding.PEM)
        + proxy_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        + eec.public_bytes(serialization.Encoding.PEM)
    )
    with open(out_path, "wb") as f:
        f.write(pem)
    os.chmod(out_path, 0o600)
    return 0


if __name__ == "__main__":
    sys.exit(main())

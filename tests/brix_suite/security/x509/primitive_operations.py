"""Composable implementations for X.509 certificate primitives."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import CertificateBuilder, CertificateRevocationListBuilder
from cryptography.x509 import Name, NameAttribute, RevokedCertificateBuilder
from cryptography.x509.oid import NameOID


def _oid_part(part):
    if part == 0:
        return [0]
    chunks = []
    while part > 0:
        chunks.append(part & 0x7F)
        part >>= 7
    chunks.reverse()
    for index in range(len(chunks) - 1):
        chunks[index] |= 0x80
    return chunks


def encode_oid(value):
    parts = [int(item) for item in value.split(".")]
    encoded = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        encoded.extend(_oid_part(part))
    return bytes(encoded)


def _weak_eec_requested(digest_name, key_type, key_bits):
    weak_digest = digest_name in ("sha1", "md5")
    weak_rsa_key = key_type == "rsa" and key_bits < 1024
    return weak_digest or weak_rsa_key


def _simple_eec_extensions(subject_name, eku, extra_ext, name_constraints):
    return all(value is None for value in (subject_name, eku, extra_ext, name_constraints))


def _openssl_eec_requested(
    digest_name, key_type, key_bits, subject_name, eku, extra_ext, name_constraints
):
    weak = _weak_eec_requested(digest_name, key_type, key_bits)
    simple = _simple_eec_extensions(subject_name, eku, extra_ext, name_constraints)
    return weak and simple


def _eec_subject(subject_name, dn, namespace):
    if subject_name is not None:
        return subject_name
    return namespace["_name"](dn)


def _base_eec_builder(
    issuer, subject, key, ca_true, path_length, not_before_days, not_after_days, namespace
):
    return (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(namespace["_EPOCH"] + not_before_days * namespace["_DAY"])
        .not_valid_after(namespace["_EPOCH"] + not_after_days * namespace["_DAY"])
        .add_extension(
            x509.BasicConstraints(ca=ca_true, path_length=path_length),
            critical=True,
        )
    )


def _add_subject_key_id(builder, key, enabled):
    if not enabled:
        return builder
    extension = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    return builder.add_extension(extension, critical=False)


def _key_usage_options(ca_true, keycert_sign, overrides):
    options = dict(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca_true and keycert_sign,
        crl_sign=ca_true and keycert_sign,
        encipher_only=False,
        decipher_only=False,
    )
    if overrides:
        options.update(overrides)
    return options


def _add_key_usage(builder, enabled, ca_true, keycert_sign, overrides):
    if not enabled:
        return builder
    options = _key_usage_options(ca_true, keycert_sign, overrides)
    return builder.add_extension(x509.KeyUsage(**options), critical=True)


def _add_extended_key_usage(builder, eku):
    if eku is None:
        return builder
    extension = x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid) for oid in eku])
    return builder.add_extension(extension, critical=False)


def _add_name_constraints(builder, constraints):
    if constraints is None:
        return builder
    return builder.add_extension(constraints, critical=True)


def _add_extra_extension(builder, item):
    if len(item) == 2:
        extension, critical = item
        return builder.add_extension(extension, critical=critical)
    oid, der, critical = item
    extension = x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der)
    return builder.add_extension(extension, critical=critical)


def _add_extra_extensions(builder, extensions):
    for item in extensions or ():
        builder = _add_extra_extension(builder, item)
    return builder


def _decorate_eec(
    builder, key, skid, with_key_usage, ca_true, keycert_sign, key_usage,
    eku, name_constraints, extra_ext,
):
    builder = _add_subject_key_id(builder, key, skid)
    builder = _add_key_usage(
        builder, with_key_usage, ca_true, keycert_sign, key_usage
    )
    builder = _add_extended_key_usage(builder, eku)
    builder = _add_name_constraints(builder, name_constraints)
    return _add_extra_extensions(builder, extra_ext)


def _make_eec_with_openssl(
    issuer, dn, key_bits, digest_name, not_after_days, not_before_days, ca_true,
    namespace,
):
    return namespace["_make_eec_openssl"](
        issuer,
        dn,
        key_bits=key_bits,
        digest_name=digest_name,
        not_after_days=not_after_days,
        not_before_days=not_before_days,
        ca_true=ca_true,
    )


def make_eec(
    issuer, dn, subject_name, key_bits, not_after_days, not_before_days,
    ca_true, keycert_sign, path_length, with_key_usage, key_usage, eku,
    name_constraints, extra_ext, skid, digest, key_type, curve, digest_name,
    namespace,
):
    if _openssl_eec_requested(
        digest_name, key_type, key_bits, subject_name, eku, extra_ext, name_constraints
    ):
        return _make_eec_with_openssl(
            issuer, dn, key_bits, digest_name, not_after_days, not_before_days,
            ca_true, namespace,
        )
    key = namespace["_make_key"](key_type, bits=key_bits, curve=curve)
    algorithm = digest or namespace["_digest"](digest_name)
    subject = _eec_subject(subject_name, dn, namespace)
    builder = _base_eec_builder(
        issuer, subject, key, ca_true, path_length, not_before_days,
        not_after_days, namespace,
    )
    builder = _decorate_eec(
        builder, key, skid, with_key_usage, ca_true, keycert_sign, key_usage,
        eku, name_constraints, extra_ext,
    )
    return namespace["Cert"](builder.sign(issuer.key, algorithm), key)


def _proxy_subject(parent, kind, serial):
    attributes = list(parent.cert.subject)
    if kind in ("legacy", "legacy-limited"):
        common_name = "limited proxy" if kind == "legacy-limited" else "proxy"
    else:
        common_name = str(serial)
    return Name(attributes + [NameAttribute(NameOID.COMMON_NAME, common_name)])


def _base_proxy_builder(
    parent, subject, key, serial, not_before_days, not_after_days, namespace
):
    return (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent.cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(namespace["_EPOCH"] + not_before_days * namespace["_DAY"])
        .not_valid_after(namespace["_EPOCH"] + not_after_days * namespace["_DAY"])
    )


def _proxy_policy(kind, policy_oid, namespace):
    if policy_oid is not None:
        return policy_oid
    policies = {
        "rfc3820": namespace["OID_PPL_INHERIT_ALL"],
        "limited": namespace["OID_GLOBUS_LIMITED"],
        "independent": namespace["OID_PPL_INDEPENDENT"],
    }
    return policies[kind]


def _add_proxy_info(builder, kind, policy_oid, path_len, critical, namespace):
    if kind in ("legacy", "legacy-limited"):
        return builder
    oid = _proxy_policy(kind, policy_oid, namespace)
    der = namespace["proxy_cert_info_der"](oid, path_len)
    extension = x509.UnrecognizedExtension(
        x509.ObjectIdentifier(namespace["OID_PROXY_CERT_INFO"]), der
    )
    return builder.add_extension(extension, critical=critical)


def _add_proxy_constraints(builder, ca_true):
    builder = builder.add_extension(
        x509.BasicConstraints(ca=ca_true, path_length=None), critical=True
    )
    usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca_true,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    return builder.add_extension(usage, critical=True)


def _add_proxy_san(builder, enabled):
    if not enabled:
        return builder
    san = x509.SubjectAlternativeName([x509.DNSName("evil.example.org")])
    return builder.add_extension(san, critical=False)


def make_proxy(
    parent, kind, path_len, pci_critical, policy_oid, ca_true, with_san,
    not_after_days, not_before_days, serial, extra_ext, namespace,
):
    key = namespace["_key"]()
    subject = _proxy_subject(parent, kind, serial)
    builder = _base_proxy_builder(
        parent, subject, key, serial, not_before_days, not_after_days, namespace
    )
    builder = _add_proxy_info(
        builder, kind, policy_oid, path_len, pci_critical, namespace
    )
    builder = _add_proxy_constraints(builder, ca_true)
    builder = _add_proxy_san(builder, with_san)
    builder = _add_extra_extensions(builder, extra_ext)
    certificate = builder.sign(parent.key, hashes.SHA256())
    return namespace["Cert"](certificate, key)


def _base_crl(ca, next_update_days, this_update_days, namespace):
    return (
        CertificateRevocationListBuilder()
        .issuer_name(ca.cert.subject)
        .last_update(namespace["_EPOCH"] + this_update_days * namespace["_DAY"])
        .next_update(namespace["_EPOCH"] + next_update_days * namespace["_DAY"])
    )


def _add_crl_number(builder, crl_number):
    if crl_number is None:
        return builder
    return builder.add_extension(x509.CRLNumber(crl_number), critical=False)


def _add_delta_indicator(builder, delta_indicator):
    if delta_indicator is None:
        return builder
    extension = x509.DeltaCRLIndicator(delta_indicator)
    return builder.add_extension(extension, critical=True)


def _revocation_entry(certificate, reason, namespace):
    builder = (
        RevokedCertificateBuilder()
        .serial_number(certificate.cert.serial_number)
        .revocation_date(namespace["_EPOCH"])
    )
    if reason is None:
        return builder.build()
    flag = getattr(x509.ReasonFlags, reason)
    return builder.add_extension(x509.CRLReason(flag), critical=False).build()


def _add_revocations(builder, revoked, reason, namespace):
    for certificate in revoked:
        entry = _revocation_entry(certificate, reason, namespace)
        builder = builder.add_revoked_certificate(entry)
    return builder


def make_crl(
    ca, revoked, next_update_days, this_update_days, signer, crl_number,
    delta_indicator, reason, digest_name, namespace,
):
    revoked = revoked or []
    signer = signer or ca
    builder = _base_crl(ca, next_update_days, this_update_days, namespace)
    builder = _add_crl_number(builder, crl_number)
    builder = _add_delta_indicator(builder, delta_indicator)
    builder = _add_revocations(builder, revoked, reason, namespace)
    crl = builder.sign(signer.key, namespace["_digest"](digest_name))
    return crl.public_bytes(serialization.Encoding.PEM)

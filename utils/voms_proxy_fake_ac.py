"""
DER helpers and the VOMS attribute-certificate builder behind
utils/voms_proxy_fake.py.

The CLI module owns the proxy certificate and the flags; this module owns the
bytes of one AttributeCertificate (RFC 5755 as libvoms encodes it) and the
knobs that shape it.  Every knob defaults to the historical output, so a proxy
minted without knobs is byte-for-byte what the fake always produced.

    AcOptions   — the AC-level knobs (signature algorithm, certs extension
                  layout, holder encoding, extra extensions, ...)
    build_voms_ac(user_cert, voms_cert, voms_key, vo, fqan, uri, hours, opts)
                — one signed AC as DER
    acseq_der(acs) — the AC_SEQ ::= SEQUENCE { SEQUENCE OF AC } wrapper

Requires: cryptography (listed in requirements.txt).
"""

import dataclasses
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import ObjectIdentifier
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# DER encoding helpers
# ---------------------------------------------------------------------------

def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF, length & 0xFF])


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_seq(value: bytes) -> bytes:
    return _der_tlv(0x30, value)


def _der_set(value: bytes) -> bytes:
    return _der_tlv(0x31, value)


def _der_int(n: int) -> bytes:
    """Encode an ASN.1 INTEGER (signed, big-endian)."""
    if n == 0:
        return _der_tlv(0x02, b'\x00')
    # Convert to signed big-endian bytes
    byte_len = (n.bit_length() + 8) // 8  # +8 for sign bit headroom
    raw = n.to_bytes(byte_len, byteorder='big', signed=False)
    # Strip leading zero bytes, but keep one if high bit set
    while len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80:
        raw = raw[1:]
    return _der_tlv(0x02, raw)


def _der_oid_content(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.split('.')]
    encoded = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        encoded.extend(_der_oid_part(part))
    return bytes(encoded)


def _der_oid_part(part: int) -> list[int]:
    if part == 0:
        return [0]
    chunks = _oid_chunks(part)
    chunks.reverse()
    return _continuation_chunks(chunks)


def _oid_chunks(part: int) -> list[int]:
    chunks = []
    while part > 0:
        chunks.append(part & 0x7F)
        part >>= 7
    return chunks


def _continuation_chunks(chunks: list[int]) -> list[int]:
    return [value | 0x80 for value in chunks[:-1]] + chunks[-1:]


def _der_oid(oid_str: str) -> bytes:
    return _der_tlv(0x06, _der_oid_content(oid_str))


def _der_octet_string(value: bytes) -> bytes:
    return _der_tlv(0x04, value)


def _der_bit_string(value: bytes) -> bytes:
    # Pad bits = 0 (whole bytes)
    return _der_tlv(0x03, b'\x00' + value)


def _der_utf8(value: str) -> bytes:
    return _der_tlv(0x0C, value.encode('utf-8'))


def _der_ia5(value: str) -> bytes:
    return _der_tlv(0x16, value.encode('ascii'))


def _der_gentime(dt: datetime.datetime) -> bytes:
    s = dt.strftime('%Y%m%d%H%M%SZ')
    return _der_tlv(0x18, s.encode('ascii'))


def _der_explicit(tag_num: int, value: bytes) -> bytes:
    """CONTEXT-SPECIFIC [tag_num] CONSTRUCTED."""
    return _der_tlv(0xA0 | tag_num, value)


def _der_implicit_prim(tag_num: int, value: bytes) -> bytes:
    """CONTEXT-SPECIFIC IMPLICIT [tag_num] PRIMITIVE."""
    return _der_tlv(0x80 | tag_num, value)


def _der_null() -> bytes:
    return b'\x05\x00'


def _der_bool_true() -> bytes:
    return _der_tlv(0x01, b'\xFF')


# ---------------------------------------------------------------------------
# X.500 Name to DER
# ---------------------------------------------------------------------------

_NAME_OID_MAP = {
    NameOID.DOMAIN_COMPONENT: '0.9.2342.19200300.100.1.25',
    NameOID.COMMON_NAME: '2.5.4.3',
    NameOID.ORGANIZATION_NAME: '2.5.4.10',
    NameOID.ORGANIZATIONAL_UNIT_NAME: '2.5.4.11',
    NameOID.COUNTRY_NAME: '2.5.4.6',
    NameOID.LOCALITY_NAME: '2.5.4.7',
    NameOID.STATE_OR_PROVINCE_NAME: '2.5.4.8',
    NameOID.EMAIL_ADDRESS: '1.2.840.113549.1.9.1',
}


def _encode_name_attr(attr: x509.NameAttribute, utf8_all: bool = False) -> bytes:
    """Encode a single RDN attribute as SET { SEQUENCE { OID, value } }.

    domainComponent uses IA5String and everything else UTF8String, unless
    `utf8_all` forces UTF8String for every attribute (the -holder-utf8 knob)."""
    oid_der = _der_oid(_NAME_OID_MAP.get(attr.oid, attr.oid.dotted_string))
    if attr.oid == NameOID.DOMAIN_COMPONENT and not utf8_all:
        val_der = _der_ia5(attr.value)
    else:
        val_der = _der_utf8(attr.value)
    return _der_set(_der_seq(oid_der + val_der))


def _encode_name(name: x509.Name, utf8_all: bool = False) -> bytes:
    """Encode an X.500 Name as DER SEQUENCE of SET of AttributeTypeAndValue."""
    return _der_seq(b''.join(_encode_name_attr(attr, utf8_all) for attr in name))


def _encode_general_name_dn(name: x509.Name, utf8_all: bool = False) -> bytes:
    """GeneralName [4] directoryName (EXPLICIT)."""
    return _der_explicit(4, _encode_name(name, utf8_all))


def _encode_general_names(name: x509.Name, utf8_all: bool = False) -> bytes:
    """GeneralNames SEQUENCE of one directoryName."""
    return _der_seq(_encode_general_name_dn(name, utf8_all))


# ---------------------------------------------------------------------------
# Signature algorithms
# ---------------------------------------------------------------------------

# name -> (AlgorithmIdentifier OID, digest class or None, key kind)
SIG_ALGS = {
    'sha1':    ('1.2.840.113549.1.1.5',  hashes.SHA1,   'rsa'),
    'sha256':  ('1.2.840.113549.1.1.11', hashes.SHA256, 'rsa'),
    'sha384':  ('1.2.840.113549.1.1.12', hashes.SHA384, 'rsa'),
    'sha512':  ('1.2.840.113549.1.1.13', hashes.SHA512, 'rsa'),
    'md5':     ('1.2.840.113549.1.1.4',  hashes.MD5,    'rsa'),
    'pss':     ('1.2.840.113549.1.1.10', hashes.SHA256, 'pss'),
    'ecdsa':   ('1.2.840.10045.4.3.2',   hashes.SHA256, 'ec'),
    'ed25519': ('1.3.101.112',           None,          'ed25519'),
}
_OID_SHA256 = '2.16.840.1.101.3.4.2.1'
_OID_MGF1 = '1.2.840.113549.1.1.8'
_DEFAULT_ALG = {'rsa': 'sha256', 'ec': 'ecdsa', 'ed25519': 'ed25519'}


def key_kind(key) -> str:
    """'rsa', 'ec' or 'ed25519' for a loaded private key."""
    if isinstance(key, rsa.RSAPrivateKey):
        return 'rsa'
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return 'ec'
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return 'ed25519'
    raise ValueError(f"unsupported VOMS host key type {type(key).__name__}")


def resolve_sig_alg(key, name: str | None) -> str:
    """The signature algorithm name to use: `name`, or the key's natural one
    (sha256 for RSA, ecdsa-with-SHA256 for EC, Ed25519) when None."""
    kind = key_kind(key)
    if name is None:
        return _DEFAULT_ALG[kind]
    wanted = SIG_ALGS[name][2]
    required = 'rsa' if wanted == 'pss' else wanted
    if required != kind:
        raise ValueError(f"-sig-alg {name} needs a {required} host key, got {kind}")
    return name


def _pss_params_der() -> bytes:
    """RSASSA-PSS-params: SHA-256, MGF1(SHA-256), salt 32, default trailer."""
    sha256 = _der_seq(_der_oid(_OID_SHA256) + _der_null())
    mgf1 = _der_seq(_der_oid(_OID_MGF1) + sha256)
    return _der_seq(b''.join([_der_explicit(0, sha256), _der_explicit(1, mgf1),
                              _der_explicit(2, _der_int(32))]))


def sig_alg_der(name: str) -> bytes:
    """AlgorithmIdentifier for `name`: NULL params for PKCS#1 v1.5, the PSS
    parameter block for RSASSA-PSS, no params for ECDSA and Ed25519."""
    oid, _digest, kind = SIG_ALGS[name]
    if kind == 'rsa':
        return _der_seq(_der_oid(oid) + _der_null())
    if kind == 'pss':
        return _der_seq(_der_oid(oid) + _pss_params_der())
    return _der_seq(_der_oid(oid))


def sign_tbs(key, name: str, tbs: bytes) -> bytes:
    _oid, digest, kind = SIG_ALGS[name]
    if kind == 'ed25519':
        return key.sign(tbs)
    if kind == 'ec':
        return key.sign(tbs, ec.ECDSA(digest()))
    if kind == 'pss':
        return key.sign(tbs, padding.PSS(mgf=padding.MGF1(digest()), salt_length=32),
                        digest())
    return key.sign(tbs, padding.PKCS1v15(), digest())


# ---------------------------------------------------------------------------
# VOMS Attribute Certificate builder
# ---------------------------------------------------------------------------

OID_VOMS_FQANS = '1.3.6.1.4.1.8005.100.100.4'
OID_VOMS_CERTS = '1.3.6.1.4.1.8005.100.100.10'
OID_VOMS_ATTRS = '1.3.6.1.4.1.8005.100.100.11'
OID_TARGETS = '2.5.29.55'
OID_NO_REV_AVAIL = '2.5.29.56'
OID_AUTH_KEY_ID = '2.5.29.35'
OID_SHA256_RSA = SIG_ALGS['sha256'][0]
_AKI_GARBAGE = b'\xde\xad\xbe\xef' * 5


@dataclasses.dataclass
class AcOptions:
    """The AC-level test knobs; every default reproduces the historical AC."""
    sig_alg: str | None = None            # None: the key's natural algorithm
    inner_alg_mismatch: bool = False      # TBS says sha1WithRSA, outer sha256
    no_certs: bool = False                # omit the certs extension
    certs_order: str = 'signer'           # 'signer' | 'reversed' | 'chain'
    ca_cert: x509.Certificate | None = None   # the signer's issuer, for the latter two
    aki_mismatch: bool = False            # AKI keyid set to garbage
    critical_exts: list[str] = dataclasses.field(default_factory=list)
    noncritical_exts: list[str] = dataclasses.field(default_factory=list)
    no_policy_uri: bool = False           # omit policyAuthority
    uri_noport: bool = False              # policy URI "vo://host"
    utf8_fqan: bool = False               # FQAN values as UTF8String
    fqan_bad: bool = False                # extra malformed FQAN value
    targets: list[str] = dataclasses.field(default_factory=list)
    gen_attrs: list[tuple[str, str, str]] = dataclasses.field(default_factory=list)
    holder_utf8: bool = False             # holder DN attributes all UTF8String
    holder_entity_name: bool = False      # holder [1] entityName, no baseCertificateID
    not_before_offset: int | None = None  # AC notBefore = now + offset seconds
    holder_serial: int | None = None      # serial the holder names


def _holder_der(user_cert: x509.Certificate, opts: AcOptions) -> bytes:
    """Holder ::= SEQUENCE { baseCertificateID [0] IMPLICIT IssuerSerial }
    (VOMS names the user certificate's SUBJECT as the issuer), or with
    -holder-entity-name: SEQUENCE { entityName [1] IMPLICIT GeneralNames }."""
    if opts.holder_entity_name:
        return _der_seq(_der_tlv(0xA1, _encode_general_name_dn(user_cert.subject,
                                                               opts.holder_utf8)))
    serial = user_cert.serial_number if opts.holder_serial is None else opts.holder_serial
    names = _encode_general_names(user_cert.subject, opts.holder_utf8)
    return _der_seq(_der_explicit(0, names + _der_int(serial)))


def _validity_der(hours: int, opts: AcOptions) -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc)
    if opts.not_before_offset is None:
        not_before = now - datetime.timedelta(minutes=5)
    else:
        not_before = now + datetime.timedelta(seconds=opts.not_before_offset)
    not_after = now + datetime.timedelta(hours=hours)
    return _der_seq(_der_gentime(not_before) + _der_gentime(not_after))


def _fqan_value_der(fqan: str, utf8: bool) -> bytes:
    return _der_utf8(fqan) if utf8 else _der_octet_string(fqan.encode('ascii'))


def _fqan_attr_der(vo: str, fqan: str, uri: str, opts: AcOptions) -> bytes:
    """The FQAN attribute: SEQUENCE { OID, SET { IetfAttrSyntax } } where
    IetfAttrSyntax ::= SEQUENCE { policyAuthority [0] GeneralNames OPTIONAL,
    values SEQUENCE OF (OCTET STRING | UTF8String) }."""
    parts = []
    if not opts.no_policy_uri:
        host = uri.split(':')[0] if opts.uri_noport else uri
        policy_uri = f"{vo}://{host}".encode('ascii')
        parts.append(_der_explicit(0, _der_implicit_prim(6, policy_uri)))
    values = [_fqan_value_der(fqan, opts.utf8_fqan)]
    if opts.fqan_bad:
        values.append(_der_octet_string(f"/{vo}/Role=bad,\x01".encode('latin-1')))
    parts.append(_der_seq(b''.join(values)))
    return _der_seq(_der_oid(OID_VOMS_FQANS) + _der_set(_der_seq(b''.join(parts))))


def _extension_der(oid: str, value: bytes, critical: bool = False) -> bytes:
    flag = _der_bool_true() if critical else b''
    return _der_seq(b''.join([_der_oid(oid), flag, _der_octet_string(value)]))


def _certs_ext_der(voms_cert: x509.Certificate, opts: AcOptions) -> bytes:
    """The certs extension: SEQUENCE { SEQUENCE OF Certificate }, the signer
    alone by default; 'chain' appends the CA, 'reversed' puts the CA first."""
    certs = [voms_cert]
    if opts.certs_order != 'signer':
        if opts.ca_cert is None:
            raise ValueError("-certs-order reversed / -certs-chain need the CA certificate")
        certs = [opts.ca_cert, voms_cert] if opts.certs_order == 'reversed' \
            else [voms_cert, opts.ca_cert]
    ders = b''.join(c.public_bytes(serialization.Encoding.DER) for c in certs)
    return _extension_der(OID_VOMS_CERTS, _der_seq(_der_seq(ders)))


def _ski_bytes(voms_cert: x509.Certificate) -> bytes | None:
    try:
        ext = voms_cert.extensions.get_extension_for_oid(ObjectIdentifier('2.5.29.14'))
    except x509.ExtensionNotFound:
        return None
    return ext.value.digest


def _aki_ext_der(voms_cert: x509.Certificate, opts: AcOptions) -> bytes:
    keyid = _AKI_GARBAGE if opts.aki_mismatch else _ski_bytes(voms_cert)
    if keyid is None:
        return b''
    return _extension_der(OID_AUTH_KEY_ID, _der_seq(_der_implicit_prim(0, keyid)))


def _targets_ext_der(opts: AcOptions) -> bytes:
    """targetInformation: SEQUENCE { SEQUENCE OF Target }, each Target the
    CHOICE targetName [0] EXPLICIT GeneralName with a dNSName ([2] IA5)."""
    if not opts.targets:
        return b''
    targets = b''.join(_der_explicit(0, _der_implicit_prim(2, host.encode('ascii')))
                       for host in opts.targets)
    return _extension_der(OID_TARGETS, _der_seq(_der_seq(targets)))


def _gen_attrs_ext_der(voms_cert: x509.Certificate, opts: AcOptions) -> bytes:
    """Generic attributes: SEQUENCE { SEQUENCE OF { grantor GeneralNames,
    attributes SEQUENCE OF { name, qualifier, value OCTET STRING } } }."""
    if not opts.gen_attrs:
        return b''
    triples = b''.join(
        _der_seq(b''.join(_der_octet_string(s.encode('utf-8'))
                          for s in (name, qualifier, value)))
        for name, value, qualifier in opts.gen_attrs)
    holder = _der_seq(_encode_general_names(voms_cert.subject) + _der_seq(triples))
    return _extension_der(OID_VOMS_ATTRS, _der_seq(_der_seq(holder)))


def _unknown_exts_der(opts: AcOptions) -> bytes:
    critical = [_extension_der(oid, _der_null(), critical=True) for oid in opts.critical_exts]
    plain = [_extension_der(oid, _der_null()) for oid in opts.noncritical_exts]
    return b''.join(critical + plain)


def _extensions_der(voms_cert: x509.Certificate, opts: AcOptions) -> bytes:
    certs = b'' if opts.no_certs else _certs_ext_der(voms_cert, opts)
    no_rev = _extension_der(OID_NO_REV_AVAIL, _der_null())
    body = [certs, no_rev, _aki_ext_der(voms_cert, opts), _targets_ext_der(opts),
            _gen_attrs_ext_der(voms_cert, opts), _unknown_exts_der(opts)]
    return _der_seq(b''.join(body))


def build_voms_ac(
    user_cert: x509.Certificate,
    voms_cert: x509.Certificate,
    voms_key,
    vo: str,
    fqan: str,
    uri: str,
    hours: int,
    opts: AcOptions | None = None,
) -> bytes:
    """Build and sign one VOMS Attribute Certificate as raw DER.

    `hours` is the AC's own validity (notAfter = now + hours; negative means
    already expired).  `opts` carries the test knobs (AcOptions); None is the
    historical AC: sha256WithRSA, signer-only certs extension, AKI from the
    signer's SKI, OCTET STRING FQANs, "vo://host:port" policy URI.
    """
    opts = opts or AcOptions()
    alg = resolve_sig_alg(voms_key, opts.sig_alg)
    outer_alg = sig_alg_der(alg)
    inner_alg = sig_alg_der('sha1') if opts.inner_alg_mismatch else outer_alg
    # AttCertIssuer ::= v2Form [0] IMPLICIT SEQUENCE { issuerName GeneralNames }
    ac_issuer = _der_explicit(0, _encode_general_names(voms_cert.subject))
    tbs_der = _der_seq(b''.join([
        _der_int(1),                                   # version v2
        _holder_der(user_cert, opts),
        ac_issuer,
        inner_alg,
        _der_int(1),                                   # serial
        _validity_der(hours, opts),
        _der_seq(_fqan_attr_der(vo, fqan, uri, opts)),  # attributes
        _extensions_der(voms_cert, opts),
    ]))
    signature = sign_tbs(voms_key, alg, tbs_der)
    # AttributeCertificate ::= SEQUENCE { tbs, sigAlg, sig }
    return _der_seq(tbs_der + outer_alg + _der_bit_string(signature))


def acseq_der(acs: list[bytes]) -> bytes:
    """AC_SEQ ::= SEQUENCE { SEQUENCE OF AttributeCertificate }, exactly as
    libvoms encodes the VOMS extension value (an empty list is a legal
    encoding that the verifier must refuse)."""
    return _der_seq(_der_seq(b''.join(acs)))

#!/usr/bin/env python3
"""
Pure-Python replacement for voms-proxy-fake from the VOMS project.

Generates an RFC 3820 proxy certificate containing a VOMS Attribute
Certificate (AC) shaped exactly as voms-proxy-init/libvoms emit it, which the
native verifier (shared/voms/) — and libvomsapi, historically — accepts.

Test-only knobs let a suite mint deliberately BAD (or merely unusual)
credentials without touching the proxy certificate itself, so GSI still
authenticates and only the AC verdict changes.  Every knob is optional and
the default output is byte-identical to the knob-less fake; `--help` lists
them all.  The two historical ones:

    -ac-hours N        AC validity: notAfter = now + N hours (default: -hours).
                       Negative N yields an AC that expired |N| hours ago while
                       the proxy certificate stays valid.
    -holder-serial N   serial number the AC's holder names (default: the user
                       certificate's own serial).  A different value breaks the
                       holder binding — the AC no longer belongs to this EEC.

Usage (same flags as the C++ voms-proxy-fake):

    python3 utils/voms_proxy_fake.py \\
        -cert   usercert.pem \\
        -key    userkey.pem \\
        -certdir /path/to/ca \\
        -hostcert vomscert.pem \\
        -hostkey  vomskey.pem \\
        -voms cms \\
        -fqan "/cms/Role=NULL/Capability=NULL" \\
        -uri  "voms.test.local:15000" \\
        -out  proxy_cms.pem \\
        -hours 24

The AC bytes themselves come from utils/voms_proxy_fake_ac.py.
Requires: cryptography (listed in requirements.txt).
"""

import argparse
import dataclasses
import datetime
import os
import random
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    CertificateBuilder, Name, NameAttribute, ObjectIdentifier,
    UnrecognizedExtension,
)
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from voms_proxy_fake_ac import (  # noqa: E402
    AcOptions, SIG_ALGS, _der_oid, _der_seq, acseq_der, build_voms_ac,
)


# ---------------------------------------------------------------------------
# Proxy certificate builder (RFC 3820 with VOMS AC extension)
# ---------------------------------------------------------------------------

OID_PROXY_CERT_INFO = '1.3.6.1.5.5.7.1.14'
OID_VOMS_EXTENSION  = '1.3.6.1.4.1.8005.100.100.5'


@dataclasses.dataclass
class ProxyOptions:
    """Proxy-level test knobs; the defaults are the historical proxy."""
    legacy_proxy: bool = False   # GT2 shape: CN=proxy, no proxyCertInfo
    legacy_kind: str = 'proxy'   # GT2 CN: proxy | limited ("limited proxy") | numeric
    delegate: bool = False       # add a second-level proxy without a VOMS extension
    empty_acseq: bool = False    # AC_SEQ with zero ACs
    ac_count: int = 1            # repeat every AC this many times


def _proxy_cert_info_der() -> bytes:
    """DER-encode proxyCertInfo with id-ppl-inheritAll policy."""
    id_ppl_inherit_all = '1.3.6.1.5.5.7.21.1'
    proxy_policy = _der_seq(_der_oid(id_ppl_inherit_all))
    return _der_seq(proxy_policy)


def _ac_pairs(vo, fqan):
    """Normalise the (vo, fqan) arguments into the AC list.

    Both are either a single string (the historical single-VO call) or an
    equal-length sequence.  They pair POSITIONALLY — pair i becomes AC i — which
    is exactly the property the 2.0 F20 authdb tests rely on to build a
    cross-tuple credential (see src/auth/authz/authdb.c::adb_pair_matches).
    """
    vos = [vo] if isinstance(vo, str) else list(vo)
    fqans = [fqan] if isinstance(fqan, str) else list(fqan)
    if len(vos) != len(fqans) or not vos:
        raise ValueError("-voms and -fqan must be given the same number of times")
    return list(zip(vos, fqans))


def _write_proxy_atomically(out_path: str, combined: bytes) -> None:
    """Write the proxy 0400, replacing any existing file.

    Existing proxy files are intentionally mode 0400.  Replacing them via
    O_TRUNC fails once the file is no longer owner-writable, so write a new file
    in the same directory and atomically swap it into place instead.
    """
    out_dir = os.path.dirname(out_path) or '.'
    os.makedirs(out_dir, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix='.voms-proxy-', dir=out_dir)
    try:
        try:
            os.write(fd, combined)
            os.fchmod(fd, 0o400)
        finally:
            os.close(fd)

        os.replace(tmp_path, out_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def _load_pem_cert(path: str) -> x509.Certificate:
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())


def _load_pem_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _key_usage() -> x509.KeyUsage:
    # A GSI proxy carries a critical keyUsage of digitalSignature (see
    # make_proxy.py).  Without it the proxy cannot be used to sign a
    # delegated proxy request — XrdCrypto's X509SignProxyReq rejects a
    # signing chain that lacks keyUsage.  Matching the plain proxy keeps the
    # VOMS-decorated proxy usable everywhere the plain one is.
    return x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    )


def _proxy_builder(issuer: x509.Certificate, cn: str, public_key, serial: int,
                   hours: int, voms_ext: bytes | None, legacy: bool):
    """A proxy certificate builder: subject = issuer's subject + CN=<cn>, the
    VOMS extension when given, then basicConstraints, keyUsage and — unless
    `legacy` (GT2 proxies predate RFC 3820) — proxyCertInfo."""
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = Name(list(issuer.subject) + [NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=hours))
    )
    if voms_ext is not None:
        builder = builder.add_extension(
            UnrecognizedExtension(ObjectIdentifier(OID_VOMS_EXTENSION), voms_ext),
            critical=False)
    builder = (
        builder
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(), critical=True)
    )
    if legacy:
        return builder
    return builder.add_extension(
        UnrecognizedExtension(ObjectIdentifier(OID_PROXY_CERT_INFO), _proxy_cert_info_der()),
        critical=True)


LEGACY_CN = {'proxy': 'proxy', 'limited': 'limited proxy', 'numeric': None}


def _sign_proxy(issuer: x509.Certificate, issuer_key, hours: int,
                voms_ext: bytes | None, legacy: bool = False,
                legacy_kind: str = 'proxy'):
    """Mint (certificate, key) for a proxy of `issuer`; the CN is a random
    serial (voms-proxy-fake's behaviour) or the literal 'proxy' for GT2."""
    proxy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    proxy_serial = random.randint(100000000, 2147483647)
    cn = (LEGACY_CN.get(legacy_kind) or str(proxy_serial)) if legacy else str(proxy_serial)
    builder = _proxy_builder(issuer, cn, proxy_key.public_key(), proxy_serial,
                             hours, voms_ext, legacy)
    return builder.sign(issuer_key, hashes.SHA256()), proxy_key


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _voms_extension_value(user_cert, voms_cert, voms_key, pairs, uri, ac_hours,
                          ac_opts: AcOptions, proxy_opts: ProxyOptions) -> bytes:
    """AC_SEQ with one AC per (vo, fqan) pair — each repeated -ac-count times,
    or none at all for -empty-acseq."""
    if proxy_opts.empty_acseq:
        return acseq_der([])
    acs = [build_voms_ac(user_cert, voms_cert, voms_key, v, f, uri, ac_hours, ac_opts)
           for v, f in pairs]
    return acseq_der(acs * proxy_opts.ac_count)


def _resolved_options(ac_opts, proxy_opts, holder_serial):
    """Defaults for absent option objects; -holder-serial lands in AcOptions."""
    ac_opts = dataclasses.replace(ac_opts or AcOptions())
    if holder_serial is not None:
        ac_opts.holder_serial = holder_serial
    return ac_opts, proxy_opts or ProxyOptions()


def _chain_pem(proxy_cert, proxy_key, user_cert_pem: bytes, hours: int,
               delegate: bool) -> bytes:
    """Output: proxy cert + proxy key + user cert (chain); with `delegate` a
    second-level proxy (no VOMS extension) leads and the VOMS proxy follows."""
    if not delegate:
        return b''.join([_pem(proxy_cert), _key_pem(proxy_key), user_cert_pem])
    leaf_cert, leaf_key = _sign_proxy(proxy_cert, proxy_key, hours, None)
    return b''.join([_pem(leaf_cert), _key_pem(leaf_key), _pem(proxy_cert), user_cert_pem])


def build_voms_proxy(
    user_cert_path: str,
    user_key_path: str,
    voms_cert_path: str,
    voms_key_path: str,
    vo,
    fqan,
    uri: str,
    out_path: str,
    hours: int = 24,
    ac_hours: int | None = None,
    holder_serial: int | None = None,
    ac_opts: AcOptions | None = None,
    proxy_opts: ProxyOptions | None = None,
):
    """Write a VOMS proxy carrying one AC per (vo, fqan) pair.

    `vo` and `fqan` are either two strings (the historical single-VO call) or
    two equal-length sequences, which produce a genuine multi-VO proxy — the
    only way to build a credential whose derived (vorg, role) tuples must be
    paired POSITIONALLY rather than crossed (2.0 F20; see
    src/auth/authz/authdb.c::adb_pair_matches).

    `ac_hours` (default `hours`) is the AC validity on its own — negative
    mints an already-expired AC inside a still-valid proxy.  `holder_serial`
    (default: the user certificate's serial) is the serial the AC's holder
    names; any other value breaks the holder binding.  `ac_opts` and
    `proxy_opts` carry the remaining test knobs (see AcOptions and
    ProxyOptions).  All exist only so the test suite can produce bad ACs the
    verifier must refuse.

    The file holds the proxy certificate, its key and the user certificate;
    with `proxy_opts.delegate` a second-level proxy (no VOMS extension) leads
    and the VOMS proxy follows it, so the AC sits on chain index 1.
    """
    pairs = _ac_pairs(vo, fqan)
    ac_opts, proxy_opts = _resolved_options(ac_opts, proxy_opts, holder_serial)
    ac_hours = hours if ac_hours is None else ac_hours

    user_cert = _load_pem_cert(user_cert_path)
    user_key = _load_pem_key(user_key_path)
    voms_cert = _load_pem_cert(voms_cert_path)
    voms_key = _load_pem_key(voms_key_path)

    voms_ac_der = _voms_extension_value(user_cert, voms_cert, voms_key, pairs, uri,
                                        ac_hours, ac_opts, proxy_opts)
    proxy_cert, proxy_key = _sign_proxy(user_cert, user_key, hours, voms_ac_der,
                                        proxy_opts.legacy_proxy,
                                        proxy_opts.legacy_kind)
    with open(user_cert_path, 'rb') as f:
        user_cert_pem = f.read()
    _write_proxy_atomically(out_path, _chain_pem(proxy_cert, proxy_key, user_cert_pem,
                                                 hours, proxy_opts.delegate))

    not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
    print(f"Your proxy is valid until {not_after.strftime('%c %Z')}")


# ---------------------------------------------------------------------------
# CLI — compatible with voms-proxy-fake flags
# ---------------------------------------------------------------------------

def _add_compat_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument('-cert',     required=True, help='User certificate PEM')
    p.add_argument('-key',      required=True, help='User private key PEM')
    p.add_argument('-certdir',  required=False,
                   help='Trusted CA directory (only read for -certs-order/-certs-chain: '
                        '<certdir>/ca.pem is the signer CA unless -cacert is given)')
    p.add_argument('-hostcert', required=True, help='VOMS server certificate PEM')
    p.add_argument('-hostkey',  required=True,
                   help='VOMS server private key PEM (RSA, EC P-256 or Ed25519)')
    p.add_argument('-voms',     required=True, action='append',
                   help='VO name (repeatable; pairs positionally with -fqan)')
    p.add_argument('-fqan',     required=True, action='append',
                   help='FQAN string (e.g. /cms/Role=NULL/Capability=NULL); repeatable')
    p.add_argument('-uri',      required=True, help='VOMS server URI (hostname:port)')
    p.add_argument('-out',      required=True, help='Output proxy file path')
    p.add_argument('-hours',    type=int, default=24, help='Proxy validity in hours (default: 24)')
    p.add_argument('-ac-hours', type=int, default=None, dest='ac_hours',
                   help='AC validity in hours (default: same as -hours); negative = already expired')
    p.add_argument('-holder-serial', type=int, default=None, dest='holder_serial',
                   help='serial the AC holder names (default: the user certificate serial); '
                        'test-only knob to break the holder binding')
    p.add_argument('-rfc',      action='store_true', help='RFC proxy (always true, accepted for compat)')


def _add_ac_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group('AC test knobs (all optional; defaults leave the AC unchanged)')
    g.add_argument('-sig-alg', dest='sig_alg', choices=sorted(SIG_ALGS), default=None,
                   help='AC signature algorithm (default: sha256WithRSA for an RSA host key, '
                        'ecdsa-with-SHA256 for EC, Ed25519 for Ed25519; ecdsa/ed25519 need '
                        'a host key of that type; md5 is what the verifier must refuse)')
    g.add_argument('-inner-alg-mismatch', dest='inner_alg_mismatch', action='store_true',
                   help='TBS signature algorithm says sha1WithRSA while the outer says sha256')
    g.add_argument('-no-certs', dest='no_certs', action='store_true',
                   help='omit the certs extension (no embedded VOMS server certificate)')
    g.add_argument('-certs-order', dest='certs_order', choices=['reversed'], default=None,
                   help='"reversed": embed the CA certificate first and the signer last')
    g.add_argument('-certs-chain', dest='certs_chain', action='store_true',
                   help='embed the signer followed by its issuer CA certificate')
    g.add_argument('-cacert', default=None,
                   help='the signer CA certificate PEM for -certs-order/-certs-chain '
                        '(default: <certdir>/ca.pem)')
    g.add_argument('-aki-mismatch', dest='aki_mismatch', action='store_true',
                   help='authorityKeyIdentifier keyid set to garbage bytes')
    g.add_argument('-critical-ext', dest='critical_ext', action='append', default=[],
                   metavar='OID', help='add an unknown extension with this OID, critical (repeatable)')
    g.add_argument('-noncritical-ext', dest='noncritical_ext', action='append', default=[],
                   metavar='OID', help='add an unknown extension with this OID, non-critical')
    g.add_argument('-no-policy-uri', dest='no_policy_uri', action='store_true',
                   help='omit the policyAuthority (VO must come from the FQAN)')
    g.add_argument('-uri-noport', dest='uri_noport', action='store_true',
                   help='policy URI "vo://host" without the :port')
    g.add_argument('-utf8-fqan', dest='utf8_fqan', action='store_true',
                   help='encode FQAN values as UTF8String instead of OCTET STRING')
    g.add_argument('-fqan-bad', dest='fqan_bad', action='store_true',
                   help='add an extra FQAN value containing a comma and a 0x01 byte')
    g.add_argument('-targets', default=None, metavar='HOST1,HOST2',
                   help='targetInformation extension naming these dNSName targets')
    g.add_argument('-gen-attr', dest='gen_attr', action='append', default=[],
                   metavar='NAME=VALUE:QUALIFIER',
                   help='a generic attribute (repeatable); the grantor is the VOMS cert subject')
    g.add_argument('-holder-utf8', dest='holder_utf8', action='store_true',
                   help='encode every holder DN attribute as UTF8String (default: DC as IA5String)')
    g.add_argument('-holder-entity-name', dest='holder_entity_name', action='store_true',
                   help='holder uses [1] entityName instead of baseCertificateID')
    g.add_argument('-ac-not-before-offset', dest='ac_not_before_offset', type=int, default=None,
                   metavar='SECONDS', help='AC notBefore = now + SECONDS (default: now - 300)')


def _add_proxy_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group('proxy test knobs')
    g.add_argument('-empty-acseq', dest='empty_acseq', action='store_true',
                   help='VOMS extension holding an AC_SEQ with zero ACs')
    g.add_argument('-ac-count', dest='ac_count', type=int, default=1, metavar='N',
                   help='repeat every AC N times in the AC_SEQ (e.g. 40 to exceed the cap)')
    g.add_argument('-legacy-proxy', dest='legacy_proxy', action='store_true',
                   help='GT2-style proxy: subject = user DN + CN=proxy, no proxyCertInfo')
    g.add_argument('-legacy-proxy-kind', dest='legacy_kind', default='proxy',
                   choices=('proxy', 'limited', 'numeric'),
                   help='with -legacy-proxy: the GT2 CN — "proxy" (default), '
                        '"limited proxy" (a limited proxy), or a numeric CN')
    g.add_argument('-delegate', action='store_true',
                   help='write a second-level proxy (no VOMS extension) signed by the VOMS '
                        'proxy; the file holds leaf, VOMS proxy, user cert (AC on index 1)')


def _parse_gen_attr(spec: str) -> tuple[str, str, str]:
    """'name=value:qualifier' -> (name, value, qualifier); qualifier may be empty."""
    name, _, rest = spec.partition('=')
    value, _, qualifier = rest.partition(':')
    if not name or not rest:
        raise SystemExit(f"-gen-attr expects NAME=VALUE[:QUALIFIER], got {spec!r}")
    return name, value, qualifier


def _ca_cert_for(args) -> x509.Certificate | None:
    """The signer CA for -certs-order/-certs-chain: -cacert, else <certdir>/ca.pem."""
    if args.certs_order is None and not args.certs_chain:
        return None
    path = args.cacert or (os.path.join(args.certdir, 'ca.pem') if args.certdir else None)
    if path is None:
        raise SystemExit("-certs-order/-certs-chain need -cacert or -certdir")
    return _load_pem_cert(path)


def _certs_order(args) -> str:
    if args.certs_chain:
        return 'chain'
    return args.certs_order or 'signer'


def _targets(args) -> list[str]:
    return [host for host in (args.targets or '').split(',') if host]


def _ac_options(args) -> AcOptions:
    return AcOptions(
        sig_alg=args.sig_alg, inner_alg_mismatch=args.inner_alg_mismatch,
        no_certs=args.no_certs, certs_order=_certs_order(args), ca_cert=_ca_cert_for(args),
        aki_mismatch=args.aki_mismatch, critical_exts=list(args.critical_ext),
        noncritical_exts=list(args.noncritical_ext), no_policy_uri=args.no_policy_uri,
        uri_noport=args.uri_noport, utf8_fqan=args.utf8_fqan, fqan_bad=args.fqan_bad,
        targets=_targets(args), gen_attrs=[_parse_gen_attr(s) for s in args.gen_attr],
        holder_utf8=args.holder_utf8, holder_entity_name=args.holder_entity_name,
        not_before_offset=args.ac_not_before_offset,
    )


def main():
    p = argparse.ArgumentParser(
        description='Generate a VOMS proxy certificate (pure-Python replacement for voms-proxy-fake)',
    )
    _add_compat_flags(p)
    _add_ac_flags(p)
    _add_proxy_flags(p)
    args = p.parse_args()

    build_voms_proxy(
        user_cert_path=args.cert,
        user_key_path=args.key,
        voms_cert_path=args.hostcert,
        voms_key_path=args.hostkey,
        vo=args.voms,
        fqan=args.fqan,
        uri=args.uri,
        out_path=args.out,
        hours=args.hours,
        ac_hours=args.ac_hours,
        holder_serial=args.holder_serial,
        ac_opts=_ac_options(args),
        proxy_opts=ProxyOptions(legacy_proxy=args.legacy_proxy, legacy_kind=args.legacy_kind, delegate=args.delegate,
                                empty_acseq=args.empty_acseq, ac_count=args.ac_count),
    )


if __name__ == '__main__':
    main()

from datetime import datetime, timezone, timedelta
from typing import NamedTuple, Union, Optional

import oqs
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5480

import chameleon

_P256_PRIVATE_KEY = serialization.load_pem_private_key("""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIObLW92AqkWunJXowVR2Z5/+yVPBaFHnEedDk5WJxk/BoAoGCCqGSM49
AwEHoUQDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV
uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==
-----END EC PRIVATE KEY-----
""".encode(), password=None)

_DUMMY_PRIVATE_KEY = _P256_PRIVATE_KEY

_P384_PRIVATE_KEY = serialization.load_pem_private_key("""
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDiVjMo36v2gYhga5EyQoHB1YpEVkMbCdUQs1/syfMHyhgihG+iZxNx
qagbrA41dJ2gBwYFK4EEACKhZANiAARbCQG4hSMpbrkZ1Q/6GpyzdLxNQJWGKCv+
yhGx2VrbtUc0r1cL+CtyKM8ia89MJd28/jsaOtOUMO/3Y+HWjS4VHZFyC3eVtY2m
s0Y5YTqPubWo2kjGdHEX+ZGehCTzfsg=
-----END EC PRIVATE KEY-----
""".encode(), password=None)

_P521_PRIVATE_KEY = serialization.load_pem_private_key("""
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB2STcygqIf42Zdno32HTmN6Esy0d9bghmU1ZpTWi3ZV5QaWOP3ntF
yFQBPcd6NbGGVbhMlmpgIg1A+R7Z9RRYAuqgBwYFK4EEACOhgYkDgYYABAHQ/XJX
qEx0f1YldcBzhdvr8vUr6lgIPbgv3RUx2KrjzIdf8C/3+i2iYNjrYtbS9dZJJ44y
FzagYoy7swMItuYY2wD2KtIExkYDWbyBiriWG/Dw/A7FquikKBc85W8A3psVfB5c
gsZPVi/K3vxKTCj200LPPvYW/ILTO3KFySHyvzb92A==
-----END EC PRIVATE KEY-----
""".encode(), password=None)


class PqcKeyPair(NamedTuple):
    oid: univ.ObjectIdentifier
    oqs_instance: oqs.Signature
    public_bytes: bytes


def _calculate_key_hash(key: Union[PqcKeyPair, ec.EllipticCurvePrivateKey]):
    if isinstance(key, PqcKeyPair):
        octets = key.public_bytes
    else:
        octets = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    h = hashes.Hash(hashes.SHA1())
    h.update(octets)

    return h.finalize()


_CURVE_TO_HASH_CLS = {
    ec.SECP256R1: hashes.SHA256,
    ec.SECP384R1: hashes.SHA384,
    ec.SECP521R1: hashes.SHA512,
}

_OID_TO_CURVE = {
    rfc5480.secp256r1: ec.SECP256R1,
    rfc5480.secp384r1: ec.SECP384R1,
    rfc5480.secp521r1: ec.SECP521R1,
}

_CURVE_TO_OID = {v: k for k, v in _OID_TO_CURVE.items()}


_CURVE_TO_SIG_ALG = {
    ec.SECP256R1: rfc5480.ecdsa_with_SHA256,
    ec.SECP384R1: rfc5480.ecdsa_with_SHA384,
    ec.SECP521R1: rfc5480.ecdsa_with_SHA512,
}


def _issue_certificate(builder: x509.CertificateBuilder, subject_key: Union[PqcKeyPair, ec.EllipticCurvePrivateKey],
                      issuer_key: Union[PqcKeyPair, ec.EllipticCurvePrivateKey],
                    delta_certificate: Optional[rfc5280.Certificate]=None) -> rfc5280.Certificate:
    builder = builder.public_key(_DUMMY_PRIVATE_KEY.public_key())
    builder = builder.add_extension(x509.SubjectKeyIdentifier(_calculate_key_hash(subject_key)), False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier(_calculate_key_hash(issuer_key), None, None), False)

    cert = builder.sign(_DUMMY_PRIVATE_KEY, hashes.SHA256())

    pyasn1_cert, _ = decode(cert.public_bytes(serialization.Encoding.DER), asn1Spec=rfc5280.Certificate())

    spki = pyasn1_cert['tbsCertificate']['subjectPublicKeyInfo']
    if isinstance(subject_key, PqcKeyPair):
        spki_alg = rfc5280.AlgorithmIdentifier()
        spki_alg['algorithm'] = subject_key.oid

        spki['algorithm'] = spki_alg
        spki['subjectPublicKey'] = univ.BitString(hexValue=subject_key.public_bytes.hex())
    else:
        spki['algorithm']['parameters'] = encode(_CURVE_TO_OID[type(subject_key.curve)])
        spki['subjectPublicKey'] = univ.BitString(hexValue=subject_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        ).hex())

    if isinstance(issuer_key, PqcKeyPair):
        pyasn1_cert['tbsCertificate']['signature']['algorithm'] = issuer_key.oid
    else:
        pyasn1_cert['tbsCertificate']['signature']['algorithm'] = _CURVE_TO_SIG_ALG[type(issuer_key.curve)]

    if delta_certificate is not None:
        dcd_ext_value = chameleon.build_delta_cert_descriptor_value(pyasn1_cert['tbsCertificate'], delta_certificate)

        ext = rfc5280.Extension()
        ext['extnID'] = chameleon.id_ce_prototype_chameleon_delta_descriptor
        ext['extnValue'] = univ.OctetString(encode(dcd_ext_value))

        pyasn1_cert['tbsCertificate']['extensions'].append(ext)

    tbs_octets = encode(pyasn1_cert['tbsCertificate'])

    if isinstance(issuer_key, PqcKeyPair):
        signature_value = issuer_key.oqs_instance.sign(tbs_octets)
    else:
        hash_alg = _CURVE_TO_HASH_CLS[type(issuer_key.curve)]()
        signature_value = issuer_key.sign(tbs_octets, ec.ECDSA(hash_alg))

    pyasn1_cert['signatureAlgorithm'] = pyasn1_cert['tbsCertificate']['signature']
    pyasn1_cert['signature'] = univ.BitString(hexValue=signature_value.hex())

    return pyasn1_cert


_ROOT_SHARED_RDNS = [
    x509.NameAttribute(x509.OID_COUNTRY_NAME, 'XX'),
    x509.NameAttribute(x509.OID_ORGANIZATION_NAME, 'Royal Institute of Public Key Infrastructure'),
    x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, 'Post-Heffalump Research Department'),
]


_DILITHIUM_ROOT_NAME = x509.Name(_ROOT_SHARED_RDNS + [
    x509.NameAttribute(x509.OID_COMMON_NAME, 'Dilithium Root - G1')
])


_ECDSA_ROOT_NAME = x509.Name(_ROOT_SHARED_RDNS + [
    x509.NameAttribute(x509.OID_COMMON_NAME, 'ECDSA Root - G1')
])

_ROOT_NOT_BEFORE = datetime.now(timezone.utc)
_ROOT_NOT_AFTER = datetime.now(timezone.utc) + timedelta(weeks=52*10)


def _add_shared_root_extensions(builder: x509.CertificateBuilder):
    builder = builder.add_extension(x509.BasicConstraints(True, None), True)
    builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)

    return builder


def _generate_dilthium_key() -> PqcKeyPair:
    instance = oqs.Signature('Dilithium3')
    public_bytes = instance.generate_keypair()

    return PqcKeyPair(univ.ObjectIdentifier('1.3.6.1.4.1.2.267.7.6.5'), instance, public_bytes)


def _issue_root(name, key, delta_cert: Optional[rfc5280.Certificate]=None):
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.issuer_name(name)
    builder = builder.subject_name(name)
    builder = builder.not_valid_before(_ROOT_NOT_BEFORE)
    builder = builder.not_valid_after(_ROOT_NOT_AFTER)

    builder = builder.add_extension(x509.BasicConstraints(True, None), True)
    builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)

    return _issue_certificate(builder, key, key, delta_cert)


def issue_dilthium_root(key: PqcKeyPair, delta_cert: Optional[rfc5280.Certificate]=None):
    return _issue_root(_DILITHIUM_ROOT_NAME, key, delta_cert)


def issue_ecdsa_root():
    return _issue_root(_ECDSA_ROOT_NAME, _P521_PRIVATE_KEY)


_EE_NOT_BEFORE = datetime.now(timezone.utc)
_EE_NOT_AFTER = datetime.now(timezone.utc) + timedelta(weeks=52*3)

_EE_SUBJECT_NAME = x509.Name([
    x509.NameAttribute(x509.OID_COUNTRY_NAME, 'XX'),
    x509.NameAttribute(x509.OID_SURNAME, 'Yamada'),
    x509.NameAttribute(x509.OID_GIVEN_NAME, 'Hanako'),
])

def _issue_ee(subject_name, issuer_name, subject_key, issuer_key, kus, delta_cert: Optional[rfc5280.Certificate]=None):
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.issuer_name(issuer_name)
    builder = builder.subject_name(subject_name)
    builder = builder.not_valid_before(_EE_NOT_BEFORE)
    builder = builder.not_valid_after(_EE_NOT_AFTER)

    builder = builder.add_extension(x509.BasicConstraints(False, None), True)
    builder = builder.add_extension(x509.KeyUsage(*kus), True)

    return _issue_certificate(builder, subject_key, issuer_key, delta_cert)


def issue_dilithium_signing_ee(subject_key, issuer_key, delta_cert):
    return _issue_ee(_EE_SUBJECT_NAME, _DILITHIUM_ROOT_NAME, subject_key, issuer_key,
                     (True, False, False, False, False, False, False, False, False), delta_cert)


def issue_ecdsa_signing_ee():
    return _issue_ee(_EE_SUBJECT_NAME, _ECDSA_ROOT_NAME, _P256_PRIVATE_KEY, _P521_PRIVATE_KEY,
                     (True, False, False, False, False, False, False, False, False))


def issue_ecdsa_key_exchange_ee(delta_cert: rfc5280.Certificate):
    return _issue_ee(_EE_SUBJECT_NAME, _ECDSA_ROOT_NAME, _P384_PRIVATE_KEY, _P521_PRIVATE_KEY,
                     (False, False, False, False, True, False, False, False, False), delta_cert)


def print_cert(name, pyasn1_cert: rfc5280.Certificate):
    encoded = encode(pyasn1_cert)

    crypto_cert = x509.load_der_x509_certificate(encoded)

    print('*' * 10 + f' {name} ' + '*' * 10)
    print(crypto_cert.public_bytes(serialization.Encoding.PEM).decode())


dilithium_root_key = _generate_dilthium_key()
dilithium_ee_key = _generate_dilthium_key()

ecdsa_root = issue_ecdsa_root()
print_cert('ECDSA P-521 root', ecdsa_root)

dilithium_root = issue_dilthium_root(dilithium_root_key, ecdsa_root)
print_cert('Dilithium root', dilithium_root)

ecdsa_signing_ee = issue_ecdsa_signing_ee()
print_cert('ECDSA signing end-entity', ecdsa_signing_ee)

dilthium_signing_ee = issue_dilithium_signing_ee(dilithium_ee_key, dilithium_root_key, ecdsa_signing_ee)
print_cert('Dilithium signing end-entity', dilthium_signing_ee)

ecdsa_dual_use_ee = issue_ecdsa_key_exchange_ee(ecdsa_signing_ee)
print_cert('ECDSA dual use end-entity', ecdsa_dual_use_ee)

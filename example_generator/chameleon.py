from datetime import datetime
from typing import Optional, Union, Tuple, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ, namedtype, tag
from pyasn1_alt_modules import rfc5280


id_ce_prototype_chameleon_delta_descriptor = univ.ObjectIdentifier('2.16.840.1.114027.80.6.1')

class ChameleonDeltaDescriptor(univ.Sequence):
    pass


ChameleonDeltaDescriptor.componentType = namedtype.NamedTypes(
    namedtype.NamedType('serialNumber', rfc5280.CertificateSerialNumber()),
    namedtype.OptionalNamedType('signature', rfc5280.AlgorithmIdentifier().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )),
    namedtype.OptionalNamedType('issuer', rfc5280.Name().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
    )),
    namedtype.OptionalNamedType('validity', rfc5280.Validity().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )),
    namedtype.OptionalNamedType('subject', rfc5280.Name().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
    )),
    namedtype.NamedType('subjectPublicKeyInfo', rfc5280.SubjectPublicKeyInfo()),
    namedtype.OptionalNamedType('extensions', rfc5280.Extensions().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
    )),
    namedtype.NamedType('signatureValue', univ.BitString())
)


id_at_delta_certificate_request = univ.ObjectIdentifier('2.16.840.1.114027.80.6.2')


class ChameleonCertificateRequestDescriptor(univ.Sequence):
    pass


ChameleonCertificateRequestDescriptor.componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType('subject', rfc5280.Name().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )),
    namedtype.NamedType('subjectPKInfo', rfc5280.SubjectPublicKeyInfo()),
    namedtype.OptionalNamedType('extensions', rfc5280.Extensions().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
    )),
    namedtype.OptionalNamedType('signatureAlgorithm', rfc5280.AlgorithmIdentifier().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )),

)


id_at_delta_certificate_request_signature = univ.ObjectIdentifier('2.16.840.1.114027.80.6.3')


class ChameleonCertificateRequestSignature(univ.BitString):
    pass


def _get_extension_idx_by_oid(exts, oid):
    found_idx = None

    for i, ext in enumerate(exts):
        if ext['extnID'] == oid:
            found_idx = i

            break

    return found_idx


def _replace_extensions(dest_extensions, descriptor_extensions):
    for delta_ext in descriptor_extensions:
        ext_idx = _get_extension_idx_by_oid(dest_extensions, delta_ext['extnID'])

        if ext_idx is None:
            raise ValueError(f'Extension with OID "{delta_ext["extnID"]}" not found in certificate')

        dest_extensions[ext_idx]['critical'] = delta_ext['critical']
        dest_extensions[ext_idx]['extnValue'] = delta_ext['extnValue']


def _pop_extension(extn_oid, document):
    exts = document['tbsCertificate']['extensions']

    if exts is None:
        return None

    found_idx = _get_extension_idx_by_oid(exts, extn_oid)

    if found_idx is None:
        return None
    else:
        new_exts = list(exts)

        popped_ext = new_exts.pop(found_idx)

        document['tbsCertificate']['extensions'].clear()
        document['tbsCertificate']['extensions'].extend()

        return popped_ext


def get_delta_cert_from_base_cert(cert: rfc5280.Certificate):
    # make a copy
    cert_der = encode(cert)

    chameleon_cert, _ = decode(cert_der, asn1Spec=cert)

    delta_desc_ext = _pop_extension(id_ce_prototype_chameleon_delta_descriptor, chameleon_cert)

    delta_desc, _ = decode(delta_desc_ext['extnValue'], asn1Spec=ChameleonDeltaDescriptor())

    chameleon_cert['tbsCertificate']['serialNumber'] = delta_desc['serialNumber']

    if delta_desc['signature'].isValue:
        chameleon_cert['tbsCertificate']['signature']['algorithm'] = delta_desc['signature']['algorithm']
        chameleon_cert['tbsCertificate']['signature']['parameters'] = delta_desc['signature']['parameters']

        chameleon_cert['signatureAlgorithm']['algorithm'] = delta_desc['signature']['algorithm']
        chameleon_cert['signatureAlgorithm']['parameters'] = delta_desc['signature']['parameters']

    if delta_desc['issuer'].isValue:
        chameleon_cert['tbsCertificate']['issuer']['rdnSequence'] = delta_desc['issuer']['rdnSequence']

    if delta_desc['validity'].isValue:
        chameleon_cert['tbsCertificate']['validity']['notBefore'] = delta_desc['validity']['notBefore']
        chameleon_cert['tbsCertificate']['validity']['notAfter'] = delta_desc['validity']['notAfter']

    if delta_desc['subject'].isValue:
        chameleon_cert['tbsCertificate']['subject']['rdnSequence'] = delta_desc['subject']['rdnSequence']

    chameleon_cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm'] = delta_desc['subjectPublicKeyInfo']['algorithm']
    chameleon_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'] = delta_desc['subjectPublicKeyInfo']['subjectPublicKey']

    if delta_desc['extensions'].isValue:
        _replace_extensions(chameleon_cert['tbsCertificate']['extensions'], delta_desc['extensions'])

    chameleon_cert['signature'] = delta_desc['signatureValue']

    return chameleon_cert


def _get_extn_oids(exts):
    return {e['extnID'] for e in exts}


def _build_delta_cert_descriptor_extensions(base_cert_exts: rfc5280.Extensions, delta_cert_exts: rfc5280.Extensions
                                           ) -> Optional[Sequence[rfc5280.Extension]]:
    exts = []

    for ext in base_cert_exts:
        delta_ext_idx = _get_extension_idx_by_oid(delta_cert_exts, ext['extnID'])

        if delta_ext_idx is None:
            continue

        delta_ext = delta_cert_exts[delta_ext_idx]

        if encode(ext) == encode(delta_ext):
            continue
        else:
            exts.append(delta_ext)

    return exts if any(exts) else None


def build_delta_cert_descriptor_value(base_cert_tbs: rfc5280.TBSCertificate, delta_cert: rfc5280.Certificate):
    if any(_get_extn_oids(delta_cert['tbsCertificate']['extensions']).difference(
            _get_extn_oids(base_cert_tbs['extensions']))):
        raise ValueError('Delta certificate contains extension(s) that are not present in Base certificate')

    if encode(base_cert_tbs['validity']) != encode(delta_cert['tbsCertificate']['validity']):
        raise ValueError('Base certificate and Delta certificate have different validity periods')

    if encode(base_cert_tbs['signature']) == encode(delta_cert['tbsCertificate']['signature']):
        sig_alg = None
    else:
        sig_alg = delta_cert['tbsCertificate']['signature']

    if encode(base_cert_tbs['issuer']) == encode(delta_cert['tbsCertificate']['issuer']):
        issuer = None
    else:
        issuer = delta_cert['tbsCertificate']['issuer']

    if encode(base_cert_tbs['validity']) == encode(delta_cert['tbsCertificate']['validity']):
        validity = None
    else:
        validity = delta_cert['tbsCertificate']['validity']

    if encode(base_cert_tbs['subject']) == encode(delta_cert['tbsCertificate']['subject']):
        subject = None
    else:
        subject = delta_cert['tbsCertificate']['subject']

    if encode(base_cert_tbs['subjectPublicKeyInfo']) == encode(delta_cert['tbsCertificate']['subjectPublicKeyInfo']):
        raise ValueError('SPKI in Base and Delta certificate cannot be the same')
    else:
        spki = delta_cert['tbsCertificate']['subjectPublicKeyInfo']

    exts = _build_delta_cert_descriptor_extensions(base_cert_tbs['extensions'],
                                                  delta_cert['tbsCertificate']['extensions'])

    ext_value = ChameleonDeltaDescriptor()
    ext_value['serialNumber'] = delta_cert['tbsCertificate']['serialNumber']
    ext_value['signatureValue'] = delta_cert['signature']

    if sig_alg is not None:
        ext_value['signature']['algorithm'] = sig_alg['algorithm']
        ext_value['signature']['parameters'] = sig_alg['parameters']
    if issuer is not None:
        ext_value['issuer']['rdnSequence'] = issuer['rdnSequence']
    if validity is not None:
        ext_value['validity']['notBefore'] = validity['notBefore']
        ext_value['validity']['notAfter'] = validity['notAfter']
    if subject is not None:
        ext_value['subject']['rdnSequence'] = subject['rdnSequence']

    ext_value['subjectPublicKeyInfo']['algorithm'] = spki['algorithm']
    ext_value['subjectPublicKeyInfo']['subjectPublicKey'] = spki['subjectPublicKey']

    if exts is not None:
        ext_value['extensions'].extend(exts)

    return ext_value


class DeltaCertificateDescriptor(x509.ExtensionType):
    oid = x509.ObjectIdentifier('2.16.840.1.114027.80.6.1')

    def __init__(self, value: ChameleonDeltaDescriptor):
        if not value.isValue:
            raise ValueError('Value is an ASN.1 schema object')

        self._value = value

    def public_bytes(self) -> bytes:
        return encode(self._value)

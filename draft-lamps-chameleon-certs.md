---
title: "A Mechanism for Encoding Differences in Related Certificates"
category: info

docname: draft-lamps-chameleon-certs-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: Security
# workgroup: WG Working Group
keyword:
 - delta certificate
 - chameleon certificate
 - related certificate
venue:
#  group: "Limited Additional Mechanisms for PKIX and SMIME (lamps)"
#  type: "Working Group"
#  mail: "spasm@ietf.org"
#  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "CBonnell/chameleon-certs"
  latest: "https://CBonnell.github.io/chameleon-certs/draft-lamps-chameleon-certs.html"

author:
 -
    fullname: Corey Bonnell
    organization: DigiCert, Inc.
    email: corey.bonnell@digicert.com
 -
    fullname: John Gray
    organization: Entrust
    email: john.gray@entrust.com
 -
    fullname: David Hook
    organization: KeyFactor
    email: david.hook@keyfactor.com
 -
    fullname: Tomofumi Okubo
    organization: DigiCert, Inc.
    email: tomofumi.okubo@digicert.com
 -
    fullname: Mike Ounsworth
    organization: Entrust
    email: mike.ounsworth@entrust.com


normative:
 - RFC5280

informative:


--- abstract

This document specifies a method to efficiently convey the
differences between two certificates in an X.509 version 3 extension.
This method allows a
relying party to extract information sufficient to construct the related
certificate and perform certification path validation using the
constructed certificate. In particular, this method is especially
useful as part of a key or signature algorithm migration, where subjects
may be issued multiple certificates containing different public keys or
signed with different CA private keys or signature algorithms. This
method does not require any changes to the certification path
algorithm as described in {{!RFC5280}}. Additionally, this method
does not violate the constraints of serial number
uniqueness for certificates issued by a single certification
authority.

--- middle

# Introduction

In certain public key infrastructures, it is common to issue multiple
certificates to a single subject. In particular, as part of an algorithm migration, multiple certificates may be issued
to a single subject which convey different public keys of different
types or are signed with different signature algorithms. In cases where
relying party systems cannot be immediately updated to support new
algorithms, it is useful to issue certificates to subjects that convey
public keys whose algorithm is being phased out to maintain
interoperability. However, multiple certificates adds complexity to
certificate management and exposes limitations in applications and protocols that support
a single certificate chain. For this
reason, it is useful to efficiently convey information concerning
the elements of two certificates that are related within a single
certificate. This information can then be used to construct the related
certificate as needed by relying parties.

This document specifies an X.509 v3 certificate extension that includes
sufficient information for a relying party to construct a related
certificate. Additionally, this document specifies two
PKCS #10 Certification Signing Request attributes that can be used by
applicants to request two related certificates using a single PKCS #10
Certification Signing Request.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Terminology

For conciseness, this document defines several terms used throughout.

Base Certificate: A X.509 v3 certificate which contains a delta
certificate descriptor extension.

DCD: An acronym meaning "delta certificate descriptor", which is a
reference to the X.509 v3 certificate extension defined in this document.

Delta Certificate: A X.509 v3 certificate which can be reconstructed
by incorporating the fields and extensions contained in a Base
Certificate.

# Delta certificate descriptor extension content and semantics

The delta certificate descriptor ("DCD") extension is used to reconstruct the
Delta Certificate by incorporating both the fields and extensions
present in the Base Certificate as well as
the information contained within the extension itself.

The subject and issuer distinguished names of the Base Certificate
and the Delta Certificate MUST be identical.

The extension is identified with the following object identifier:

```
id-ce-delta-certificate-descriptor ::= OBJECT IDENTIFIER {
   joint-iso-itu-t(2) country(16) us(840) organization(1)
   entrust(114027) 80 6 1
}
```

The ASN.1 syntax of the extension is as follows:

```
DeltaCertificateDescriptor ::= SEQUENCE {
  serialNumber          CertificateSerialNumber,
  signature             [0] IMPLICIT AlgorithmIdentifier OPTIONAL,
  issuer                [1] IMPLICIT Name OPTIONAL,
  subjectPublicKeyInfo  [2] IMPLICIT SubjectPublicKeyInfo OPTIONAL,
  extensions            [3] IMPLICIT Extensions OPTIONAL,
  signatureValue        BIT STRING }
```

The serialNumber field MUST be present and contain the
serial number of the Delta Certificate. 

If present, the signature field specifies the signature algorithm used
by the issuing certification authority to sign the Delta Certificate.
If the signature field is absent, then the value of the signature field of the
Base Certificate and Delta Certificate is equal.

If present, the issuer field specifies the distinguished name of the
issuing certification authority to sign the Delta Certificate. If the
issuer field is absent, then the distinguished name of the issuing
certification authority for both the Base Certificate and Delta
Certificate is the same.

If present, the subjectPublicKeyInfo field contains the public key included in
the Delta Certificate. If this field is absent, then the public key
included in the Base Certificate and Delta Certificate is equal.

If present, the extensions field the extensions whose
criticality and/or value are different in the Delta Certificate compared
to the Base Certificate. If the extensions field is
absent, then all extensions in the Delta Certificate have the same
criticality and value as the Base Certificate. This field MUST NOT
contain any extensions which do
not appear in the Base Certificate. Additionally, the Base Certificate
SHALL NOT include any extensions which are not included in the Delta
Certificate, with the exception of the DCD
extension itself.
Therefore, it is not possible to add or remove extensions using the
DCD extension.

The signatureValue field contains the value of the signatureValue field
of the Delta Certificate. It MUST be present.

At least one of signature, issuer, subjectPublicKeyInfo, or extensions
MUST be present in the extension value.

## Issuing a Base Certificate

The signature of the Delta Certificate must be known so that its
value can be included in the signatureValue field of the delta
certificate descriptor extension. Given this, the Base Certificate will
necessarily need to be issued after the Delta Certificate is issued.

After the Delta Certificate is issued, the certification authority
compares the signature, issuer, subjectPublicKeyInfo, and extensions fields
of the Delta Certificate and the to-be-signed certificate which
will contain the DCD extension. The
certification authority then populates the delta certificate
descriptor extension with the values of the fields which differ from
the Delta Certificate. The ordering of extensions in the DCD extension's
"extensions" field MUST be the same as the ordering of those extensions
in the Base Certificate. Maintaining this relative ordering ensures that
the Delta Certificate's extensions can be constructed with a single pass.

The certification authority then adds the computed 
DCD extension to the to-be-signed Base Certificate and signs the
Base Certificate.

## Reconstructing a Delta Certificate from a Base Certificate

The following procedure describes how to reconstruct a Delta Certificate
from a Base Certificate:

1. Remove the DCD extension from the Base Certificate.
2. Replace the value of the serialNumber field of the Base Certificate
   with the value of the DCD extension's serialNumber field.
3. If the DCD extension contains a value for the signature field, then
   replace the value of the signature field of the Base Certificate with
   the value of the DCD extension's signature field.
4. If the DCD extensions contains a value for the issuer field, then
   replace the value of the issuer field of the Base Certificate with
   the value of the DCD extension's issuer field.
5. If the DCD extension contains a value for the subjectPublicKeyInfo
   field, then replace the value of the subjectPublicKeyInfo field of
   the Base Certificate with the value of the DCD extension's
   subjectPublicKeyInfo field.
6. If the DCD extension contains a value for the extensions field, then
   iterate over the DCD extension's "extensions" field, replacing the
   criticality and/or extension value of each identified extension in
   the Base Certificate.
7. Replace the value of the signatureValue field of the Base Certificate
   with the value of the DCD extension's signatureValue field.
   
# Delta certificate request content and semantics

Using the two attributes that are defined below, it is possible to
create Certification Signing Requests for both Base and Delta
Certificates within a single PKCS #10 Certificate Signing Request.

The delta certificate request attribute is used to convey the requested
differences between the request for issuance of the Base Certificate
and the requested Delta Certificate.

The attribute is identified with the following object identifier:

```
id-at-delta-certificate-request ::= OBJECT IDENTIFIER {
   joint-iso-itu-t(2) country(16) us(840) organization(1)
   entrust(114027) 80 6 2
}
```

The ASN.1 syntax of the attribute is as follows:

```
DeltaCertificateRequest ::= SEQUENCE {
  subjectPublicKeyInfo  [0] IMPLICIT SubjectPublicKeyInfo OPTIONAL,
  extensions            [1] IMPLICIT Extensions OPTIONAL,
  signatureAlgorithm    [2] IMPLICIT AlgorithmIdentifier OPTIONAL,
}

deltaCertificateRequest ATTRIBUTE ::= {
   WITH SYNTAX DeltaCertificateRequest
   SINGLE VALUE TRUE
   ID id-at-delta-certificate-request
}
```

The delta certificate request signature attribute is used to convey
the signature that is calculated over the CertificationRequestInfo
using the signature algorithm and key that is specified in the delta
certificate request attribute. The following section describes in detail
how to calculate the value of this attribute.

This attribute is identified with the following object identifier:

```
id-at-delta-certificate-request-signature ::= OBJECT IDENTIFIER {
   joint-iso-itu-t(2) country(16) us(840) organization(1)
   entrust(114027) 80 6 3
}
```

The ASN.1 syntax of the attribute is as follows:

```
DeltaCertificateRequestSignature ::= BIT STRING

deltaCertificateRequestSignature ATTRIBUTE ::= {
   WITH SYNTAX DeltaCertificateRequestSignature
   SINGLE VALUE TRUE
   ID id-at-delta-certificate-request-signature
}
```

## Creating a combined certification signing request

The following procedure is used by certificate requestors to create a
combined certification signing request for both a Base Certificate and
a Delta Certificate.

1. The certificate requestor creates a CertificationRequestInfo
   containing the subject, subjectPKInfo, and attributes for
   the Base Certificate.
2. The certificate requestor creates a delta certificate request
   attribute that specifies the requested differences between the
   to-be-issued Base Certificate and Delta Certificate requests.
3. The certificate requestor adds the delta certificate request
   attribute that was created by step 3 to the list of attributes in
   the CertificationRequestInfo.
4. The certificate requestor signs the CertificationRequestInfo. If
   the value of the subjectPublicKeyInfo field in the delta certificate
   request attribute is present, then the corresponding private key is
   used for signing. If value is absent, then the private key
   corresponding to the public key in the CertificationRequestInfo's
   subjectPKInfo field is used for signing.
   If the value of the signatureAlgorithm field in the delta certificate
   request attribute is present, then the specified signature algorithm
   is used for signing. If the value is absent, then the signature
   algorithm that will be used for signing the CertificationRequest in
   step 7 is used for signing.
5. The certificate requestor creates a delta certificate request
   signature attribute that contains the signature value calculated by
   step 4.
6. The certificate requestor adds the delta certificate request
   signature attribute that was created by step 5 to the list of
   attributes.
7. The certificate requestor signs the CertificationRequestInfo using
   private key that corresponds to the public key contained in the
   subjectPKInfo field.

# Security Considerations


TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

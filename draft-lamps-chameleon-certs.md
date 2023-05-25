---
title: "A Mechanism for Encoding Differences in Paired Certificates"
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
 - paired certificate
venue:
#  group: "Limited Additional Mechanisms for PKIX and SMIME (lamps)"
#  type: "Working Group"
#  mail: "spasm@ietf.org"
#  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "CBonnell/chameleon-certs"
  latest: "https://CBonnell.github.io/chameleon-certs/draft-lamps-chameleon-certs.html"

author:
 -
    fullname: C. Bonnell
    organization: DigiCert
    email: corey.bonnell@digicert.com
 -
    fullname: J. Gray
    organization: Entrust
    email: john.gray@entrust.com
 -
    fullname: D. Hook
    organization: KeyFactor
    email: david.hook@keyfactor.com
 -
    fullname: T. Okubo
    organization: DigiCert
    email: tomofumi.okubo@digicert.com
 -
    fullname: M. Ounsworth
    organization: Entrust
    email: mike.ounsworth@entrust.com


normative:
  X.680:
      title: "Information technology - Abstract Syntax Notation One (ASN.1): Specification of basic notation"
      date: November 2015
      author:
        org: ITU-T
      seriesinfo:
        ISO/IEC: 8824-1:2015

informative:


--- abstract

This document specifies a method to efficiently convey the
differences between two certificates in an X.509 version 3 extension.
This method allows a
relying party to extract information sufficient to construct the paired
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
certificates to a single subject. In particular, as part of an algorithm
migration, multiple certificates may be issued to a single subject which
convey public keys of different types or are signed with different
signature algorithms. In cases where relying party systems cannot be
immediately updated to support new algorithms, it is useful to issue
certificates to subjects that convey public keys whose algorithm is
being phased out to maintain interoperability. However, multiple
certificates adds complexity to certificate management and exposes
limitations in applications and protocols that support a single
certificate chain. For this reason, it is useful to efficiently convey
information concerning the elements of two certificates within a single
certificate. This information can then be used to construct the paired
certificate as needed by relying parties.

This document specifies an X.509 v3 certificate extension that includes
sufficient information for a relying party to construct both paired
certificates with a single certificate. Additionally, this document
specifies two PKCS #10 Certification Signing Request attributes that can
be used by applicants to request Paired Certificates using a single
PKCS #10 Certification Signing Request.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Definitions

For conciseness, this document defines several terms that are
frequently used throughout.

Base Certificate: A X.509 v3 certificate which contains a delta
certificate descriptor extension.

DCD: An acronym meaning "Delta Certificate descriptor", which is a
reference to the X.509 v3 certificate extension defined in this
document.

Delta Certificate: A X.509 v3 certificate which can be reconstructed
by incorporating the fields and extensions contained in a Base
Certificate.

Paired Certificates: A Base Certificate and the corresponding Delta
Certificate whose information is encoded in the Base Certificate's
DCD extension.

# Relationship between Base Certificates and Delta Certificates

In some public key infrastructures, it may be common to issue multiple
certificates to the same subject. These certificates generally contain
the same (or substantially similar) identity information and generally
have identical validity periods. The differences in certificate content
generally stem from the certification of different keys, where the named
subject may have multiple keys of different algorithms certified by
separate certificates. The use of different keys allows for the subject
to use the key that is most appropriate for a given operation and
intended recipient. For example, as part of an ongoing algorithm
migration, it is useful to use stronger algorithms when both of the
systems utilized by the subscriber/sender and recipient have been
upgraded. However, in the case where systems have not yet been updated,
the use of a legacy key algorithm may be required. Additionally,
multiple certificates may be issued to the same subject that certify
keys for different purposes, such as one key for signing and another
key for encryption.

The management of multiple certificates may be complex, and there
may be limitations in protocols regarding the handling of multiple
certificate chains. To account for these concerns, this document
proposes a method to efficiently encode the differences between two
certificates with sufficient information such that a relying
party can derive the complete certificate from another. For the
purposes of this document, the "Base Certificate" contains its own
fields and extensions and additionally includes an extension that
conveys all differences contained within the paired certificate. The
certificate whose elements which differ from the Base Certificate and
are captured in the Delta Certificate descriptor extension of the Base
Certificate is known as the "Delta Certificate".

Delta Certificates are reconstructed from the Base Certificate either on
the sender's side or the recipient's side depending on the protocol and
application(s) in use. The sender may elect to send the Base Certificate
or the Delta Certificate based on information that it has about what the
recipient can process. Similarly, the client may send either the Base
Certificate or the Delta Certificate based on what the server can
process. This assures backwards compatibility as the certificate sent
to the peer (server or client) is chosen based on what it can process.
The negotiation on which certificate to use is out-of-scope of
this document and is deferred to each protocol and application.

In the absence of information concerning the capabilities of the peer,
it is unknown whether it understands the DCD extension in the Base
Certificate. When the recipient does not understand the DCD extension,
it only processes the information within the Base Certificate and
ignores the information found in a non-critical DCD extension. If the
recipient receives a Base Certificate and is capable of processing the
DCD extension, then it may reconstruct the Delta Certificate to be used
for processing.

In a protocol, the sender may perform a cryptographic operation with
the key conveyed within the Base Certificate. If it understands the DCD
extension, then it may reconstruct the Delta Certificate and choose to
perform the same operation with the key conveyed within the DCD
extension. This behavior is deferred to the software in use.

# Delta certificate descriptor extension

The Delta Certificate descriptor ("DCD") extension is used to
reconstruct the Delta Certificate by incorporating both the fields and
extensions present in the Base Certificate as well as the information
contained within the extension itself.

Certification authorities SHOULD NOT mark this extension as critical so
that applications that do not understand the extension will still be
able to process the Base Certificate.

## Delta certificate descriptor content {#dcd-extension-content}

The DCD extension is identified with the following object identifier:

(TODO: replace this temporary OID)

~~~
id-ce-deltaCertificateDescriptor OBJECT IDENTIFIER ::= {
   joint-iso-itu-t(2) country(16) us(840) organization(1)
   entrust(114027) 80 6 1
}
~~~

The ASN.1 syntax of the extension is as follows:

~~~
DeltaCertificateDescriptor ::= SEQUENCE {
  serialNumber          CertificateSerialNumber,
  signature             [0] IMPLICIT AlgorithmIdentifier {SIGNATURE_ALGORITHM, {...}} OPTIONAL,
  issuer                [1] IMPLICIT Name OPTIONAL,
  validity              [2] IMPLICIT Validity OPTIONAL,
  subject               [3] IMPLICIT Name OPTIONAL,
  subjectPublicKeyInfo  SubjectPublicKeyInfo,
  extensions            [4] IMPLICIT Extensions{CertExtensions} OPTIONAL,
  signatureValue        BIT STRING
}
~~~

The serialNumber field MUST be present and contain the
serial number of the Delta Certificate.

If present, the signature field specifies the signature algorithm used
by the issuing certification authority to sign the Delta Certificate.
If the signature field is absent, then the value of the signature field
of the Base Certificate and Delta Certificate is equal.

If present, the issuer field specifies the distinguished name of the
issuing certification authority which signed the Delta Certificate. If
the issuer field is absent, then the distinguished name of the issuing
certification authority for both the Base Certificate and Delta
Certificate is the same.

If present, the validity field specifies the validity period of the
Delta Certificate. If the validity field is absent, then the validity
period of both the Base Certificate and Delta Certificate is the same.

If present, the subject field specifies the distinguished name of the
named subject as encoded in the Delta Certificate. If the
subject field is absent, then the distinguished name of the named
subject for both the Base Certificate and Delta Certificate is the same.

The subjectPublicKeyInfo field contains the public key
included in the Delta Certificate. The value of this field MUST differ
from the value of the subjectPublicKeyInfo field of the Base
Certificate. In other words, the Base Certificate and Delta Certificate
MUST certify different keys.

If present, the extensions field contains the extensions whose
criticality and/or value are different in the Delta Certificate compared
to the Base Certificate. If the extensions field is absent, then all
extensions in the Delta Certificate MUST have the same
criticality and value as the Base Certificate. This field MUST NOT
contain any extension types which do not appear in the Base Certificate.
Additionally, the Base Certificate SHALL NOT include any extensions
which are not included in the Delta Certificate, with the exception of
the DCD extension itself. Therefore, it is not possible to add or remove
extensions using the DCD extension. The ordering of extensions in this
field MUST be relative to the ordering of the extensions as they are
encoded in the Delta Certificate. Maintaining this relative
ordering ensures that the Delta Certificate's extensions can be
constructed with a single pass.

The signatureValue field contains the value of the signature field
of the Delta Certificate. It MUST be present.

## Issuing a Base Certificate

The signature of the Delta Certificate must be known so that its
value can be included in the signatureValue field of the delta
certificate descriptor extension. Given this, Delta Certificate will
necessarily need to be issued prior to the issuance of the Base
Certificate.

After the Delta Certificate is issued, the certification authority
compares the signature, issuer, validity, subject, subjectPublicKeyInfo,
and extensions fields of the Delta Certificate and the to-be-signed
certificate which will contain the DCD extension. The certification
authority then populates the DCD extension with the values of the fields
which differ from the Base Certificate. The CA MUST encode extensions
in the Base Certificate in the same order used for the Delta
Certificate, with the exception of the DCD extension itself.

The certification authority then adds the computed DCD extension to the
to-be-signed Base Certificate and signs the Base Certificate.

## Reconstructing a Delta Certificate from a Base Certificate

The following procedure describes how to reconstruct a Delta Certificate
from a Base Certificate:

1. Create an initial Delta Certificate template by copying the Base
   Certificate excluding the DCD extension.
2. Replace the value of the serialNumber field of the Delta Certificate
   template with the value of the DCD extension's serialNumber field.
3. If the DCD extension contains a value for the signature field, then
   replace the value of the signature field of the Delta Certificate
   template with the value of the DCD extension's signature field.
4. If the DCD extension contains a value for the issuer field, then
   replace the value of the issuer field of the Delta Certificate
   template with the value of the DCD extension's issuer field.
5. If the DCD extension contains a value for the validity field, then
   replace the value of the validity field of the Delta Certificate
   template with the value of the DCD extension's validity field.
6. Replace the value of the subjectPublicKeyInfo field of the Delta
   Certificate template with the value of the DCD extension's
   subjectPublicKeyInfo field.
7. If the DCD extension contains a value for the subject field, then
   replace the value of the subject field of the Delta Certificate
   template with the value of the DCD extension's subject field.
8. If the DCD extension contains a value for the extensions field, then
   iterate over the DCD extension's "extensions" field, replacing the
   criticality and/or extension value of each identified extension in
   the Delta Certificate template. If any extension is present in the
   field that does not appear in the Delta Certificate template, then
   this reconstruction process MUST fail.
9. Replace the value of the signature field of the Delta Certificate
   template with the value of the DCD extension's signatureValue field.

# Delta certificate request content and semantics {#dcr-attribute}

Using the two attributes that are defined below, it is possible to
create Certification Signing Requests for both Base and Delta
Certificates within a single PKCS #10 Certificate Signing Request.

The delta certificate request attribute is used to convey the requested
differences between the request for issuance of the Base Certificate
and the requested Delta Certificate.

The attribute is identified with the following object identifier:

(TODO: replace this temporary OID)

~~~
id-at-deltaCertificateRequest OBJECT IDENTIFIER ::= {
   joint-iso-itu-t(2) country(16) us(840) organization(1)
   entrust(114027) 80 6 2
}
~~~

The ASN.1 syntax of the attribute is as follows:

~~~
DeltaCertificateRequestValue ::= SEQUENCE {
  subject               [0] IMPLICIT Name OPTIONAL,
  subjectPKInfo         SubjectPublicKeyInfo,
  extensions            [1] IMPLICIT Extensions{CertExtensions} OPTIONAL,
  signatureAlgorithm    [2] IMPLICIT AlgorithmIdentifier {SIGNATURE_ALGORITHM, {...}} OPTIONAL
}

DeltaCertificateRequest ::= ATTRIBUTE {
   WITH SYNTAX DeltaCertificateRequestValue
   SINGLE VALUE TRUE
   ID id-at-deltaCertificateRequest
}
~~~

The delta certificate request signature attribute is used to convey
the signature that is calculated over the CertificationRequestInfo
using the signature algorithm and key that is specified in the delta
certificate request attribute. {{dcd-csr-create}} describes in detail
how to determine the value of this attribute.

This attribute is identified with the following object identifier:

(TODO: replace this temporary OID)

~~~
id-at-deltaCertificateRequestSignature OBJECT IDENTIFIER ::= {
   joint-iso-itu-t(2) country(16) us(840) organization(1)
   entrust(114027) 80 6 3
}
~~~

The ASN.1 syntax of the attribute is as follows:

~~~
DeltaCertificateRequestSignatureValue ::= BIT STRING

deltaCertificateRequestSignature ATTRIBUTE ::= {
   WITH SYNTAX DeltaCertificateRequestSignatureValue
   SINGLE VALUE TRUE
   ID id-at-deltaCertificateRequestSignature
}
~~~

## Creating a certification signing request for Paired Certificates {#dcd-csr-create}

The following procedure is used by certificate requestors to create a
combined certification signing request for Paired Certificates.

1. The certificate requestor creates a CertificationRequestInfo
   containing the subject, subjectPKInfo, and attributes for
   the Base Certificate.
2. The certificate requestor creates a delta certificate request
   attribute that specifies the requested differences between the
   to-be-issued Base Certificate and Delta Certificate requests.
3. The certificate requestor adds the delta certificate request
   attribute that was created by step 2 to the list of attributes in
   the CertificationRequestInfo.
4. The certificate requestor signs the CertificationRequestInfo using
   the private key of the Delta certificate request subject.
5. The certificate requestor creates a delta certificate request
   signature attribute that contains the signature value calculated by
   step 4.
6. The certificate requestor adds the delta certificate request
   signature attribute that was created by step 5 to the list of
   attributes.
7. The certificate requestor signs the CertificationRequestInfo using
   the private key of the Base certificate request subject.

# Security Considerations

The validation of Base Certificates and Delta Certificates follows the
certification path validation algorithm defined in {{!RFC5280}}.
However, there are some additional considerations for the software to
handle the Base Certificate and Delta Certificate. The Base Certificate
and Delta Certificate may have different security properties such as
different signing algorithms, different key types or the same key types
with different key sizes or signing algorithms. The preference on which
certificate to be used or using both when available is deferred to the
server or client software.

The software is expected to make choices depending on the certificate's
security properties or a policy set for the particular PKI. One example
of handling two certificates is "fallback" where if the validation of
the first certificate fails, it attempts to validate the second
certificate. Another example to handle two certificate is "upgrade",
where the validation of the first certificate succeeds but still
attempts the validation of the second certificate. While this document
provides a vehicle to convey information of two certificates in one,
it does not address the rules that are expected to be set by the policy
of a PKI on how to issue Paired Certificates and how to handle them.

The algorithms that are used for the Base Certificate and Delta
Certificate respectively should be carefully set by the policy of each
PKI reflecting the best current practices in usage of cryptography. The
behavior of the server or client software is expected to be well-defined
in accordance with the policy in order to avoid downgrade attacks or
substitution attacks.

# IANA Considerations

For the Delta Certificate descriptor extension as defined in
{{dcd-extension-content}}, IANA is requested to assign an object
identifier (OID) for the certificate extension. The OID for the
certificate extension should be allocated in the
"SMI Security for PKIX Certificate Extension" registry
(1.3.6.1.5.5.7.1).

For the Delta Certificate Request and Delta Certificate Request
Signature attributes as defined in {{dcr-attribute}}, IANA
is requested to create a new registry under SMI Security Codes and
assign two object identifiers (OID).

For the ASN.1 Module for the extension and attributes defined in
{{asn1-module}}, IANA is requested to assign an object identifier (OID).
The OID for the module should be allocated in the
"SMI Security for PKIX Module Identifier" registry (1.3.6.1.5.5.7.0).

--- back

# ASN.1 Module {#asn1-module}

The following ASN.1 {{X.680}} module provides the complete definition of the extensions, attributes, and
associated identifiers specified in this document.

~~~

DeltaCertificateDescriptor { iso(1) identified-organization(3) dod(6) internet(1)
  security(5) mechanisms(5) pkix(7) id-mod(0)
  id-mod-deltaCertificateDescriptor(TBD) }

DEFINITIONS EXPLICIT TAGS ::=

BEGIN

EXPORTS ALL;

IMPORTS
  AlgorithmIdentifier{}, SIGNATURE-ALGORITHM
  FROM AlgorithmInformation-2009  -- RFC 5912
  { iso(1) identified-organization(3) dod(6) internet(1) security(5)
    mechanisms(5) pkix(7) id-mod(0)
    id-mod-algorithmInformation-02(58) }

  EXTENSION, ATTRIBUTE, Extensions{}
  FROM PKIX-CommonTypes-2009  -- RFC 5912
  { iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-mod(0)
    id-mod-pkixCommon-02(57) }

  CertificateSerialNumber, Name, Validity, SubjectPublicKeyInfo, CertExtensions
  FROM PKIX1Explicit-2009  -- RFC 5912
  { iso(1) identified-organization(3) dod(6) internet(1) security(5)
    mechanisms(5) pkix(7) id-mod(0) id-mod-pkix1-explicit-02(51) };

-- Temporary OID arc --

id-temporaryArc OBJECT IDENTIFIER ::= {
  joint-iso-itu-t(2) country(16) us(840) organization(1)
  entrust(114027) 80 6
}

-- Extension --

id-ce-deltaCertificateDescriptor OBJECT IDENTIFIER ::= { id-temporaryArc 1 }

DeltaCertificateDescriptor ::= SEQUENCE {
  serialNumber          CertificateSerialNumber,
  signature             [0] IMPLICIT AlgorithmIdentifier {SIGNATURE_ALGORITHM, {...}} OPTIONAL,
  issuer                [1] IMPLICIT Name OPTIONAL,
  validity              [2] IMPLICIT Validity OPTIONAL,
  subject               [3] IMPLICIT Name OPTIONAL,
  subjectPublicKeyInfo  SubjectPublicKeyInfo,
  extensions            [4] IMPLICIT Extensions{CertExtensions} OPTIONAL,
  signatureValue        BIT STRING
}

ext-deltaCertificateDescriptor EXTENSION ::= {
  SYNTAX DeltaCertificateDescriptor
  IDENTIFIED BY id-ce-deltaCertificateDescriptor
  CRITICALITY { FALSE }
}

-- Request Attributes --

id-at-deltaCertificateRequest OBJECT IDENTIFIER ::= { id-temporaryArc 2 }

DeltaCertificateRequestValue ::= SEQUENCE {
  subject               [0] IMPLICIT Name OPTIONAL,
  subjectPKInfo         SubjectPublicKeyInfo,
  extensions            [1] IMPLICIT Extensions{CertExtensions} OPTIONAL,
  signatureAlgorithm    [2] IMPLICIT AlgorithmIdentifier {SIGNATURE_ALGORITHM, {...}} OPTIONAL
}

DeltaCertificateRequest ::= ATTRIBUTE {
   WITH SYNTAX DeltaCertificateRequestValue
   SINGLE VALUE TRUE
   ID id-at-deltaCertificateRequest
}

id-at-deltaCertificateRequestSignature OBJECT IDENTIFIER ::= { id-temporaryArc 3 }

DeltaCertificateRequestSignatureValue ::= BIT STRING

DeltaCertificateRequestSignature ::= ATTRIBUTE {
   WITH SYNTAX DeltaCertificateRequestSignatureValue
   SINGLE VALUE TRUE
   ID id-at-deltaCertificateRequestSignature
}

END

~~~

# Examples

This appendix includes some example certificates which demonstrate the use of the mechanism specified in this document.

## ECDSA P-521 root

This is the ECDSA root certificate.

```
  0 773: SEQUENCE {
  4 614:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13  20:     INTEGER 61 9B 9D 7E D8 62 16 3E 33 4D EA 15 D2 63 83 68 50 91 4C 63
 35  10:     SEQUENCE {
 37   8:       OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :       }
 47 139:     SEQUENCE {
 50  11:       SET {
 52   9:         SEQUENCE {
 54   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 59   2:           PrintableString 'XX'
       :           }
       :         }
 63  53:       SET {
 65  51:         SEQUENCE {
 67   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
 72  44:           UTF8String
       :             'Royal Institute of Public Key Infrastructure'
       :           }
       :         }
118  43:       SET {
120  41:         SEQUENCE {
122   3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
127  34:           UTF8String 'Post-Heffalump Research Department'
       :           }
       :         }
163  24:       SET {
165  22:         SEQUENCE {
167   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
172  15:           UTF8String 'ECDSA Root - G1'
       :           }
       :         }
       :       }
189  30:     SEQUENCE {
191  13:       UTCTime 25/05/2023 20:35:19 GMT
206  13:       UTCTime 12/05/2033 20:35:19 GMT
       :       }
221 139:     SEQUENCE {
224  11:       SET {
226   9:         SEQUENCE {
228   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
233   2:           PrintableString 'XX'
       :           }
       :         }
237  53:       SET {
239  51:         SEQUENCE {
241   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
246  44:           UTF8String
       :             'Royal Institute of Public Key Infrastructure'
       :           }
       :         }
292  43:       SET {
294  41:         SEQUENCE {
296   3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
301  34:           UTF8String 'Post-Heffalump Research Department'
       :           }
       :         }
337  24:       SET {
339  22:         SEQUENCE {
341   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
346  15:           UTF8String 'ECDSA Root - G1'
       :           }
       :         }
       :       }
363 155:     SEQUENCE {
366  16:       SEQUENCE {
368   7:         OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
377   5:         OBJECT IDENTIFIER secp521r1 (1 3 132 0 35)
       :         }
384 134:       BIT STRING
       :         04 01 D0 FD 72 57 A8 4C 74 7F 56 25 75 C0 73 85
       :         DB EB F2 F5 2B EA 58 08 3D B8 2F DD 15 31 D8 AA
       :         E3 CC 87 5F F0 2F F7 FA 2D A2 60 D8 EB 62 D6 D2
       :         F5 D6 49 27 8E 32 17 36 A0 62 8C BB B3 03 08 B6
       :         E6 18 DB 00 F6 2A D2 04 C6 46 03 59 BC 81 8A B8
       :         96 1B F0 F0 FC 0E C5 AA E8 A4 28 17 3C E5 6F 00
       :         DE 9B 15 7C 1E 5C 82 C6 4F 56 2F CA DE FC 4A 4C
       :         28 F6 D3 42 CF 3E F6 16 FC 82 D3 3B 72 85 C9 21
       :         F2 BF 36 FD D8
       :       }
521  99:     [3] {
523  97:       SEQUENCE {
525  15:         SEQUENCE {
527   3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
532   1:           BOOLEAN TRUE
535   5:           OCTET STRING, encapsulates {
537   3:             SEQUENCE {
539   1:               BOOLEAN TRUE
       :               }
       :             }
       :           }
542  14:         SEQUENCE {
544   3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
549   1:           BOOLEAN TRUE
552   4:           OCTET STRING, encapsulates {
554   2:             BIT STRING 1 unused bit
       :               '1100000'B
       :             }
       :           }
558  29:         SEQUENCE {
560   3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
565  22:           OCTET STRING, encapsulates {
567  20:             OCTET STRING
       :               8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
       :               17 7D 9F BE
       :             }
       :           }
589  31:         SEQUENCE {
591   3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
596  24:           OCTET STRING, encapsulates {
598  22:             SEQUENCE {
600  20:               [0]
       :                 8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
       :                 17 7D 9F BE
       :               }
       :             }
       :           }
       :         }
       :       }
       :     }
622  10:   SEQUENCE {
624   8:     OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :     }
634 140:   BIT STRING, encapsulates {
638 136:     SEQUENCE {
641  66:       INTEGER
       :         01 74 D5 A3 F9 4B CC F0 BC 1C 03 81 EA 81 02 40
       :         68 E2 BF C0 FF 57 78 4A 66 F0 57 20 DF 2A 43 AA
       :         10 9D 42 E9 7E C4 FA 9F 1F 8F 40 3D E3 D6 2A D3
       :         4C E9 04 D9 70 BE 44 FC 0C 9D B7 68 98 05 D4 B9
       :         6B 8B
709  66:       INTEGER
       :         01 F8 79 09 8C FC 4E E8 72 89 10 D1 75 08 07 79
       :         8D 5D EA BA C1 F4 83 E7 78 DD E6 9E 34 50 B9 CF
       :         A8 54 75 B0 27 C0 D1 81 23 B9 A2 3C 47 C2 0A ED
       :         5C 70 4D 8A 5D 01 D7 F9 04 9D 98 B0 72 18 79 A0
       :         A9 52
       :       }
       :     }
       :   }

-----BEGIN CERTIFICATE-----
MIIDBTCCAmagAwIBAgIUYZudfthiFj4zTeoV0mODaFCRTGMwCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDUyNTIwMzUxOVoXDTMzMDUxMjIwMzUxOVowgYsxCzAJBgNVBAYTAlhYMTUw
MwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVj
dHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVu
dDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMIGbMBAGByqGSM49AgEGBSuBBAAj
A4GGAAQB0P1yV6hMdH9WJXXAc4Xb6/L1K+pYCD24L90VMdiq48yHX/Av9/otomDY
62LW0vXWSSeOMhc2oGKMu7MDCLbmGNsA9irSBMZGA1m8gYq4lhvw8PwOxaropCgX
POVvAN6bFXweXILGT1Yvyt78Skwo9tNCzz72FvyC0ztyhckh8r82/dijYzBhMA8G
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSOwhQJYHbq
kDjpOa4bbVLEF32fvjAfBgNVHSMEGDAWgBSOwhQJYHbqkDjpOa4bbVLEF32fvjAK
BggqhkjOPQQDBAOBjAAwgYgCQgF01aP5S8zwvBwDgeqBAkBo4r/A/1d4SmbwVyDf
KkOqEJ1C6X7E+p8fj0A949Yq00zpBNlwvkT8DJ23aJgF1LlriwJCAfh5CYz8Tuhy
iRDRdQgHeY1d6rrB9IPneN3mnjRQuc+oVHWwJ8DRgSO5ojxHwgrtXHBNil0B1/kE
nZiwchh5oKlS
-----END CERTIFICATE-----

```

## Dilithium root

This is the Dilithium root certificate. It contains a Delta Certificate Descriptor extension which includes sufficient information to recreate the ECDSA P-521 root

```
   0 6479: SEQUENCE {
   4 3162:   SEQUENCE {
   8    3:     [0] {
  10    1:       INTEGER 2
         :       }
  13   20:     INTEGER 2A 3A 37 2C 0B 01 9B 50 C1 BE C2 C1 40 70 B8 75 EB 1F 45 7A
  35   13:     SEQUENCE {
  37   11:       OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :       }
  50  143:     SEQUENCE {
  53   11:       SET {
  55    9:         SEQUENCE {
  57    3:           OBJECT IDENTIFIER countryName (2 5 4 6)
  62    2:           PrintableString 'XX'
         :           }
         :         }
  66   53:       SET {
  68   51:         SEQUENCE {
  70    3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
  75   44:           UTF8String
         :             'Royal Institute of Public Key Infrastructure'
         :           }
         :         }
 121   43:       SET {
 123   41:         SEQUENCE {
 125    3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
 130   34:           UTF8String 'Post-Heffalump Research Department'
         :           }
         :         }
 166   28:       SET {
 168   26:         SEQUENCE {
 170    3:           OBJECT IDENTIFIER commonName (2 5 4 3)
 175   19:           UTF8String 'Dilithium Root - G1'
         :           }
         :         }
         :       }
 196   30:     SEQUENCE {
 198   13:       UTCTime 25/05/2023 20:35:19 GMT
 213   13:       UTCTime 12/05/2033 20:35:19 GMT
         :       }
 228  143:     SEQUENCE {
 231   11:       SET {
 233    9:         SEQUENCE {
 235    3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 240    2:           PrintableString 'XX'
         :           }
         :         }
 244   53:       SET {
 246   51:         SEQUENCE {
 248    3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
 253   44:           UTF8String
         :             'Royal Institute of Public Key Infrastructure'
         :           }
         :         }
 299   43:       SET {
 301   41:         SEQUENCE {
 303    3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
 308   34:           UTF8String 'Post-Heffalump Research Department'
         :           }
         :         }
 344   28:       SET {
 346   26:         SEQUENCE {
 348    3:           OBJECT IDENTIFIER commonName (2 5 4 3)
 353   19:           UTF8String 'Dilithium Root - G1'
         :           }
         :         }
         :       }
 374 1972:     SEQUENCE {
 378   13:       SEQUENCE {
 380   11:         OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :         }
 393 1953:       BIT STRING
         :         EF 01 70 48 1F 60 F4 54 2D B9 31 EC D6 31 BD 97
         :         60 A3 7A D7 42 BB 43 53 02 27 91 4B 9A F1 01 C0
         :         3F 5A 00 47 AD 94 8F F3 8C 3B 85 95 FE 79 5D 71
         :         FA BC 2D 3C 53 39 0E 2A 5B 5A BD C9 4C EB BA 65
         :         3A 94 8F 50 BA 4D 94 67 32 3A 23 92 36 5C 96 AB
         :         1B C7 83 ED 54 4D DC BF DC AE ED FB 8C 6A 4E 60
         :         8E 3C 27 F3 D2 CD 5B F6 9D 8B C6 19 41 EF 60 D2
         :         79 EA AC 47 69 86 4D CE 2B 94 67 91 2B 9D 08 F0
         :                 [ Another 1824 bytes skipped ]
         :       }
2350  816:     [3] {
2354  812:       SEQUENCE {
2358   15:         SEQUENCE {
2360    3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
2365    1:           BOOLEAN TRUE
2368    5:           OCTET STRING, encapsulates {
2370    3:             SEQUENCE {
2372    1:               BOOLEAN TRUE
         :               }
         :             }
         :           }
2375   14:         SEQUENCE {
2377    3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
2382    1:           BOOLEAN TRUE
2385    4:           OCTET STRING, encapsulates {
2387    2:             BIT STRING 1 unused bit
         :               '1100000'B
         :             }
         :           }
2391   29:         SEQUENCE {
2393    3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2398   22:           OCTET STRING, encapsulates {
2400   20:             OCTET STRING
         :               C4 91 2E B3 34 3C B6 D4 7B 43 05 22 79 FF 36 13
         :               59 4E 4D AF
         :             }
         :           }
2422   31:         SEQUENCE {
2424    3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
2429   24:           OCTET STRING, encapsulates {
2431   22:             SEQUENCE {
2433   20:               [0]
         :                 C4 91 2E B3 34 3C B6 D4 7B 43 05 22 79 FF 36 13
         :                 59 4E 4D AF
         :               }
         :             }
         :           }
2455  711:         SEQUENCE {
2459   10:           OBJECT IDENTIFIER '2 16 840 1 114027 80 6 1'
2471  695:           OCTET STRING, encapsulates {
2475  691:             SEQUENCE {
2479   20:               INTEGER
         :                 61 9B 9D 7E D8 62 16 3E 33 4D EA 15 D2 63 83 68
         :                 50 91 4C 63
2501   10:               [0] {
2503    8:                 OBJECT IDENTIFIER
         :                   ecdsaWithSHA512 (1 2 840 10045 4 3 4)
         :                 }
2513  142:               [1] {
2516  139:                 SEQUENCE {
2519   11:                   SET {
2521    9:                     SEQUENCE {
2523    3:                       OBJECT IDENTIFIER countryName (2 5 4 6)
2528    2:                       PrintableString 'XX'
         :                       }
         :                     }
2532   53:                   SET {
2534   51:                     SEQUENCE {
2536    3:                       OBJECT IDENTIFIER organizationName (2 5 4 10)
2541   44:                       UTF8String
         :                   'Royal Institute of Public Key Infrastructure'
         :                       }
         :                     }
2587   43:                   SET {
2589   41:                     SEQUENCE {
2591    3:                       OBJECT IDENTIFIER
         :                         organizationalUnitName (2 5 4 11)
2596   34:                       UTF8String 'Post-Heffalump Research Department'
         :                       }
         :                     }
2632   24:                   SET {
2634   22:                     SEQUENCE {
2636    3:                       OBJECT IDENTIFIER commonName (2 5 4 3)
2641   15:                       UTF8String 'ECDSA Root - G1'
         :                       }
         :                     }
         :                   }
         :                 }
2658  142:               [3] {
2661  139:                 SEQUENCE {
2664   11:                   SET {
2666    9:                     SEQUENCE {
2668    3:                       OBJECT IDENTIFIER countryName (2 5 4 6)
2673    2:                       PrintableString 'XX'
         :                       }
         :                     }
2677   53:                   SET {
2679   51:                     SEQUENCE {
2681    3:                       OBJECT IDENTIFIER organizationName (2 5 4 10)
2686   44:                       UTF8String
         :                   'Royal Institute of Public Key Infrastructure'
         :                       }
         :                     }
2732   43:                   SET {
2734   41:                     SEQUENCE {
2736    3:                       OBJECT IDENTIFIER
         :                         organizationalUnitName (2 5 4 11)
2741   34:                       UTF8String 'Post-Heffalump Research Department'
         :                       }
         :                     }
2777   24:                   SET {
2779   22:                     SEQUENCE {
2781    3:                       OBJECT IDENTIFIER commonName (2 5 4 3)
2786   15:                       UTF8String 'ECDSA Root - G1'
         :                       }
         :                     }
         :                   }
         :                 }
2803  155:               SEQUENCE {
2806   16:                 SEQUENCE {
2808    7:                   OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
2817    5:                   OBJECT IDENTIFIER secp521r1 (1 3 132 0 35)
         :                   }
2824  134:                 BIT STRING
         :                   04 01 D0 FD 72 57 A8 4C 74 7F 56 25 75 C0 73 85
         :                   DB EB F2 F5 2B EA 58 08 3D B8 2F DD 15 31 D8 AA
         :                   E3 CC 87 5F F0 2F F7 FA 2D A2 60 D8 EB 62 D6 D2
         :                   F5 D6 49 27 8E 32 17 36 A0 62 8C BB B3 03 08 B6
         :                   E6 18 DB 00 F6 2A D2 04 C6 46 03 59 BC 81 8A B8
         :                   96 1B F0 F0 FC 0E C5 AA E8 A4 28 17 3C E5 6F 00
         :                   DE 9B 15 7C 1E 5C 82 C6 4F 56 2F CA DE FC 4A 4C
         :                   28 F6 D3 42 CF 3E F6 16 FC 82 D3 3B 72 85 C9 21
         :                   F2 BF 36 FD D8
         :                 }
2961   64:               [4] {
2963   29:                 SEQUENCE {
2965    3:                   OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2970   22:                   OCTET STRING, encapsulates {
2972   20:                     OCTET STRING
         :                     8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
         :                     17 7D 9F BE
         :                     }
         :                   }
2994   31:                 SEQUENCE {
2996    3:                   OBJECT IDENTIFIER
         :                     authorityKeyIdentifier (2 5 29 35)
3001   24:                   OCTET STRING, encapsulates {
3003   22:                     SEQUENCE {
3005   20:                       [0]
         :                     8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
         :                     17 7D 9F BE
         :                       }
         :                     }
         :                   }
         :                 }
3027  140:               BIT STRING, encapsulates {
3031  136:                 SEQUENCE {
3034   66:                   INTEGER
         :                     01 74 D5 A3 F9 4B CC F0 BC 1C 03 81 EA 81 02 40
         :                     68 E2 BF C0 FF 57 78 4A 66 F0 57 20 DF 2A 43 AA
         :                     10 9D 42 E9 7E C4 FA 9F 1F 8F 40 3D E3 D6 2A D3
         :                     4C E9 04 D9 70 BE 44 FC 0C 9D B7 68 98 05 D4 B9
         :                     6B 8B
3102   66:                   INTEGER
         :                     01 F8 79 09 8C FC 4E E8 72 89 10 D1 75 08 07 79
         :                     8D 5D EA BA C1 F4 83 E7 78 DD E6 9E 34 50 B9 CF
         :                     A8 54 75 B0 27 C0 D1 81 23 B9 A2 3C 47 C2 0A ED
         :                     5C 70 4D 8A 5D 01 D7 F9 04 9D 98 B0 72 18 79 A0
         :                     A9 52
         :                   }
         :                 }
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
3170   13:   SEQUENCE {
3172   11:     OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :     }
3185 3294:   BIT STRING
         :     58 AB 83 89 40 B2 A7 75 AB 34 97 5F 41 A9 4B 12
         :     C1 4F 6F 09 8F C6 A3 65 2E 11 56 68 C2 2D D0 B7
         :     F7 52 44 90 99 EA C4 33 33 60 2F FC C3 B5 2F AC
         :     EC 59 97 E7 82 94 FD 90 3C 32 71 10 C9 C9 D2 1A
         :     25 70 3E 49 05 42 80 0B DC 77 8B 2E 88 99 96 36
         :     DC ED FA 83 E5 5C B1 13 34 CA CF 8F 9D C4 B2 27
         :     AA D7 41 31 91 0E EC 51 0F EF E6 2A FF 00 0F AD
         :     6C B9 58 97 7D B8 12 D8 11 5E F0 7C BE B4 A0 B0
         :             [ Another 3165 bytes skipped ]
         :   }

-----BEGIN CERTIFICATE-----
MIIZTzCCDFqgAwIBAgIUKjo3LAsBm1DBvsLBQHC4desfRXowDQYLKwYBBAECggsH
BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg
UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1
bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg
LSBHMTAeFw0yMzA1MjUyMDM1MTlaFw0zMzA1MTIyMDM1MTlaMIGPMQswCQYDVQQG
EwJYWDE1MDMGA1UECgwsUm95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5m
cmFzdHJ1Y3R1cmUxKzApBgNVBAsMIlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERl
cGFydG1lbnQxHDAaBgNVBAMME0RpbGl0aGl1bSBSb290IC0gRzEwgge0MA0GCysG
AQQBAoILBwYFA4IHoQDvAXBIH2D0VC25MezWMb2XYKN610K7Q1MCJ5FLmvEBwD9a
AEetlI/zjDuFlf55XXH6vC08UzkOKltavclM67plOpSPULpNlGcyOiOSNlyWqxvH
g+1UTdy/3K7t+4xqTmCOPCfz0s1b9p2LxhlB72DSeeqsR2mGTc4rlGeRK50I8Mn+
m+vs6jN61FLjp+402HR3oz3UDh5lPAIYShfSRSWMiL5W85TAWajEfrIas25x2qHx
77fv8JGFzdbTMnvPbngjlNO/zWdfC05aCQHuh5cp3m0+aGqAdQoh7ntVltj2yzyc
vEswYeG15tTUUfR4qHxQnyTifGXX7UP6uIkd9z3ZPitpIOw8G6lYg7Mi5xD4HQdz
7bAIKGyVps8/BC/46oAcJqYj9R1Waw6WTlwDt1rvN/kJEP+hSo7SpnMkIDWTk5z6
Suh2ZmTmrmU8BLjBW72JdV1FaUIEIR6Kr0oDOO+crpIz0WfObYU/MN7kGGRrdW+R
gKB6Gpad1J9A6AKihOWHkvCoxWsB6o216jtFfoDzrR2xXGtnsWW8i+KXI5CP6aPg
QfM27PqsGzxYtaaGkRnDE5XmeSQfLQyIkzMNI1lIWV9+CcN4AIHA2v5H4/YwBZAV
gOhsJQd8zGZlX06ZCjrO/LnFWLAfHLYb9X0qSPMW7ez2NhfswFYamgjIy2hp3dgh
w9A3Z5SzESvoRratEaqjZnLNreZuMCyKGZip/go/qw6I/CQr/tse1XsymCBuaKLb
MkG3tLM0l7+ihfjy9l+sumYxlY7H/Y5ovleXcUdhDZ1khAtYKmCPQhYDYLYJfJst
c2etZJQol33RwtT5fwxH1KQV3NRI50nqZjN+d0NyDJ2jQBdT4/L/YdZ30fs9MpWV
0nLiHgdiNxW9ZFVc/VTpPb5M9HcSd7gsTa9CLT4nAeq3FfW2XTCGboMHd9YTJTPV
y3tfnAAZS5MPuwUwbknP65gjbpapo0PceDk7ywB+ab2bmpTiSrptu0WoZA2kTnsM
a5SWrz+ETr1ukmX6l3ShmbShYE3ALh1C5YLps/OjZ7DNajzDHXGbrMcAMbqUjmIt
EiVF0Vva2JIX1VI5TC0kfV6vqSayAtdqYDcng0PukQjdm4ZRKxC3oBi1wmi0hUnQ
oYYBrbEz+DHPRHcvvKwsNdqsUXKGwHcoDy2lJHSvvJA3WDlF4JkYd8e76pyzPjdV
F14qiEeufy5j0lklCHDhT0oQJxWi4H3bgizF4JwA4YRgUWNppw3i4XmuurWnPTlo
XuXej0qp71fJX4l3CwBL9mN2nT7xDIJIyPjLD9n+oTEbt1/qwJO41QeQ07slzb9X
XQeOm4IVvmyGiWx6ymtHwOoTu0noUvkDsYpigZSgOTXn+OSYkd/AxzJQsXcY3WvR
mMvTyLcsZGiZL9C9kncbmtUwqR3hVnFxcxcw4STNgNeNDvE7qNqXZTNuQ1WY+RSJ
1L01G3uMeco8OLCqJwfnYU/6/2lAZ8SOUEST54CcZ52fqnp6iruD9i8VH8iKyVFO
Ky/hX+2H7BmL3raQkTzCzQNZJpPFAoj1GT2ghv38VU6Biad3Mcja09puo1LEhBI5
0SCWswDeFeay3L4rI3RruZAHaCmDoPFM4eXXD68kmSZeZo0vCMkv2/FG84KdMvBi
65gxArrGE/QLMWP5A3S8QBUvwGtc0yOHTYJfhhyEpBdm2PFGti1SaPp0BCoEj9vq
+/is1xXxCABxZcCF6rsBN0e2Kj1Bmfv+bfz0yY3aCspJP25Uvw1d0sbWmU3tkkeF
Yqvsu/xz0ATz1jfLD3j3M1sWUP5Akdey9Jq4crQmCkccNH9H/fwGWRT3hgqOQOSv
FSRqeSshkZRkhl9rFo0KcK7dcyfnpQjq0T2xlBeOqtDfujldTLgr8/HbcYpM8Ivg
PWqm1h7ANuBvt4uzYaPMVTVZKX+NmqYrz9/3uCr1En0v9u6D3y1SGzr8kZHib1oe
IY0snH494zwVb0ak6nv+MIj4+A5bFG1cm2eBgRyqeiT7JZAdBa9AQz64ZMd98Tz3
Jn2KgQyUlHylE/xfyw1112oar7d7nEJXZCrMswKLHvo/gx2NdjChU9N0F+rYuKu1
yIFfZpgQVwFaEzhiLK/XZvnltJkHcI7Q5Vjuiu6RDpxBqjmume8mx6O6ZmFkNzwr
iSE9y3SbPBxoij/LUh8rmBt1n0mkx1RFCltQE8aQjajNIw/kpptydqYDC5Vl1M2I
JecL357Wqk3eDVKAUO5cYxox1X9rVRj/aDiUaMjRLESM7blf183tHgHYaHNBXp5+
c0X29xCiqUduRO0MahGHrifMJDXo82WJA4ghNyuVnY45/gTYO4HTzP2pLTcsewoQ
ufoHWp2LfgzlfTykT0a2rdkgS/fzMu4PKx0RFixnTe2bPHnHs7aukyWrSTV28Wvs
aut+LriWLRdZSPJpIFejOZBl0ghF4uXFepKWfYygrVoNVhpeX41XYQR2xS9vz8CK
h2z0ePnvQPsiCVnVHOtddKu3sd/XK5+PXFlK+l8Xs8ioxG3UmVy/C6fuwu1Ki7hR
qLKIs5GNT2vqJHyIqe5kihpY9xeXmm6+cDhXfLuuzGaEBpwMAa33OdNmVGGcDKOC
AzAwggMsMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW
BBTEkS6zNDy21HtDBSJ5/zYTWU5NrzAfBgNVHSMEGDAWgBTEkS6zNDy21HtDBSJ5
/zYTWU5NrzCCAscGCmCGSAGG+mtQBgEEggK3MIICswIUYZudfthiFj4zTeoV0mOD
aFCRTGOgCgYIKoZIzj0EAwShgY4wgYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxS
b3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkG
A1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UE
AwwPRUNEU0EgUm9vdCAtIEcxo4GOMIGLMQswCQYDVQQGEwJYWDE1MDMGA1UECgws
Um95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5mcmFzdHJ1Y3R1cmUxKzAp
BgNVBAsMIlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERlcGFydG1lbnQxGDAWBgNV
BAMMD0VDRFNBIFJvb3QgLSBHMTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAdD9
cleoTHR/ViV1wHOF2+vy9SvqWAg9uC/dFTHYquPMh1/wL/f6LaJg2Oti1tL11kkn
jjIXNqBijLuzAwi25hjbAPYq0gTGRgNZvIGKuJYb8PD8DsWq6KQoFzzlbwDemxV8
HlyCxk9WL8re/EpMKPbTQs8+9hb8gtM7coXJIfK/Nv3YpEAwHQYDVR0OBBYEFI7C
FAlgduqQOOk5rhttUsQXfZ++MB8GA1UdIwQYMBaAFI7CFAlgduqQOOk5rhttUsQX
fZ++A4GMADCBiAJCAXTVo/lLzPC8HAOB6oECQGjiv8D/V3hKZvBXIN8qQ6oQnULp
fsT6nx+PQD3j1irTTOkE2XC+RPwMnbdomAXUuWuLAkIB+HkJjPxO6HKJENF1CAd5
jV3qusH0g+d43eaeNFC5z6hUdbAnwNGBI7miPEfCCu1ccE2KXQHX+QSdmLByGHmg
qVIwDQYLKwYBBAECggsHBgUDggzeAFirg4lAsqd1qzSXX0GpSxLBT28Jj8ajZS4R
VmjCLdC391JEkJnqxDMzYC/8w7UvrOxZl+eClP2QPDJxEMnJ0holcD5JBUKAC9x3
iy6ImZY23O36g+VcsRM0ys+PncSyJ6rXQTGRDuxRD+/mKv8AD61suViXfbgS2BFe
8Hy+tKCwJrkY5OwhjwTelDEzs2FDEWd6YcisH7nh9mtU2RCYQJqH84nEiLMbOuCi
FG1LAR9/ihsHp281e5p4YrYqDqwjvVIeIHRl7miXMz6PH2t7F1h2mGHeIS6tVpW6
3U+kIF2jd9OxVp9Zzs10Ok3F3HrQaJ6ym7HGaNfdYV7vu5GQV8uQk5eZuEsLMKHv
IK2uk+5p9fC8B9ipxijz/hJeGhir6+2NUq2p/f/n0Eav3MYH2nC16mwg1hCwcAER
K8G6/uddS9NjAs9u70W8ApWbln2oS84NwCaTx690/Bg1E8MwQkmd55vKB64YmvHL
unjWIgWWjPl1LjPKj2R8nnPNRcH3CxtMhL0JPU6vTofji8ANmd/3igL3w5cvr3Rb
CVxSDZD1fQf3ctK+5f76mNGzXl1nuGianArUx/yROO3Jt6pD3/oHvkWHqhnGZVG2
UtWkPqo+9HLrtFJ7WmdrhRIP2aOB0/xuKTFo4Ma9z+XqVoxNT9zDy5Z9LlK0hmJh
NbqVTnq0iF6OxsF7xXlaG/z8u9JtqMlplAJZKI3aJpjZ9Qex3F4h5V1/hG4EFri1
UEM98q4AXOqDDN2twN/dg2NttwK6HqDH2Jy6rAUP8QsxCWts/4kPUEEGq9SVHM2d
VgIxfyVUSfClnBO3CpLQBCzsdOUJDqMs6Jok5RoMDx3NQYbznKEaFgKnnD+ie8B9
9fe4XvThKQ7n4Es4b7A5Cn8ddCMjb6UilaTotqO9immA7VjEovNSVJ9NqLXCeTS6
3iBMaLwIfFDNgYSNfX8lIUvuc/m6en59kDOGp5nkCQK584lh0qim0eVwnSr+TWsg
eI6yBF7iTyr5FSjSne0ysbIscGpgewGNmduKhBsatX51tf2waXgi0MFIdx7n1LfG
mCA1EczIBMIgUyDQFP6hIywxN/Kwo10Ls9MhCSNiyMBewcxoa6Vc9ZPBu36FH45U
UvMgD6QQMuGTwhkD5T1p76gw0hYLCcIuAK+/vlVY0q6YJ7EBxQ6PnxuO5g5WdI+O
MER4sv7XvWnoC10uMUSrtxpA7CycS07m8LMi+n5RqoQWA45kMjAN4rb/2V+5Poet
cI0AhtG+b56fUn3uBQe60v6q0d1gw5Bzr46AAO49RbcYUi2Ls7EPmk1MAfx4Mxc7
+Cgqqb/qz7Wpog5MWCuMCk68Kmbm4gaPr1GPIyjFfvXjbc6/o8nsEmd+lDUms7pL
Ne65baMPVRhSER2EffyrqjMn2adBysqVEJU2vWs+mRND2KVzMWNyWvt5KWovp89E
PX1RFp7H/wKw6rEL4Hp1Gn/xUyi/dAIUo7U3mhhlvAEWZxEqD3ABxj1j6H34uTxY
mz6mO0QPjZAcIhRXRYfXxC3aXMFIm+AkxrWCva6IF7cobeWMIe4Uh0dcoKP5VXbO
ZPJ0tV1ug9tzNywC+JXpXZagCTMOxQJpPTxgRl1iZZT/U7sSUPBWnyPTH/lUAuld
T9W+6qxSvb9VlcGeEKyWYDKij13V7els3nbYlLL7cEJR+lA1HkaEoCQEGu3YdwLK
ZVE4MfYearU0gm7S/QXfxLh5MR6phhp5y8Ve6suoXiS4dP1S2C5J8Md5sOASM38n
tIdXhR2dRk3LbmJIvhXqqtO5nBTx6LLznqUKyGaJd+lmTDhpLXzbnm7K4+Mdkt+P
paXsBHbzj+13fTzBQ5zyxz8TNfk0J2m4qBDMf12SsFj0NZ4Lco0meYnhsbkWr1YA
7cc4DPl4xrR8JpfKdRHNg+yVmkfSfmBeLiEaLH61h6a3QKHSLGkpJk1x6h+WpVHY
eMYahsk4sDALaN+QerJfgxO8D6W7xbQc6fHLPmFSVqltqq/DsKTpIErD57+Ir0uo
EQECk70GVNy9WiwLPWvvQtBLcpG0ANPhkJxp7OYho4EQPyTMDjJMqSRB6ZCi7KTJ
StfjUSftvO121L1MjtjQLKkSRQJUM7qWXKqHDym8k8ELh7rwsT7yxH4I5wZg/iEe
ZY8YfBVXakThB4iH+zWqJktxmQJ94LccDYPHORDeBVTC1oygS5z414UQP632CV5O
TX6OTQ3AKDmzOdVJsqH0RpH1lrH6tOgtaBN+c+mN/iOZgtiEBYyomw0W7AKsfU0h
hjZDuEWk+4IE7nNJP39prS5rpGtMIqgXiuFmDe1n8wt009QIy5GfF3ZslO6AoIHA
yv8V/5UYPCq1VVqPYIyHDVGWII+stbKqdPF5I+ZP10oEaZgH3zYuXF5cyImyaxT6
71t8fl5nnKTmBlHe7aDHxnluuvZIwQd1GavQQD+TGTfdMaA73p2k2GvYRIR1D+C9
pO1BDstPBfKzH/gKiLEDc1MDqzibQ32zJ7j9ZgnBdoaQeYlSMKl6WrgO2q1x5Z1Z
DHZ5UohTMTOOcgiiWsDEsZzud35DoUXV1rCfp3pr+lPjqAokZlNK3nxelZMu/VEB
pGOeLnv17WSOeiV9w7rjTAvompyCZF4RgI1gTkHzBvMU6oBjyIj/RuI4FVJGvOmH
wSop9ZX7OWZx/oSfuZWhboP7+DKdPNfni/ntHJOoH3ew0NoCWvvtuVUb2LbB5fbT
OnRg6U9zEhpECwwkC81xl3mb7EwGdDDj+iiUbuLPiCnEXlndWVzn4kNj9de/kPil
8gj/Klpdagdb0UoLtiPt3Qx1bWzblIcxFrLFviDXlyvA2LS+d3SswAelulevM6TB
7gIqbJ1IPI0KV1P5996yDnKOUY5R5kmTdcRjx8vN8CPnJtyL40TYz+bI4svJjEPL
ZKT6EmUFtEkhD/EZcHFOvbArMtD7+CseuNWpbhlSG7NxQWh6oTputGuyKCGlKtyr
4Ai9p7BiRmSAlpTzUborzvM8/C6NVmwolkmObYmAr7OtNc39LVKTXbk8crTPnZ6O
OGvoBrv+z4NF/kW92TOjyzAPl/HWgifCqqxE+NnbxtLy5nqM7EiFvdnFhJzxMK+9
729vMUw6iyaDfE/v1EchRoleNsGf9vJaBH0BUjv4k2J4GruMX8Bab++zv2O18znr
h+dgLf7sWA2+DWcRfyKIF0pwYhedC7BP14lY3fnqH5cvMtMui8lgY86AkhQo9bNH
yu/JG+SHE+j3m2vRTPey/TA6pGIh8wOoQmfmkNRzO8Jaw88wGHM+BHwJKVTJFKM6
hC4sSozBgWhCLnNy3F5t/3e7EsC4DDtVh/IqBPfCYY0IFjVEZuv0MOKQ7yetZmxh
Bwk8fyfZBjjkUGYVcHimgPaPQFad1mQLBdz/5qAPdHtK+qrr9uoiD+UTq2PZunaG
09IPhf6OeXFSHxg4xTtzaJuL3gcwBsnPE3ODTx4eBzTlfCSGSHqtoftTUl6ODb6z
Sp51vyIopD6bAeg7eJOW8y9vBsTDMJqRb+66ab/QSnApF2kBH3m1874m/U1KBshk
y9XDdsBJtmVQt4MKWIJEF+7kohNlATqlIPyBUcE6uR4cPTTXyQof1IxYxdFsxSNW
GFia9tLmL2HkKzVK5zv/V93kiFi6ISHjZ9+bbVRcwKnkyVM18NndIUNwgqh8l2a1
UsX4Xmf7r/SzvY9k4bhsg/XnmUi38X1RI1zvZZAPQm0giNMQRljDI4SnaTT/M0cs
f03MSJ/+rfe/5df53qhBVB6VO4UCRCLspn9Hw+gaA2MkZSOW6360zp39i5Qmt2U6
KYfbrYPIaqnmvsXRnZFRvUSkqkXFuNPmIH7AIGVt6esazETnl0qqcDXgiuHdm6zd
2fQ9Fp6b9YVpTKXscFhJ0xvVtZrkavtODGrpjbiHd1mw9AIKKgf0T3QWrbaDkKy5
cq6IrrLkMj9dGi/uDs/kmafDVfRf2119wbE46ESe9s2O6xHHQhaEWKjaoX2rZimn
vI3K3I/ClhEkM+Ja2g42jta+PEPL1Cv1iA/W8sdM+TfdbPwokvJ/a7UGjjIvdNcQ
VGjoEHUckxxepUhwF25tD/Wv0k36iEN9x02O7G/dmhZCzuRcfzTvKW7mDlP527E6
pBYCU/FtzcMqZjc0bTAEVZd+heLAWj52+C06xXBfHtUco8ZWpyB8L4uTDxY3lqNa
EbqeOEIFkuyuqrx64f7XQWiPxMVutWG9JzcqzX/pxo9tzChBs+ivXIE5mkG6gD+c
gi1iERWk+MCvVC+19l31QKdEABMN+CJFGst8Zxr3Shug3BP8uOgFDDI2PICFiq3R
LJCTosLUKTdOirnZFxkpMktgh6TF/SI3SWSAkL7d4hkwS2a35e0AAAAAAAAAChAW
ICkw
-----END CERTIFICATE-----

```

## ECDSA signing end-entity

This is an end-entity signing certificate which certifies an ECDSA key.

```
  0 609: SEQUENCE {
  4 451:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13  20:     INTEGER 35 FE 9A 5B 0F 76 7D AE 26 CB D0 71 6C 9A 9E DE 62 49 3A 5D
 35  10:     SEQUENCE {
 37   8:       OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :       }
 47 139:     SEQUENCE {
 50  11:       SET {
 52   9:         SEQUENCE {
 54   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 59   2:           PrintableString 'XX'
       :           }
       :         }
 63  53:       SET {
 65  51:         SEQUENCE {
 67   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
 72  44:           UTF8String
       :             'Royal Institute of Public Key Infrastructure'
       :           }
       :         }
118  43:       SET {
120  41:         SEQUENCE {
122   3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
127  34:           UTF8String 'Post-Heffalump Research Department'
       :           }
       :         }
163  24:       SET {
165  22:         SEQUENCE {
167   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
172  15:           UTF8String 'ECDSA Root - G1'
       :           }
       :         }
       :       }
189  30:     SEQUENCE {
191  13:       UTCTime 25/05/2023 20:35:19 GMT
206  13:       UTCTime 21/05/2026 20:35:19 GMT
       :       }
221  47:     SEQUENCE {
223  11:       SET {
225   9:         SEQUENCE {
227   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
232   2:           PrintableString 'XX'
       :           }
       :         }
236  15:       SET {
238  13:         SEQUENCE {
240   3:           OBJECT IDENTIFIER surname (2 5 4 4)
245   6:           UTF8String 'Yamada'
       :           }
       :         }
253  15:       SET {
255  13:         SEQUENCE {
257   3:           OBJECT IDENTIFIER givenName (2 5 4 42)
262   6:           UTF8String 'Hanako'
       :           }
       :         }
       :       }
270  89:     SEQUENCE {
272  19:       SEQUENCE {
274   7:         OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
283   8:         OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       :         }
293  66:       BIT STRING
       :         04 42 25 48 F8 8F B7 82 FF B5 EC A3 74 44 52 C7
       :         2A 1E 55 8F BD 6F 73 BE 5E 48 E9 32 32 CC 45 C5
       :         B1 6C 4C D1 0C 4C B8 D5 B8 A1 71 39 E9 48 82 C8
       :         99 25 72 99 34 25 F4 14 19 AB 7E 90 A4 2A 49 42
       :         72
       :       }
361  96:     [3] {
363  94:       SEQUENCE {
365  12:         SEQUENCE {
367   3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
372   1:           BOOLEAN TRUE
375   2:           OCTET STRING, encapsulates {
377   0:             SEQUENCE {}
       :             }
       :           }
379  14:         SEQUENCE {
381   3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
386   1:           BOOLEAN TRUE
389   4:           OCTET STRING, encapsulates {
391   2:             BIT STRING 7 unused bits
       :               '1'B (bit 0)
       :             }
       :           }
395  29:         SEQUENCE {
397   3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
402  22:           OCTET STRING, encapsulates {
404  20:             OCTET STRING
       :               5B 70 A7 98 17 F7 9F F6 37 D2 F7 E3 DC 44 6C 21
       :               09 D7 BB D4
       :             }
       :           }
426  31:         SEQUENCE {
428   3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
433  24:           OCTET STRING, encapsulates {
435  22:             SEQUENCE {
437  20:               [0]
       :                 8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
       :                 17 7D 9F BE
       :               }
       :             }
       :           }
       :         }
       :       }
       :     }
459  10:   SEQUENCE {
461   8:     OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :     }
471 139:   BIT STRING, encapsulates {
475 135:     SEQUENCE {
478  65:       INTEGER
       :         76 32 73 9A 33 9E CF 60 5B CD F5 60 09 58 D6 6C
       :         65 48 F6 B3 C9 68 16 07 80 B1 6A CD 0D D5 73 57
       :         97 1A 17 98 FA 6E 1C 0B AA 17 98 32 A3 32 00 D6
       :         A4 FF C6 2D 2A F2 AB DC 96 6F 28 25 4D 80 5F 61
       :         A3
545  66:       INTEGER
       :         01 27 6A 87 C7 1E 72 ED 67 D2 ED C5 A3 0F 88 A7
       :         7D 6A 84 64 74 7E C2 CF A3 4A 17 27 09 03 CB AB
       :         D5 1F A7 38 D2 A8 11 FC 00 EE FB C0 46 85 66 23
       :         28 80 8C 19 07 4D EB 1E B0 1E 53 2C 53 90 D6 96
       :         97 6F
       :       }
       :     }
       :   }

-----BEGIN CERTIFICATE-----
MIICYTCCAcOgAwIBAgIUNf6aWw92fa4my9BxbJqe3mJJOl0wCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDUyNTIwMzUxOVoXDTI2MDUyMTIwMzUxOVowLzELMAkGA1UEBhMCWFgxDzAN
BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV
uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcqNgMF4wDAYDVR0TAQH/BAIwADAOBgNV
HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFtwp5gX95/2N9L349xEbCEJ17vUMB8GA1Ud
IwQYMBaAFI7CFAlgduqQOOk5rhttUsQXfZ++MAoGCCqGSM49BAMEA4GLADCBhwJB
djJzmjOez2BbzfVgCVjWbGVI9rPJaBYHgLFqzQ3Vc1eXGheY+m4cC6oXmDKjMgDW
pP/GLSryq9yWbyglTYBfYaMCQgEnaofHHnLtZ9LtxaMPiKd9aoRkdH7Cz6NKFycJ
A8ur1R+nONKoEfwA7vvARoVmIyiAjBkHTesesB5TLFOQ1paXbw==
-----END CERTIFICATE-----

```

## Dilithium signing end-entity

This is an end-entity signing certificate which certifies a Dilithium key. It contains a Delta Certificate Descriptor extension which includes sufficient information to recreate the ECDSA signing end-entity certificate.

```
   0 6166: SEQUENCE {
   4 2849:   SEQUENCE {
   8    3:     [0] {
  10    1:       INTEGER 2
         :       }
  13   20:     INTEGER 0D 8C F2 DF 03 16 03 78 8D DD FE CD E4 EB EB 56 86 BB 4B C6
  35   13:     SEQUENCE {
  37   11:       OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :       }
  50  143:     SEQUENCE {
  53   11:       SET {
  55    9:         SEQUENCE {
  57    3:           OBJECT IDENTIFIER countryName (2 5 4 6)
  62    2:           PrintableString 'XX'
         :           }
         :         }
  66   53:       SET {
  68   51:         SEQUENCE {
  70    3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
  75   44:           UTF8String
         :             'Royal Institute of Public Key Infrastructure'
         :           }
         :         }
 121   43:       SET {
 123   41:         SEQUENCE {
 125    3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
 130   34:           UTF8String 'Post-Heffalump Research Department'
         :           }
         :         }
 166   28:       SET {
 168   26:         SEQUENCE {
 170    3:           OBJECT IDENTIFIER commonName (2 5 4 3)
 175   19:           UTF8String 'Dilithium Root - G1'
         :           }
         :         }
         :       }
 196   30:     SEQUENCE {
 198   13:       UTCTime 25/05/2023 20:35:19 GMT
 213   13:       UTCTime 21/05/2026 20:35:19 GMT
         :       }
 228   47:     SEQUENCE {
 230   11:       SET {
 232    9:         SEQUENCE {
 234    3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 239    2:           PrintableString 'XX'
         :           }
         :         }
 243   15:       SET {
 245   13:         SEQUENCE {
 247    3:           OBJECT IDENTIFIER surname (2 5 4 4)
 252    6:           UTF8String 'Yamada'
         :           }
         :         }
 260   15:       SET {
 262   13:         SEQUENCE {
 264    3:           OBJECT IDENTIFIER givenName (2 5 4 42)
 269    6:           UTF8String 'Hanako'
         :           }
         :         }
         :       }
 277 1972:     SEQUENCE {
 281   13:       SEQUENCE {
 283   11:         OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :         }
 296 1953:       BIT STRING
         :         26 B7 9D 05 2D DA 22 4D BB F4 CC 11 00 21 88 46
         :         45 A8 B0 B0 58 29 23 0E 96 98 0F D2 0A EB 18 53
         :         FE 86 B8 78 71 96 38 E3 07 7F A8 4B BB B8 78 BB
         :         B4 9D DC 7D 06 EB 88 43 9D AB 5B A0 E7 A5 81 0B
         :         C4 A8 4D 27 02 2F BA 2D 71 C5 EB 9B 7E B6 1E 4F
         :         23 EB EA 28 FF 6C 10 FE 1E F8 D2 29 DB DD C2 77
         :         22 42 D5 A1 8F 1D 20 33 FD 1A 6D 07 A1 B2 86 D4
         :         D4 02 CF 23 38 8B 17 A8 6F 0C 6E D7 A2 6B 33 87
         :                 [ Another 1824 bytes skipped ]
         :       }
2253  600:     [3] {
2257  596:       SEQUENCE {
2261   12:         SEQUENCE {
2263    3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
2268    1:           BOOLEAN TRUE
2271    2:           OCTET STRING, encapsulates {
2273    0:             SEQUENCE {}
         :             }
         :           }
2275   14:         SEQUENCE {
2277    3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
2282    1:           BOOLEAN TRUE
2285    4:           OCTET STRING, encapsulates {
2287    2:             BIT STRING 7 unused bits
         :               '1'B (bit 0)
         :             }
         :           }
2291   29:         SEQUENCE {
2293    3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2298   22:           OCTET STRING, encapsulates {
2300   20:             OCTET STRING
         :               8F E9 0D 6F F4 13 3C A4 4C C2 04 D5 E6 39 CB FD
         :               5C C7 83 11
         :             }
         :           }
2322   31:         SEQUENCE {
2324    3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
2329   24:           OCTET STRING, encapsulates {
2331   22:             SEQUENCE {
2333   20:               [0]
         :                 C4 91 2E B3 34 3C B6 D4 7B 43 05 22 79 FF 36 13
         :                 59 4E 4D AF
         :               }
         :             }
         :           }
2355  498:         SEQUENCE {
2359   10:           OBJECT IDENTIFIER '2 16 840 1 114027 80 6 1'
2371  482:           OCTET STRING, encapsulates {
2375  478:             SEQUENCE {
2379   20:               INTEGER
         :                 35 FE 9A 5B 0F 76 7D AE 26 CB D0 71 6C 9A 9E DE
         :                 62 49 3A 5D
2401   10:               [0] {
2403    8:                 OBJECT IDENTIFIER
         :                   ecdsaWithSHA512 (1 2 840 10045 4 3 4)
         :                 }
2413  142:               [1] {
2416  139:                 SEQUENCE {
2419   11:                   SET {
2421    9:                     SEQUENCE {
2423    3:                       OBJECT IDENTIFIER countryName (2 5 4 6)
2428    2:                       PrintableString 'XX'
         :                       }
         :                     }
2432   53:                   SET {
2434   51:                     SEQUENCE {
2436    3:                       OBJECT IDENTIFIER organizationName (2 5 4 10)
2441   44:                       UTF8String
         :                   'Royal Institute of Public Key Infrastructure'
         :                       }
         :                     }
2487   43:                   SET {
2489   41:                     SEQUENCE {
2491    3:                       OBJECT IDENTIFIER
         :                         organizationalUnitName (2 5 4 11)
2496   34:                       UTF8String 'Post-Heffalump Research Department'
         :                       }
         :                     }
2532   24:                   SET {
2534   22:                     SEQUENCE {
2536    3:                       OBJECT IDENTIFIER commonName (2 5 4 3)
2541   15:                       UTF8String 'ECDSA Root - G1'
         :                       }
         :                     }
         :                   }
         :                 }
2558   89:               SEQUENCE {
2560   19:                 SEQUENCE {
2562    7:                   OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
2571    8:                   OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
         :                   }
2581   66:                 BIT STRING
         :                   04 42 25 48 F8 8F B7 82 FF B5 EC A3 74 44 52 C7
         :                   2A 1E 55 8F BD 6F 73 BE 5E 48 E9 32 32 CC 45 C5
         :                   B1 6C 4C D1 0C 4C B8 D5 B8 A1 71 39 E9 48 82 C8
         :                   99 25 72 99 34 25 F4 14 19 AB 7E 90 A4 2A 49 42
         :                   72
         :                 }
2649   64:               [4] {
2651   29:                 SEQUENCE {
2653    3:                   OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2658   22:                   OCTET STRING, encapsulates {
2660   20:                     OCTET STRING
         :                     5B 70 A7 98 17 F7 9F F6 37 D2 F7 E3 DC 44 6C 21
         :                     09 D7 BB D4
         :                     }
         :                   }
2682   31:                 SEQUENCE {
2684    3:                   OBJECT IDENTIFIER
         :                     authorityKeyIdentifier (2 5 29 35)
2689   24:                   OCTET STRING, encapsulates {
2691   22:                     SEQUENCE {
2693   20:                       [0]
         :                     8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
         :                     17 7D 9F BE
         :                       }
         :                     }
         :                   }
         :                 }
2715  139:               BIT STRING, encapsulates {
2719  135:                 SEQUENCE {
2722   65:                   INTEGER
         :                     76 32 73 9A 33 9E CF 60 5B CD F5 60 09 58 D6 6C
         :                     65 48 F6 B3 C9 68 16 07 80 B1 6A CD 0D D5 73 57
         :                     97 1A 17 98 FA 6E 1C 0B AA 17 98 32 A3 32 00 D6
         :                     A4 FF C6 2D 2A F2 AB DC 96 6F 28 25 4D 80 5F 61
         :                     A3
2789   66:                   INTEGER
         :                     01 27 6A 87 C7 1E 72 ED 67 D2 ED C5 A3 0F 88 A7
         :                     7D 6A 84 64 74 7E C2 CF A3 4A 17 27 09 03 CB AB
         :                     D5 1F A7 38 D2 A8 11 FC 00 EE FB C0 46 85 66 23
         :                     28 80 8C 19 07 4D EB 1E B0 1E 53 2C 53 90 D6 96
         :                     97 6F
         :                   }
         :                 }
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
2857   13:   SEQUENCE {
2859   11:     OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :     }
2872 3294:   BIT STRING
         :     AB 1C 18 8F 51 6D AC F2 C2 4B EB 47 0C 25 A3 54
         :     BF 6E 3F EF DB 96 44 C3 BA 54 A1 E6 43 C9 88 13
         :     1B ED 8D C6 22 C6 F2 EC 95 8F 5E E2 C7 A2 DE 92
         :     9E 49 32 35 33 B6 93 07 EF 60 41 4B CB 3F ED E9
         :     21 91 EB 6F 61 F5 15 60 57 60 9B 93 DC 73 C1 54
         :     FF EF AA 07 2F 46 57 CD DE EE BD B0 23 EF 20 C6
         :     17 68 D4 D0 11 35 79 85 5B 80 DB 90 25 7E A8 17
         :     11 FC DA 0C BD F9 31 91 FA 4D C7 6D 80 4C AB FB
         :             [ Another 3165 bytes skipped ]
         :   }

-----BEGIN CERTIFICATE-----
MIIYFjCCCyGgAwIBAgIUDYzy3wMWA3iN3f7N5OvrVoa7S8YwDQYLKwYBBAECggsH
BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg
UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1
bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg
LSBHMTAeFw0yMzA1MjUyMDM1MTlaFw0yNjA1MjEyMDM1MTlaMC8xCzAJBgNVBAYT
AlhYMQ8wDQYDVQQEDAZZYW1hZGExDzANBgNVBCoMBkhhbmFrbzCCB7QwDQYLKwYB
BAECggsHBgUDggehACa3nQUt2iJNu/TMEQAhiEZFqLCwWCkjDpaYD9IK6xhT/oa4
eHGWOOMHf6hLu7h4u7Sd3H0G64hDnatboOelgQvEqE0nAi+6LXHF65t+th5PI+vq
KP9sEP4e+NIp293CdyJC1aGPHSAz/RptB6GyhtTUAs8jOIsXqG8MbteiazOHHpqI
w3bL4185e0VLkk2X/I26+qaiJyTstWIzT0xmp2P1dtDFA/7pJkpvt7bnCjY6dPQx
Fm1h2OEOIdAL91ujNqKcx5mh5gq956ms4MyjnW6qFJuPm+txzIT/YOFlWwSnaEm0
HCVZO8ah4yTKJqXbzjv4IeoQ0ZzU8FsNm7NL2TA+26WhBEdK3JlHPMOgKftjQBd5
fR5M+9hS1wJ+88RfUqQZw4pHSsVpq7DbyUV3e13aVOD6qTOcralEibUD6gVrhIbt
2jfD24fBI+mEO2+uxtaLJy83fUz9kEoOayjqyl7iyJLaiC5POoCq0WX2JZD0olD9
nzSxkWXhKwtCnbRSrFLTqNbkTjRG2R6dqRsLPpXQSzHuH1AP+nfWsxZm0w3i7PGQ
AXUDMGieaPKvN5GIKB77WzPOOu8cecoCAC4znAM5JtTS+AyXUPhRa0baRpJMBmdp
74kLxsjv4dKJ3PHZEEgFBBonfVe1WL49byD8L1tMTyMtJIyeULojyQEDSiIeQ3O8
U1SuCExX/CJUnwMkGcabJWvNOB3PoWd1Ub/39cHcyA+S+/W5jCJhHypt4tPRZE4Y
1tx1tJbyRfI4JDi4NhXjI7mpY3Ny5NgYqvI4EcY3hryy8ICM61wFAEIaIkM4H7Iw
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
t9bkPD9cnN8AAAAAAAAAAAAAAAAJEBkhJis=
-----END CERTIFICATE-----

```

## EC dual use end-entity

This is an end-entity key exchange certificate which certifies a EC key. It contains a Delta Certificate Descriptor extension which includes sufficient information to the recreate the ECDSA signing end-entity certificate.

```
  0 971: SEQUENCE {
  4 812:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13  20:     INTEGER 7B D9 3E F5 D3 01 58 7A 40 F8 5D 73 F0 AC 7E 5E 0B AB 88 16
 35  10:     SEQUENCE {
 37   8:       OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :       }
 47 139:     SEQUENCE {
 50  11:       SET {
 52   9:         SEQUENCE {
 54   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 59   2:           PrintableString 'XX'
       :           }
       :         }
 63  53:       SET {
 65  51:         SEQUENCE {
 67   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
 72  44:           UTF8String
       :             'Royal Institute of Public Key Infrastructure'
       :           }
       :         }
118  43:       SET {
120  41:         SEQUENCE {
122   3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
127  34:           UTF8String 'Post-Heffalump Research Department'
       :           }
       :         }
163  24:       SET {
165  22:         SEQUENCE {
167   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
172  15:           UTF8String 'ECDSA Root - G1'
       :           }
       :         }
       :       }
189  30:     SEQUENCE {
191  13:       UTCTime 25/05/2023 20:35:19 GMT
206  13:       UTCTime 21/05/2026 20:35:19 GMT
       :       }
221  47:     SEQUENCE {
223  11:       SET {
225   9:         SEQUENCE {
227   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
232   2:           PrintableString 'XX'
       :           }
       :         }
236  15:       SET {
238  13:         SEQUENCE {
240   3:           OBJECT IDENTIFIER surname (2 5 4 4)
245   6:           UTF8String 'Yamada'
       :           }
       :         }
253  15:       SET {
255  13:         SEQUENCE {
257   3:           OBJECT IDENTIFIER givenName (2 5 4 42)
262   6:           UTF8String 'Hanako'
       :           }
       :         }
       :       }
270 118:     SEQUENCE {
272  16:       SEQUENCE {
274   7:         OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
283   5:         OBJECT IDENTIFIER secp384r1 (1 3 132 0 34)
       :         }
290  98:       BIT STRING
       :         04 5B 09 01 B8 85 23 29 6E B9 19 D5 0F FA 1A 9C
       :         B3 74 BC 4D 40 95 86 28 2B FE CA 11 B1 D9 5A DB
       :         B5 47 34 AF 57 0B F8 2B 72 28 CF 22 6B CF 4C 25
       :         DD BC FE 3B 1A 3A D3 94 30 EF F7 63 E1 D6 8D 2E
       :         15 1D 91 72 0B 77 95 B5 8D A6 B3 46 39 61 3A 8F
       :         B9 B5 A8 DA 48 C6 74 71 17 F9 91 9E 84 24 F3 7E
       :         C8
       :       }
390 426:     [3] {
394 422:       SEQUENCE {
398  12:         SEQUENCE {
400   3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
405   1:           BOOLEAN TRUE
408   2:           OCTET STRING, encapsulates {
410   0:             SEQUENCE {}
       :             }
       :           }
412  14:         SEQUENCE {
414   3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
419   1:           BOOLEAN TRUE
422   4:           OCTET STRING, encapsulates {
424   2:             BIT STRING 3 unused bits
       :               '10000'B (bit 4)
       :             }
       :           }
428  29:         SEQUENCE {
430   3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
435  22:           OCTET STRING, encapsulates {
437  20:             OCTET STRING
       :               0A E3 A0 FE 9D D4 25 76 98 B5 EB 72 EB CA 0C E7
       :               BF 3D F5 F1
       :             }
       :           }
459  31:         SEQUENCE {
461   3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
466  24:           OCTET STRING, encapsulates {
468  22:             SEQUENCE {
470  20:               [0]
       :                 8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
       :                 17 7D 9F BE
       :               }
       :             }
       :           }
492 324:         SEQUENCE {
496  10:           OBJECT IDENTIFIER '2 16 840 1 114027 80 6 1'
508 308:           OCTET STRING, encapsulates {
512 304:             SEQUENCE {
516  20:               INTEGER
       :                 35 FE 9A 5B 0F 76 7D AE 26 CB D0 71 6C 9A 9E DE
       :                 62 49 3A 5D
538  89:               SEQUENCE {
540  19:                 SEQUENCE {
542   7:                   OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
551   8:                   OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       :                   }
561  66:                 BIT STRING
       :                   04 42 25 48 F8 8F B7 82 FF B5 EC A3 74 44 52 C7
       :                   2A 1E 55 8F BD 6F 73 BE 5E 48 E9 32 32 CC 45 C5
       :                   B1 6C 4C D1 0C 4C B8 D5 B8 A1 71 39 E9 48 82 C8
       :                   99 25 72 99 34 25 F4 14 19 AB 7E 90 A4 2A 49 42
       :                   72
       :                 }
629  47:               [4] {
631  14:                 SEQUENCE {
633   3:                   OBJECT IDENTIFIER keyUsage (2 5 29 15)
638   1:                   BOOLEAN TRUE
641   4:                   OCTET STRING, encapsulates {
643   2:                     BIT STRING 7 unused bits
       :                       '1'B (bit 0)
       :                     }
       :                   }
647  29:                 SEQUENCE {
649   3:                   OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
654  22:                   OCTET STRING, encapsulates {
656  20:                     OCTET STRING
       :                       5B 70 A7 98 17 F7 9F F6 37 D2 F7 E3 DC 44 6C 21
       :                       09 D7 BB D4
       :                     }
       :                   }
       :                 }
678 139:               BIT STRING, encapsulates {
682 135:                 SEQUENCE {
685  65:                   INTEGER
       :                     76 32 73 9A 33 9E CF 60 5B CD F5 60 09 58 D6 6C
       :                     65 48 F6 B3 C9 68 16 07 80 B1 6A CD 0D D5 73 57
       :                     97 1A 17 98 FA 6E 1C 0B AA 17 98 32 A3 32 00 D6
       :                     A4 FF C6 2D 2A F2 AB DC 96 6F 28 25 4D 80 5F 61
       :                     A3
752  66:                   INTEGER
       :                     01 27 6A 87 C7 1E 72 ED 67 D2 ED C5 A3 0F 88 A7
       :                     7D 6A 84 64 74 7E C2 CF A3 4A 17 27 09 03 CB AB
       :                     D5 1F A7 38 D2 A8 11 FC 00 EE FB C0 46 85 66 23
       :                     28 80 8C 19 07 4D EB 1E B0 1E 53 2C 53 90 D6 96
       :                     97 6F
       :                   }
       :                 }
       :               }
       :             }
       :           }
       :         }
       :       }
       :     }
820  10:   SEQUENCE {
822   8:     OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :     }
832 140:   BIT STRING, encapsulates {
836 136:     SEQUENCE {
839  66:       INTEGER
       :         01 D2 2C 49 9F E5 03 D7 DA D3 27 60 83 1F 9A AF
       :         DF 0A DA D8 45 EF 1D 7F C4 63 AF D2 F5 8C 05 95
       :         05 86 9E 83 3B 91 32 49 22 1E 2C 71 23 8B 88 22
       :         99 D1 8F A3 9A ED 95 58 7B 91 32 0F 2D 53 26 43
       :         E6 50
907  66:       INTEGER
       :         01 D0 FD E2 6A E4 15 65 3D 54 97 E6 E2 59 A4 70
       :         5F 26 93 DB 2B ED BD 68 24 A9 44 AB F4 9C 10 EA
       :         D6 A5 FF D2 9E 4E 77 1C 8A 4C 3F DB E3 35 CE F6
       :         BB CB 16 0E 1F BC 6C E5 1A 49 32 0D CB 91 5C F4
       :         35 DD
       :       }
       :     }
       :   }

-----BEGIN CERTIFICATE-----
MIIDyzCCAyygAwIBAgIUe9k+9dMBWHpA+F1z8Kx+XguriBYwCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDUyNTIwMzUxOVoXDTI2MDUyMTIwMzUxOVowLzELMAkGA1UEBhMCWFgxDzAN
BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEWwkBuIUjKW65GdUP+hqcs3S8TUCVhigr/soRsdla27VHNK9XC/grcijP
ImvPTCXdvP47GjrTlDDv92Ph1o0uFR2Rcgt3lbWNprNGOWE6j7m1qNpIxnRxF/mR
noQk837Io4IBqjCCAaYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCAwgwHQYD
VR0OBBYEFArjoP6d1CV2mLXrcuvKDOe/PfXxMB8GA1UdIwQYMBaAFI7CFAlgduqQ
OOk5rhttUsQXfZ++MIIBRAYKYIZIAYb6a1AGAQSCATQwggEwAhQ1/ppbD3Z9ribL
0HFsmp7eYkk6XTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyj
dERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36Q
pCpJQnKkLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFtwp5gX95/2N9L349xE
bCEJ17vUA4GLADCBhwJBdjJzmjOez2BbzfVgCVjWbGVI9rPJaBYHgLFqzQ3Vc1eX
GheY+m4cC6oXmDKjMgDWpP/GLSryq9yWbyglTYBfYaMCQgEnaofHHnLtZ9LtxaMP
iKd9aoRkdH7Cz6NKFycJA8ur1R+nONKoEfwA7vvARoVmIyiAjBkHTesesB5TLFOQ
1paXbzAKBggqhkjOPQQDBAOBjAAwgYgCQgHSLEmf5QPX2tMnYIMfmq/fCtrYRe8d
f8Rjr9L1jAWVBYaegzuRMkkiHixxI4uIIpnRj6Oa7ZVYe5EyDy1TJkPmUAJCAdD9
4mrkFWU9VJfm4lmkcF8mk9sr7b1oJKlEq/ScEOrWpf/Snk53HIpMP9vjNc72u8sW
Dh+8bOUaSTINy5Fc9DXd
-----END CERTIFICATE-----

```

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

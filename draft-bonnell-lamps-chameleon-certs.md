---
title: "A Mechanism for Encoding Differences in Paired Certificates"
category: std

docname: draft-bonnell-lamps-chameleon-certs-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: Security
# workgroup: WG Working Group
keyword:
 - delta certificate
 - chameleon certificate
 - paired certificate
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME (lamps)"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "CBonnell/chameleon-certs"
  latest: "https://CBonnell.github.io/chameleon-certs/draft-bonnell-lamps-chameleon-certs.html"

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
method does not require any changes to the certification path validation
algorithm as described in RFC 5280. Additionally, this method
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
certificates adds complexity to certificate management for relying
parties and exposes limitations in applications and protocols that
support a single certificate chain. For this reason, it is useful to
efficiently convey information concerning the elements of two
certificates within a single certificate. This information can then be
used to construct the paired certificate as needed by relying parties.

This document specifies an X.509 v3 certificate extension that includes
sufficient information for a relying party to construct both paired
certificates with a single certificate. This
method does not require any changes to the certification path validation
algorithm as described in {{!RFC5280}}. Additionally, this method
does not violate the constraints of serial number
uniqueness for certificates issued by a single certification
authority.

In addition to the certificate extension, this document
specifies two PKCS #10 Certificate Signing Request attributes that can
be used by applicants to request Paired Certificates using a single
PKCS #10 Certificate Signing Request.

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
certificates to the same subject. For example, these certificates
generally contain the same (or substantially similar) identity
information and generally have identical validity periods. The
differences in certificate content generally stem from the certification
of different keys, where the named subject may have multiple keys of
different algorithms certified by separate certificates. The use of
different keys allows for the subject to use the key that is most
appropriate for a given operation and intended recipient. For example,
as part of an ongoing algorithm migration, it is useful to use stronger
algorithms when both of the systems utilized by the subscriber/sender
and recipient have been upgraded. However, in the case where systems
have not yet been updated, the use of a legacy key algorithm may be
required. Additionally, multiple certificates may be issued to the same
subject that certify keys for different purposes, such as one key for
signing and another key for encryption.

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

The inclusion of the DCD extension within a Base Certificate is not a
statement from the issuing Certification Authority of the Base
Certificate that the contents of the Delta Certificate have been
verified. Conversely, the DCD extension is merely a mechanism to
encode the differences between two Paired Certificates. Given this,
it is possible for the Base Certificate to expire prior to the Delta
Certificate, and vice versa. However, the policies governing a public
key infrastructure may add additional requirements for the content of
the DCD extension or alignment of validity periods for Base Certificates
and Delta Certificates. For example, a policy may require that the
validity periods of the Base Certificate and Delta Certificate be
identical, or that if the Delta Certificate is revoked, the Base
Certificate must also be revoked.

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
  signature             [0] IMPLICIT AlgorithmIdentifier
       {SIGNATURE_ALGORITHM, {...}} OPTIONAL,
  issuer                [1] IMPLICIT Name OPTIONAL,
  validity              [2] IMPLICIT Validity OPTIONAL,
  subject               [3] IMPLICIT Name OPTIONAL,
  subjectPublicKeyInfo  SubjectPublicKeyInfo,
  extensions            [4] IMPLICIT Extensions{CertExtensions}
       OPTIONAL,
  signatureValue        BIT STRING
}
~~~

The serialNumber field MUST be present and contain the
serial number of the Delta Certificate.

If present, the signature field specifies the signature algorithm used
by the issuing certification authority to sign the Delta Certificate.
If the signature field is absent, then the DER encoding of the value of
the signature field of the Base Certificate and Delta Certificate is
equal.

If present, the issuer field specifies the distinguished name of the
issuing certification authority which signed the Delta Certificate. If
the issuer field is absent, then the DER encoding of the distinguished
name of the issuing certification authority for both the Base
Certificate and Delta Certificate is the same.

If present, the validity field specifies the validity period of the
Delta Certificate. If the validity field is absent, then the validity
period of both the Base Certificate and Delta Certificate is the same.

If present, the subject field specifies the distinguished name of the
named subject as encoded in the Delta Certificate. If the
subject field is absent, then the DER encoding of the distinguished name
of the named subject for both the Base Certificate and Delta Certificate
is the same.

The subjectPublicKeyInfo field contains the public key
included in the Delta Certificate. The value of this field MUST differ
from the value of the subjectPublicKeyInfo field of the Base
Certificate. In other words, the Base Certificate and Delta Certificate
MUST certify different keys.

If present, the extensions field contains the extensions whose
criticality and/or value are different in the Delta Certificate compared
to the Base Certificate with the exception of the DCD extension itself.
If the extensions field is absent, then all extensions in the Delta
Certificate MUST have the same criticality and value as the Base
Certificate (except for the DCD extension, which MUST be absent from
the Delta Certificate). This field MUST NOT contain any extension types
which do not appear in the Base Certificate, and this field MUST NOT
contain any instance of the DCD extension (recursive Delta Certificates
are not permitted). Additionally, the Base Certificate SHALL NOT include
any extensions which are not included in the Delta Certificate, with the
exception of the DCD extension itself. Therefore, it is not possible to
add or remove extensions using the DCD extension. The ordering of
extensions in this field MUST be relative to the ordering of the
extensions as they are encoded in the Delta Certificate. Maintaining
this relative ordering ensures that the Delta Certificate's extensions
can be constructed with a single pass.

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
   replace the value of the signature field and the signatureAlgorithm
   field of the Delta Certificate template with the value of the DCD
   extension's signature field.
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
create Certificate Signing Requests for both Base and Delta
Certificates within a single PKCS #10 Certificate Signing Request. The
mechanism presented in this section need not be used exclusively by
requestors for the issuance of Paired Certificates; other mechanisms
(such as the submission of two Certificate Signing Requests, etc.) are
also acceptable. Additionally, this document does not place any
restriction on the amount of time that may elapse between the issuance
of a Delta Certificate and the request of a Base Certificate; such
restrictions should be defined by the policy of a particular public key
infrastructure.

The delta certificate request attribute is used to convey the requested
differences between the request for issuance of the Base Certificate
and the requested Delta Certificate. Similar to the semantics of
Certificate Signing Requests in general, the Certification Authority MAY
add, modify, or selectively ignore information conveyed in the attribute
when issuing the corresponding Delta Certificate.

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
  extensions            [1] IMPLICIT Extensions{CertExtensions}
       OPTIONAL,
  signatureAlgorithm    [2] IMPLICIT AlgorithmIdentifier
       {SIGNATURE_ALGORITHM, {...}} OPTIONAL
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

## Creating a Certificate Signing Request for Paired Certificates {#dcd-csr-create}

The following procedure is used by a certificate requestor to create a
combined Certificate Signing Request for Paired Certificates.

1. Create a CertificationRequestInfo containing the subject,
   subjectPKInfo, and attributes for the Base Certificate.
2. Create a delta certificate request attribute that specifies the
   requested differences between the to-be-issued Base Certificate and
   Delta Certificate requests.
3. Add the delta certificate request attribute that was created by step
   2 to the list of attributes in the CertificationRequestInfo.
4. Sign the CertificationRequestInfo using the private key of the delta
   certificate request subject.
5. Create a delta certificate request signature attribute that contains
   the signature value calculated by step 4.
6. Add the delta certificate request signature attribute that was
   created by step 5 to the list of attributes.
7. Sign the CertificationRequestInfo using the private key of the base
   certificate request subject.

## Verifying a Certificate Signing Request for Paired Certificates

The following procedure is used by a Certification Authority to verify
a Certificate Signing Request for Paired Certificates that was created
using the process outlined in {{dcd-csr-create}}.

1. Create a CertificationRequest template by copying the
   CertificationRequest submitted by the certificate requestor.
2. Verify the signature of the base certificate request using the
   public key associated with the base certificate request subject and
   the signature algorithm specified in the `signatureAlgorithm` field
   of the CertificationRequest template. If
   signature verification fails, then the Certification Authority MUST
   treat the Certificate Signing Request as invalid.
3. Remove the delta certificate request signature attribute from the
   CertificationRequest template.
4. Replace the value of the `signature` field of the
   CertificationRequest template with the value of the delta certificate
   request attribute that was removed in step 3.
5. Verify the signature of the delta certificate request using the
   public key associated with the delta certificate request subject.
   If the `signatureAlgorithm` field of the delta certificate request
   attribute is present, then the Certification Authority MUST perform
   signature verification using the algorithm specified in this field.
   Otherwise, the Certification Authority MUST perform signature
   verification using the algorithm specified in the
   `signatureAlgorithm` field of the CertificationRequest template. If
   signature verification fails, then the Certification Authority MUST
   treat the Certificate Signing Request as invalid.

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

The following ASN.1 {{X.680}} module provides the complete definition of
the extensions, attributes, and associated identifiers specified in this
document.

~~~

DeltaCertificateDescriptor { iso(1) identified-organization(3) dod(6)
  internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
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

  CertificateSerialNumber, Name, Validity, SubjectPublicKeyInfo,
  CertExtensions FROM PKIX1Explicit-2009  -- RFC 5912
  { iso(1) identified-organization(3) dod(6) internet(1) security(5)
    mechanisms(5) pkix(7) id-mod(0) id-mod-pkix1-explicit-02(51) };

-- Temporary OID arc --

id-temporaryArc OBJECT IDENTIFIER ::= {
  joint-iso-itu-t(2) country(16) us(840) organization(1)
  entrust(114027) 80 6
}

-- Extension --

id-ce-deltaCertificateDescriptor OBJECT IDENTIFIER ::= {
       id-temporaryArc 1 }

DeltaCertificateDescriptor ::= SEQUENCE {
  serialNumber          CertificateSerialNumber,
  signature             [0] IMPLICIT AlgorithmIdentifier
       {SIGNATURE_ALGORITHM, {...}} OPTIONAL,
  issuer                [1] IMPLICIT Name OPTIONAL,
  validity              [2] IMPLICIT Validity OPTIONAL,
  subject               [3] IMPLICIT Name OPTIONAL,
  subjectPublicKeyInfo  SubjectPublicKeyInfo,
  extensions            [4] IMPLICIT Extensions{CertExtensions}
       OPTIONAL,
  signatureValue        BIT STRING
}

ext-deltaCertificateDescriptor EXTENSION ::= {
  SYNTAX DeltaCertificateDescriptor
  IDENTIFIED BY id-ce-deltaCertificateDescriptor
  CRITICALITY { FALSE }
}

-- Request Attributes --

id-at-deltaCertificateRequest OBJECT IDENTIFIER ::= {
       id-temporaryArc 2 }

DeltaCertificateRequestValue ::= SEQUENCE {
  subject               [0] IMPLICIT Name OPTIONAL,
  subjectPKInfo         SubjectPublicKeyInfo,
  extensions            [1] IMPLICIT Extensions{CertExtensions}
       OPTIONAL,
  signatureAlgorithm    [2] IMPLICIT AlgorithmIdentifier
       {SIGNATURE_ALGORITHM, {...}} OPTIONAL
}

DeltaCertificateRequest ::= ATTRIBUTE {
   WITH SYNTAX DeltaCertificateRequestValue
   SINGLE VALUE TRUE
   ID id-at-deltaCertificateRequest
}

id-at-deltaCertificateRequestSignature OBJECT IDENTIFIER ::= {
       id-temporaryArc 3 }

DeltaCertificateRequestSignatureValue ::= BIT STRING

DeltaCertificateRequestSignature ::= ATTRIBUTE {
   WITH SYNTAX DeltaCertificateRequestSignatureValue
   SINGLE VALUE TRUE
   ID id-at-deltaCertificateRequestSignature
}

END

~~~

# Examples

This appendix includes some example certificates which demonstrate the
use of the mechanism specified in this document. Two use cases of this
mechanism are demonstrated: algorithm migration and dual use. The PEM
text and dumpasn1 output for each certificate is provided.

## Root certificates

The two certificates in this section represent the two root
Certification Authorities which issue the end-entity certificates in the
following section.

### EC P-521 root certificate

This is the EC root certificate.

~~~
-----BEGIN CERTIFICATE-----
MIIDBTCCAmagAwIBAgIUdZEeu4lEPANMQ4Ut/Odnc431EMQwCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDUyNjEzMDYzMVoXDTMzMDUxMzEzMDYzMVowgYsxCzAJBgNVBAYTAlhYMTUw
MwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVj
dHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVu
dDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMIGbMBAGByqGSM49AgEGBSuBBAAj
A4GGAAQB0P1yV6hMdH9WJXXAc4Xb6/L1K+pYCD24L90VMdiq48yHX/Av9/otomDY
62LW0vXWSSeOMhc2oGKMu7MDCLbmGNsA9irSBMZGA1m8gYq4lhvw8PwOxaropCgX
POVvAN6bFXweXILGT1Yvyt78Skwo9tNCzz72FvyC0ztyhckh8r82/dijYzBhMA8G
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSOwhQJYHbq
kDjpOa4bbVLEF32fvjAfBgNVHSMEGDAWgBSOwhQJYHbqkDjpOa4bbVLEF32fvjAK
BggqhkjOPQQDBAOBjAAwgYgCQgHivbIinPYg05GqnJiiTbYk99oBusIPryKeUWmn
7hpiVek+2rvyThgb38HPWSAVYKzzdr+U37O9RB1jdnYwdU60fAJCAL7faPjE9OvK
Vo2Hnfup6J7p0RD0n+8YAc1yYJwXN30We1fxwk1DkUG4SD5P5tIJL/cPogHmmaZM
GgzGspA2nRph
-----END CERTIFICATE-----

~~~

~~~
  0 773: SEQUENCE {
  4 614:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13  20:     INTEGER 75 91 1E BB 89 44 3C 03 4C 43 85 2D FC E7 67 73 8D F5 10 C4
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
191  13:       UTCTime 26/05/2023 13:06:31 GMT
206  13:       UTCTime 13/05/2033 13:06:31 GMT
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
       :         01 E2 BD B2 22 9C F6 20 D3 91 AA 9C 98 A2 4D B6
       :         24 F7 DA 01 BA C2 0F AF 22 9E 51 69 A7 EE 1A 62
       :         55 E9 3E DA BB F2 4E 18 1B DF C1 CF 59 20 15 60
       :         AC F3 76 BF 94 DF B3 BD 44 1D 63 76 76 30 75 4E
       :         B4 7C
709  66:       INTEGER
       :         00 BE DF 68 F8 C4 F4 EB CA 56 8D 87 9D FB A9 E8
       :         9E E9 D1 10 F4 9F EF 18 01 CD 72 60 9C 17 37 7D
       :         16 7B 57 F1 C2 4D 43 91 41 B8 48 3E 4F E6 D2 09
       :         2F F7 0F A2 01 E6 99 A6 4C 1A 0C C6 B2 90 36 9D
       :         1A 61
       :       }
       :     }
       :   }

~~~

### Dilithium root certificate

This is the Dilithium root certificate. It contains a Delta Certificate
Descriptor extension which includes sufficient information to recreate
the ECDSA P-521 root.

~~~
-----BEGIN CERTIFICATE-----
MIIZTzCCDFqgAwIBAgIUZnCGGMVMAm3yS76tvDlbOa45t5QwDQYLKwYBBAECggsH
BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg
UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1
bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg
LSBHMTAeFw0yMzA1MjYxMzA2MzFaFw0zMzA1MTMxMzA2MzFaMIGPMQswCQYDVQQG
EwJYWDE1MDMGA1UECgwsUm95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5m
cmFzdHJ1Y3R1cmUxKzApBgNVBAsMIlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERl
cGFydG1lbnQxHDAaBgNVBAMME0RpbGl0aGl1bSBSb290IC0gRzEwgge0MA0GCysG
AQQBAoILBwYFA4IHoQB7StC53PkXiBLhRp0ZAuHNjkOkiU8vd5eh4KH1qiLLRda3
hXUGT1aOLXGNaQqA4h0e8tH9ysN8grz142/KnfypTitm/QVCAIqnWMlFy5B5sQX1
lSVYwYRhDXkyickuinqBc/PvRH0MI/pcsh0wawZCZJFItMnVSkBqv0SJJEQVkVoB
Whrvvl1Y0iwBpbXayNNhUX1mytXi+bFGeDsMKtWzMc1Lz36h9Wg67Ybu4VAbg9YA
1zcUrRLHihxlX8qG1yWy0r2V62zx4HprCK3vBRMNm/XnXKZfv++bIUaok9CP1IKK
SFNa0/YIZaEwd22dPlJnUxe8C2q59CsUZlOUWApQDwG72IraDX2u0vDx6DaOWGm4
UjmutRTng60q4TOTxaaMwXr3+QLUHNGmy5QnG4oci/MhgjvJlJc2BhhlgMF39Tg9
Z0Om8FGvrc6Z9FGjfyPp9aDW8IDmMeqwYAtaeWLq0IKCWgsoO3kAb8ZAmsfz27Aa
VLRp29nqMYy7nniQMv7BTube2MjvSOl5X5AXFbQD6SkrfT3BZ6+QREVvTEt4GRzq
NE75TtFX1M+BuXgi8h1LPuCQYa6jk/vGMUfo0NxRLCm8qyU7lA9JUM4hEHWIOREk
d9FAGwQMjU+utgfnEPnSrWy3aChQdErJiCnW7tof71PgO9HLjxEgmxjLdWP7RsPm
2QK7+5lhZIVPZIH64TzgXfjO33SHKWgi2nhrs33VY9k4SbEysrrICltYcVprELNT
1YZGBhE/tbpGOXL1RTlL2HPRyw3eNo/nlaB6yu5neZoJXMTX1f9V911Iuh6mU+G8
eTYap9nV+w6wH6F0TngLPdF86eEaXXOXDCCJpSggjSN2E575sx5dqnDQAlOVEn6R
1vQqEQYEOdU/f4WM76APNz1MMzoWkE5JViZIQPQF83yxro8sezSk/q74hBfa/q22
gNwjjdOTkS0NZl1lYjFVQbTdSie9dHoehRya3zbkVdJrK3/qiN3K2CWsjNJhrQi3
qQmngUoMB9Lp14WqAJ8P9dmDPvKOBpgsph7GYzwTWWnep9O3sVEuTwedCJ7ctVW/
hN1IeKpZ/ffsn2mbQTPA/qccf6zE9W357ZZAdYEtmggPPnGEeQqQT+75ynJaHhHu
ue4nTa9PetkFST5O1OH7Ba4pVcGSDL62A+4lIk7HE3HvIxeAUJIHBMYOJcZeilTS
TL2kIrVEl4yPRR/0XVADCaX6MUmv0skPnDVbDcVTEEtw6JWMlTYQJtCUiLg11Yvd
Qu7oddra1H5V62QCNNEoJGxOk5sBJZtrgokAPanrdKHELqk9RAq52sGvZZQZNXZL
SghWTBB/nsfJU40Z7R7zmMZJH5WbbaI9i0D6qdcCi3v/O89Z53pXAdKjMng97XON
Z/oVv+Q5Cdr6kRbuISPryxiV5qNiWc/8i1oVKDP/wpCmKZRB/wYP5oKx+RIJx3KS
eHk02ftgtYsRXC02aNuSNkFcJ8kVm3qZ1Aac8c+qKgbM1xcLPbdPocs/CjNCX64X
nZmgiSP7a0tktid9NC5Ynm/9txKAO6rl9PRhDmGqf9JZa9JNUETV2raZ/wuf7lNh
KK1oCjMJ626yerhk5bS0QOD5siSRksIfa86PWdMUj3glDV2GtKh/ARSEzy734DFV
37anyZFmAW8IOWQvoeo2BgB7e90Dmxt9F8fp2iqPgCkbqW7dOuAC/tN787wwQikY
p/tUFn2wsFHhrfOzbp28ImAtC38Hgdc2/XntMnIoJ/6OMWQSv1r+khgnUDNsuVNN
84a7ShW/T8k1LsOY8EUotvfELqkjm78ggEfuMt3Wwtehes3vm7THfhBOsO1i64j5
hsasi4vRGo76EwT0szOoObIuXRKC1tDxrpuSqnyzrEY2Blh7P3sWTRO8i3t+nUNr
nGS6ea4CCdOuI3CpJimxzwg1Ec1TZmn2LiaPFwo5AZ2BxAEFiUxXQC3ugE3csEai
DA2RKtndyx2tKXgHFs2mAKeqcdlxoAxbYrJ+dM7kPUAqZVZyGXA7PcZ+NWN+xEZu
a4bctTwAa0hyc5zCX4dbxEceh/MruT6pPCiX/EehAjeuFtr/grRkP0Ro/1UiDSKr
s0xBtdWbiUOGBpxleEg8V3h9gIv15ofH4F92/dnopD4r+TOcaEW9wCELi9iQTGYl
2bOBgBqV3YCdb2xCcA1AljUTPTttBg/DVKJh31/SOj50MrjSQlCsjrsPlmmPA5Lj
bs8SVTlRMBdueA9fwsq2aN4dRW4j7OMRbh6UpDUXoFwlutqVGu+r1O1SR3otVxja
oPJHr4gKbYHFqa5G9VEkMtCazyE7uc5xAzQh3E+aP9DhrFZRieEQd2ftgQVotJFU
CiCTHgqX4Ggkum2j2Z6gOV953FAZMmlVM4BaQgWu6Dzd6VMPoAaC5jtBOM/siZ42
x2ESbHYtBZGtWpW3TLnm1/0zeLez7BRO4xyFjuizTb93tmxQlX+GV0L8ddL8pAMk
MTm58+d98Rn+hKuZojwaMBFLlzeNgN5CtUXYZ8LEwaMBb28DhiQVC3zw4jVnTpGS
8sMkqYYIdIU2QelWtIJ/adsAarOPG/7JwBhko4C3o82WpReEHKh314w1VjgT6qOC
AzAwggMsMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW
BBQR2SgXC+AqR80zlzW3DistnJRMSjAfBgNVHSMEGDAWgBQR2SgXC+AqR80zlzW3
DistnJRMSjCCAscGCmCGSAGG+mtQBgEEggK3MIICswIUdZEeu4lEPANMQ4Ut/Odn
c431EMSgCgYIKoZIzj0EAwShgY4wgYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxS
b3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkG
A1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UE
AwwPRUNEU0EgUm9vdCAtIEcxo4GOMIGLMQswCQYDVQQGEwJYWDE1MDMGA1UECgws
Um95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5mcmFzdHJ1Y3R1cmUxKzAp
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
GyUp
-----END CERTIFICATE-----

~~~

~~~
   0 6479: SEQUENCE {
   4 3162:   SEQUENCE {
   8    3:     [0] {
  10    1:       INTEGER 2
         :       }
  13   20:     INTEGER 66 70 86 18 C5 4C 02 6D F2 4B BE AD BC 39 5B 39 AE 39 B7 94
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
 198   13:       UTCTime 26/05/2023 13:06:31 GMT
 213   13:       UTCTime 13/05/2033 13:06:31 GMT
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
         :         7B 4A D0 B9 DC F9 17 88 12 E1 46 9D 19 02 E1 CD
         :         8E 43 A4 89 4F 2F 77 97 A1 E0 A1 F5 AA 22 CB 45
         :         D6 B7 85 75 06 4F 56 8E 2D 71 8D 69 0A 80 E2 1D
         :         1E F2 D1 FD CA C3 7C 82 BC F5 E3 6F CA 9D FC A9
         :         4E 2B 66 FD 05 42 00 8A A7 58 C9 45 CB 90 79 B1
         :         05 F5 95 25 58 C1 84 61 0D 79 32 89 C9 2E 8A 7A
         :         81 73 F3 EF 44 7D 0C 23 FA 5C B2 1D 30 6B 06 42
         :         64 91 48 B4 C9 D5 4A 40 6A BF 44 89 24 44 15 91
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
         :               11 D9 28 17 0B E0 2A 47 CD 33 97 35 B7 0E 2B 2D
         :               9C 94 4C 4A
         :             }
         :           }
2422   31:         SEQUENCE {
2424    3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
2429   24:           OCTET STRING, encapsulates {
2431   22:             SEQUENCE {
2433   20:               [0]
         :                 11 D9 28 17 0B E0 2A 47 CD 33 97 35 B7 0E 2B 2D
         :                 9C 94 4C 4A
         :               }
         :             }
         :           }
2455  711:         SEQUENCE {
2459   10:           OBJECT IDENTIFIER
         :             deltaCertificateDescriptor (2 16 840 1 114027 80 6 1)
2471  695:           OCTET STRING, encapsulates {
2475  691:             SEQUENCE {
2479   20:               INTEGER
         :                 75 91 1E BB 89 44 3C 03 4C 43 85 2D FC E7 67 73
         :                 8D F5 10 C4
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
         :                     01 E2 BD B2 22 9C F6 20 D3 91 AA 9C 98 A2 4D B6
         :                     24 F7 DA 01 BA C2 0F AF 22 9E 51 69 A7 EE 1A 62
         :                     55 E9 3E DA BB F2 4E 18 1B DF C1 CF 59 20 15 60
         :                     AC F3 76 BF 94 DF B3 BD 44 1D 63 76 76 30 75 4E
         :                     B4 7C
3102   66:                   INTEGER
         :                     00 BE DF 68 F8 C4 F4 EB CA 56 8D 87 9D FB A9 E8
         :                     9E E9 D1 10 F4 9F EF 18 01 CD 72 60 9C 17 37 7D
         :                     16 7B 57 F1 C2 4D 43 91 41 B8 48 3E 4F E6 D2 09
         :                     2F F7 0F A2 01 E6 99 A6 4C 1A 0C C6 B2 90 36 9D
         :                     1A 61
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
         :     63 48 4B DD 18 24 F0 A7 B9 7B E8 69 BE 80 40 18
         :     C2 B3 95 1C 3D 23 AA AA 81 3C A6 91 B3 E2 A0 B9
         :     D1 E8 D6 B8 9A 52 EE 59 D7 C9 CB 80 B7 B0 89 5A
         :     44 21 4D E1 75 88 FE 47 4F 66 9E 52 69 52 F7 DE
         :     36 C8 7D 3E 1C 32 C1 29 E2 A3 6B BA 86 E6 33 A4
         :     9C 2B 6C FB 8D 48 DD 14 F4 59 C2 B8 34 F6 7D 45
         :     83 AD 13 21 75 CD FB F5 24 F9 FA 49 64 81 89 C3
         :     C3 5C D5 21 D2 DC 83 E2 12 FD 32 DD 31 AF 0F 92
         :             [ Another 3165 bytes skipped ]
         :   }

~~~

## Algorithm migration example

### Dilithium signing end-entity certificate

This is an end-entity signing certificate which certifies a Dilithium
key.

~~~
-----BEGIN CERTIFICATE-----
MIIWHDCCCSegAwIBAgIUC3I3HCAo5RSH45s1sH6CS+5eAd4wDQYLKwYBBAECggsH
BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg
UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1
bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg
LSBHMTAeFw0yMzA1MjYxMzA2MzFaFw0yNjA1MjIxMzA2MzFaMC8xCzAJBgNVBAYT
AlhYMQ8wDQYDVQQEDAZZYW1hZGExDzANBgNVBCoMBkhhbmFrbzCCB7QwDQYLKwYB
BAECggsHBgUDggehAGyPSbiYL9NxlDxjNk1v5p/BQmedaYkenir6NNWBIcZ2GDKT
mnC1ZUZ5v6BirMUlAYu+2AtSzDPeLRVpebmN86TGhVSifeERcv5Ohb0Ms0Cpnvqv
3ZE93D74fdyYn7uyiyFiLmdI8uPElHiLLuuS6YClGqZitt82FKaSlP5CmOm8qt+8
JQ+oZ/zCkJOVHOfAKgjz3klNxK0vBcHVOLx02ciHNnCqCUU+wvt2R7rkm5oOqlGq
jvRiofYOC7saMEtx4WKrTq7VcGPCIZQFIkietxVRqH+X+UAppPTfk2DcoO96kKk+
BbGKJiJ1fR0tyUtkaPSFRGp54KOTw6t0ZbgiAXSNPzJ8uCPwFPW0vJWYZMGPSRkX
oTEHlGkEvlo4nUBCvHxa4i7UB/gmY9rCYWE3/eNJ7gyS7+RNNHa2e7y1MuMT2OpZ
4vV+Hlj35arvXyflFNmRgq7QU5ed0Bp7G0+iodgF8w06pAp1GR6xD3UWHu82b9HR
pMo1sv1JdVmY7u6yKLGFyCU8Ap9S7WkfkDwQXzWmo/BGf4cLFHHTV8cy6jKPUhf+
gQgNjozs4P3HF+DJYQ1xkGKIs0enmIb0IKa3z/Hzz70hUSNtE2tZdh0Z32u5lnwg
omSEJXBpI5tLjfqJeGB6yXG70gY+TPAVtmzuPyiQkSq2lh/ZGxRZf0YmLQj8KX8/
581kF1WEODGDaY4slXji5MHCWKk5jXv7d9GjmNeeRaoya7dD5BQII0rlv7pIcb1v
PWsKNakYCnybhjaqnmEGJX1cj9/i67Tsho3e9X5GbTL1TgjgQWkGaCj6dNy3s2BD
GrfUXfsLxlMSNXHjnNcXASVxYx6Eandk6mOrj5ULHSGE+VKBu8BdriXddXsNnbvd
yUi6rNE4G8mr9Bxs54wcG7wPzYAJzyTbwwDbNn6GrPPcsuYdevMfg04IqPtDTotD
9NeJk105PqE0fcfK+MeR48fjAr/58qZiHLwpXgMY92ZsCsU8Je1AH0oB3FH2z/mY
24UK6l75mbpOcoRvw102WlMJ4yz5wNX9QlbT1a9pdAya9BBI/r7K4YK7sBPf2R5Q
Rr/8/CcwsneGDemkuDybeglHYHGE0dtqjMSJHxwrGKFmDzMO/mZ7D4N/Wa6OUGzO
fIDV634opSvw29/8M22IfAhQcqrZ0Cdo1vRtMOIFZX9TzZ7DdbPWHrhKwK0cz7ll
mwwrKX98ZGfnoUEYT2mRqubWVkVQzwOjhS+isIoOOL6ZjYjJeC14r1C4h6hERNyx
zOJXlUnm9p6lhJDEuilT0EswzHXUEhBHUUFP8ZUyw01KOq+xJGq+5/So44OVMK3e
B76fE8OFndNfGDvkVaBx9yotk1ryc1pweLSoFhsIyNNMEOnMr0qtiG4fDujaFZNW
ucpTgQzBChietFdRORUZHJoOQJK7tv7jBVjswnqHfh/oEXEECksO0UgjccIo8HMc
FpXMY5Y9uFbSdjHsXgBFDUMZBZ7y95Jwtzn/Q1iZaArhmNvOxRwAwaBCYoSB2uqE
ba/6LEX6onE//5MwwhaQL9Wa94npbQgLs8bGdfW08G/TuVuw+Jf/QB6z4r3D55ck
nH01q8YkAD3FZulDbekVBmrxX9+StRCf4Tqn2RZl86C9PhcIL6EuVvigqQvl4gAO
7rjz8lolGFb7nn8dl3b1XRXZ6dppgLFHQ4xsJ4DOmqfcleolv2Xe2lS72TcNa61D
m9mOPU+XCCaBOHhDYbY7q6dA2nytMtLI5zSkyL6sQPyYExLe8xD3G/2iZNcxpBdb
zQ+eewOPRpQV2AxV75l2KUQYC+kakMeTHbeb8r56AStNZgmf8DlljGyDRJAzzDMW
UWBv6OKPESPlsxnSxnT2ufnGUGBrEEMt/VIP9ZjVQ3+whl9DLXH+DjdoXPeMhZpS
eTyoAqo1QCEgZdZz0VvTH4gZF5qEVleyMw/PeuGqNC/uoRPh8e77dfQ49CYBwjB4
cn/TmCniK8X2z+ywaLy3U+S4MOUTYPK2EloAY2/QByaUmixHw1MwM3yVlhq/7nOK
yC2uP8QZ2faIWNMcm6XROdSrqRx4LWnA61ZRBvxoAEDMHat/1BQm90Ri8XyOpQCL
zwv7SDZ3888lss0Tgjs5bzPr7gP/XzMHx/vKTNeCi9hmTFTwcbNNhORNpCnpGdSf
lB5LIAMfTEg2F8ExTQV4YCVZMxhn8bR+9bGPci0uVsOMD5liK3lsAGMY3jShBO12
D2RAlL14PrSLHCitlo/LnO2eykefITZkHrtdZaFIJshULFSgw12sae7pZKqz6f67
jW9I29zNZW/TQrUmHz8/6SA5VIDs39DjQ7iK3nrY4iaz94WsuGE6i8/oUnntx0xq
GyZEpjvCYhrYuT7XGv3sopP8a4tZ0rkY+vH95V7mlF0fnDu1HC2kPTmmx9o3YzeX
rNN1mGemrbRqqd5fW50BkX0A2X6E70SsQbxd0CjUVgMPBEuE0laXVpuGQ+nJGSFz
l8nc35lLDZrqgibk6Mfjcb3rCfzXHiYaIGcn3Nm+uqYrxk5rfvCCchsdxMisIeRg
A6WLClKxwqn321Rwo0UhVv5V2Pm3H0pWL0AjJaNLp9YSL3UcdAOd9wWZ9ckyo2Aw
XjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUo1/qtvrL
Y4E91ZQfqEEt8JbbulswHwYDVR0jBBgwFoAUEdkoFwvgKkfNM5c1tw4rLZyUTEow
DQYLKwYBBAECggsHBgUDggzeAHQdgMbQJgbhfxy4mToCwDKa9HVxpfiurORIDe93
l2pqy66/N736aLSsN9NBehCf+ZcaFpAySD6ObKNJVsPYyF1YeaQTvqtGA9GFkmQn
BF63XsZlzgrUn1Caug8rNWd1LJhRm+IZfmcIN6vEBZlQpJGXjM9v8kNFzXdsun+U
91emmoul5sJY4zIoTEOhRHjcH5oJ4EyddoU+hvPLp/W0sKp5wlgu+S/OBp0HY3Xk
SC0VGb+XcXqXE0HblEHVFyx9PyFz9ANWkjgtvlCoecSGwGREhMh+8P1s29Rfn5PZ
P43AojO8w4+b/TArqB6V1T0eHsVKgvqgYFu/bTHpijkg9InM1/VkUP0etsEQh4gO
pSsHlE2CBnBPCyAbT1F2vEq828MI9aBW5XVqeLf1KICZFLdt1fXDTOeaekUY4coF
di29yg3cYOZ4RzECeyV+k9i1z9r7XjzbvS9IvEPC/ygf64iGcJFvI1yPyO3TBIoh
xWgtQeQqMgF153kh7OjSnX0ONcvSglDWy95y/qCnK7hE562QJY2WZkLAH9QYtg2c
kvaxjgzKJII19OLNny1AeqcN3KKPFud9hh66NG68ccRnKBpyTTOuG2FySxCuOzpg
APoXRyq26LOsjTmt3FO/gUVd6qPW8CCQOhaKLEtVAvn1FEvXUH539AfyqNupruQQ
fZ+rq4kjWhMUM0sL8gw3g52CMtUbF3bW0PfmzE092GU+VeB2K0ZIlVp74vRqh7kh
Z5Jm7XKdFamY2nUBcxSMGISe1qOfJeWersaLaLmFYhN+hNfCA4T6PtDIis324LLJ
1+eW8ztzzoZHFJFp4DYIHzc+wkvj5vkl4XMRyfDI0FuEN+wmvOh+r6haon2djaGP
MltYrK2ZDgDpe1DxB9TuZNiQYonCwaNS4re3Vg4stitV3kG5BfvfV6M9vZZ8MALV
7dNRk8RKD8iVM/NbG5PgzIsumK784YcyF6NReUvKCBDhCx1n1NUArWkBiCIXZj+I
Aio4fUGVJqmay8ccw0hH9QWfJ0EdcEjSeJrIIMXrpG8DesDjwaqLFGrdE4INmRDo
HGF3yQTLesinsPJsOR0nLAdyKAmkemog8UUXSKAvDXUqvWKfjx+zkAjqFurrPXRQ
3ljHntn/gq2hyrxZwtbQiUThix0ePqAWD2u/DQKMJXm1WcwwXbW83cnKs3WI2S1n
NSm0/RI2nF1OFcRQxXEVufm+CM77PIUDmfkYpmTJbrIK21GTAFqg8javxVwPvlj8
LmMBxnTVrtUviEhN/dTq8Jlyaht7vpmrL3q9cQ50Q1gJr5SGU1ry865M+Pt2hme/
pr6qNwUlZclvpiHCvXszWcocCorBceERVngnYPajee56n9IU+1Yv9NfN8X8odjxN
Vm/20l6pG10X+jmET7a54oH0dnoqfVqJ1UIdjza7DqzmF5p/it4aJsRB8pfP4JUF
aiS3pedU1XbhvTN1WDhFEK6ZcoF4EPD23IJU2MtgsGapmkbp8Ki/j64sCN6K8Hfm
vgcJr9g6KsidjkeI/mu8cFJvyDIlM2j0H7cJEL769x/EQUBZWMyRw9uQr9CaUQKe
iCZYrIeJfIf0h+xRm2c/nv7Ph7pM7oG7HspoU8Z2ltV40YgF4Qk34I5PF31Cxaea
ClkNuw4tdUDGub/dxtTCXl53NBX4PrPVrtSzxJWVRfm9BCn/ms4XboOcIHV6t/+9
L/i+v+3ujTUtd+pb6EjyoXehs5UapUfsrV2aQrcmrPHKYjT54KZHoyQKRa+kip77
JbBJudChTOsNZX1QWbrSyfl9Nthg7djhTPo604oTT/jJRL9kB/M0m0dimVKIaqed
eGlxwDZgP7NF4fTYIydgPZK1TzLbgG0DusrVX1i6QerbosSfGwZ3UAArx4Ty4j0P
zWE6SDOpuwleF5t5S010KdaGYw9B7IgC8gQXb4YkuqY9KgtISXImjn8rmTbUvlER
sokbajbph1ClpbxSvLVPANzwG8xexibHjFaxA3dEG896gmeaSYeIv9NWpRnRjzwx
111v83mjgHgVwdSlO+8/GpS5gyakrY89GOD3LWfSEPot50YCZZu6ET1P/nkC8hUp
49vrd6VnMnCGNf9IqaAzalq94kEJWoJLbNdLRYow+cuecYdOO2Ofyp/thmrIHAmL
k2qsTDqxr9tzWErI/Y+4bhOykGVjyx1CBlIXc4FOO2aKM4jw9R9toz5o6WoxgFHQ
pggL9gkfYprzdhiRYkTzYloWIzL+rxlmRC4Fnv7EbSqprDN01G123oUMJPJ14qQs
ZD7R9FkbojVlusHFAzgizrSauUSG6aoeXdLiXL2m+DpZ8/t9asZcaDwI4tqX1hGB
InKbomoHA1L/w7gNN/Uyozr9xgJ3KsQ88m03GlU2X/MJxJyJqqxkJQaluZJqKZSl
ETa2moaJvFcm7j1z3R7FzLd6ieRvvdA2RzeWxEBnnHv9jLrqKeGbOfgDaNd1brw8
92K0uGwlasSH4Myxii2A/p9IAVE+g7AosD8BYFqtlbdQEA9Ps4Jx04cNfXOXdeWs
2Silq9VDZNQ4atmUa17RVbAuvha4XjFnsCovWqaDZzmyY7b/eVoCWRL5ETuXNNJ/
6e4Ryhg2KbHksksWRjJmjhG/k5JRm2UfIaLHj5lFdgMwOF4+hPZ5jnq9nKpGXJj1
csuiwvQASBZtix2/UOALqOQg6UnHGFdhTXA8RG9Z+8AnK4nQJ1wyPLMgMu3w8IKJ
EPYENRHnOj2Qw3k/nAgBYcvf/Jnzsv8ZaHzNrmSvma91OieCYj2jjPfWKgweJkyf
/c8pIp5qHgTtohlmak8D+v9mj18M8ZNpqBJ8lY0OdVyWMhvmA4o4xXkylE+p4DxU
4vmDLb/dkn1r6cFhuzS33uc/YghWel5j+GAEviKsez5lw5tx/HrdxnRVGqfhlqUB
Q1kPvMLkR/1GlzUnrBm3viXiKwRau82IbaUUSu6pTUNy8ghe2JI0v9Hsgx2bBLBf
X1umQ9daffsFFI9CHEyscpPe3WPcRRSJVGvVVMSnCkTA105CCZDRWLDNkgKzpE8O
XzoRXkVICH3ZI8YW/Rub/z3pVS9ZPuxXyM1JCeCr/8AMSBG5lrWSYXTb1WV/j9Aq
uNrtZlYWkOzmjnSiTZgfGGVvT+9wOG2dcjnsp2qDsu/8vOAoyNpTdDlSEVjtfVPX
AueyD6//RSJFgqlT8DDS60t8QdxOZm4Hb+SYv4rLGZ/N0Wcg7w29tXXiwqQAcRYI
ypXuvy8SHHXkVcxwhwDEBDllBAe0822agCX9CqQW8KSLbfIyZTABUz85kZs1eBwr
bOEY3Xzqf+vUKfEjTiP97AA9Lq01kBdKqJboBzwWJEOY5WIHeS+NjMo0j6GfiuoK
zEBcJtdYhb4y0gqNEZZZZzikcQjS0Gkql34SZiZQPJ7fmD7G/XaaYKcQrGdpJXSX
S6rQZvkedK2h0T3BcYi7nhjsiR6soyxVZz5UHFb88ybY3KEJQQ+6j2MNg/rKXr27
OeUSmBtzpDpaArrTgrnVO7dAiW9bEFEoQv0kzhb2Gu3dI+Ku0LQ7yzTnET1K6QiW
nFypfw6ohXlvHA0R3DYfzhEHvHgT5FxvFZJfWMrSM9NhFsdI9MYl73JdMXpVV0jH
pFOPedD2KNp/4CPpb0Pptnz8uqhe9XhFBiT8Jvt3W8ZCYXj1zY5X7uDOgRhkufml
f+Zxw/f+R1lXuZWGMSvR8PfDv8deb1vUeZWJNRKELeCdfE8ykJbQ6cHXNRRDvd2J
BfFbRsufpnUuq6iQRjYUm4CD7FonFbxlu3rM/Q5dIRoZfu2G8wuiTCbGBGBuxFw4
BEpuoYRE5nus5XDMxZzTnnoMPO/viR0VJp9GBL10+otiVZCak+g5l9BPVboUOTCH
4AcYdVQv2tmusA0A5oC2K88dzraQtCrK21vRTwSmfVWVatNEATtbMlYKT6lUbDEU
/zeaqbTKjjwlZgvZMoCDtdrZZx9qn4Vc5sJq2Ytys1p1yYIT7k13MomTeCQTqvR8
KTN/5fNy+CxqCgVEvB1VqKzCeeAXY3Q4Xpd7I+DSlv0J6fcKhqQeRWWi6ybSo/vM
uDcK0tdBHk1yzU8ctA8jrPOiMBhDTgUJ1QI8ZvU5g0ZI4UTk8u0JXHSZxxeZKD/9
PepYosw6QhBqESn/AjQNF7s4VIUGXaWcKmVl0Ie1i63z0wrwCC44USIiPvkxFJS1
KJsohqJs5O0IeUGPOGdUsUfJoytIz7d5hMkuJ4fIqhHkFjvYBvUPwx9XsUay/9Ha
uX999JOpGGBLIz2Bv3BfNZksdYwh0u2vngoMtHuDpqwhO0gHDBkiOz9caW2TrMnT
CxUZH1pqqK4KFj1fY2mv9RooO2OVmxIYGzhFj56go8IbRpWlztcAAAAADRUdIy0z
-----END CERTIFICATE-----

~~~

~~~
   0 5660: SEQUENCE {
   4 2343:   SEQUENCE {
   8    3:     [0] {
  10    1:       INTEGER 2
         :       }
  13   20:     INTEGER 0B 72 37 1C 20 28 E5 14 87 E3 9B 35 B0 7E 82 4B EE 5E 01 DE
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
 198   13:       UTCTime 26/05/2023 13:06:31 GMT
 213   13:       UTCTime 22/05/2026 13:06:31 GMT
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
         :         6C 8F 49 B8 98 2F D3 71 94 3C 63 36 4D 6F E6 9F
         :         C1 42 67 9D 69 89 1E 9E 2A FA 34 D5 81 21 C6 76
         :         18 32 93 9A 70 B5 65 46 79 BF A0 62 AC C5 25 01
         :         8B BE D8 0B 52 CC 33 DE 2D 15 69 79 B9 8D F3 A4
         :         C6 85 54 A2 7D E1 11 72 FE 4E 85 BD 0C B3 40 A9
         :         9E FA AF DD 91 3D DC 3E F8 7D DC 98 9F BB B2 8B
         :         21 62 2E 67 48 F2 E3 C4 94 78 8B 2E EB 92 E9 80
         :         A5 1A A6 62 B6 DF 36 14 A6 92 94 FE 42 98 E9 BC
         :                 [ Another 1824 bytes skipped ]
         :       }
2253   96:     [3] {
2255   94:       SEQUENCE {
2257   12:         SEQUENCE {
2259    3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
2264    1:           BOOLEAN TRUE
2267    2:           OCTET STRING, encapsulates {
2269    0:             SEQUENCE {}
         :             }
         :           }
2271   14:         SEQUENCE {
2273    3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
2278    1:           BOOLEAN TRUE
2281    4:           OCTET STRING, encapsulates {
2283    2:             BIT STRING 7 unused bits
         :               '1'B (bit 0)
         :             }
         :           }
2287   29:         SEQUENCE {
2289    3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2294   22:           OCTET STRING, encapsulates {
2296   20:             OCTET STRING
         :               A3 5F EA B6 FA CB 63 81 3D D5 94 1F A8 41 2D F0
         :               96 DB BA 5B
         :             }
         :           }
2318   31:         SEQUENCE {
2320    3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
2325   24:           OCTET STRING, encapsulates {
2327   22:             SEQUENCE {
2329   20:               [0]
         :                 11 D9 28 17 0B E0 2A 47 CD 33 97 35 B7 0E 2B 2D
         :                 9C 94 4C 4A
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
2351   13:   SEQUENCE {
2353   11:     OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :     }
2366 3294:   BIT STRING
         :     74 1D 80 C6 D0 26 06 E1 7F 1C B8 99 3A 02 C0 32
         :     9A F4 75 71 A5 F8 AE AC E4 48 0D EF 77 97 6A 6A
         :     CB AE BF 37 BD FA 68 B4 AC 37 D3 41 7A 10 9F F9
         :     97 1A 16 90 32 48 3E 8E 6C A3 49 56 C3 D8 C8 5D
         :     58 79 A4 13 BE AB 46 03 D1 85 92 64 27 04 5E B7
         :     5E C6 65 CE 0A D4 9F 50 9A BA 0F 2B 35 67 75 2C
         :     98 51 9B E2 19 7E 67 08 37 AB C4 05 99 50 A4 91
         :     97 8C CF 6F F2 43 45 CD 77 6C BA 7F 94 F7 57 A6
         :             [ Another 3165 bytes skipped ]
         :   }

~~~

### EC signing end-entity certificate with encoded Delta Certificate

This is an end-entity signing certificate which certifies an EC key. It
contains a Delta Certificate Descriptor extension which includes
sufficient information to recreate the Dilithium signing end-entity
certificate.

~~~
-----BEGIN CERTIFICATE-----
MIIYEzCCF3WgAwIBAgIUVSjCfFKRz32x2VXdKmhcOKCiAeIwCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDUyNjEzMDYzMVoXDTI2MDUyMjEzMDYzMVowLzELMAkGA1UEBhMCWFgxDzAN
BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV
uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcqOCFhAwghYMMAwGA1UdEwEB/wQCMAAw
DgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBRbcKeYF/ef9jfS9+PcRGwhCde71DAf
BgNVHSMEGDAWgBSOwhQJYHbqkDjpOa4bbVLEF32fvjCCFaoGCmCGSAGG+mtQBgEE
ghWaMIIVlgIUC3I3HCAo5RSH45s1sH6CS+5eAd6gDQYLKwYBBAECggsHBgWhgZIw
gY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3QgLSBH
MTCCB7QwDQYLKwYBBAECggsHBgUDggehAGyPSbiYL9NxlDxjNk1v5p/BQmedaYke
nir6NNWBIcZ2GDKTmnC1ZUZ5v6BirMUlAYu+2AtSzDPeLRVpebmN86TGhVSifeER
cv5Ohb0Ms0Cpnvqv3ZE93D74fdyYn7uyiyFiLmdI8uPElHiLLuuS6YClGqZitt82
FKaSlP5CmOm8qt+8JQ+oZ/zCkJOVHOfAKgjz3klNxK0vBcHVOLx02ciHNnCqCUU+
wvt2R7rkm5oOqlGqjvRiofYOC7saMEtx4WKrTq7VcGPCIZQFIkietxVRqH+X+UAp
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
dWfd9sixl7+a5dc1mQpHcIorcQ/VAWA=
-----END CERTIFICATE-----

~~~

~~~
   0 6163: SEQUENCE {
   4 6005:   SEQUENCE {
   8    3:     [0] {
  10    1:       INTEGER 2
         :       }
  13   20:     INTEGER 55 28 C2 7C 52 91 CF 7D B1 D9 55 DD 2A 68 5C 38 A0 A2 01 E2
  35   10:     SEQUENCE {
  37    8:       OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
         :       }
  47  139:     SEQUENCE {
  50   11:       SET {
  52    9:         SEQUENCE {
  54    3:           OBJECT IDENTIFIER countryName (2 5 4 6)
  59    2:           PrintableString 'XX'
         :           }
         :         }
  63   53:       SET {
  65   51:         SEQUENCE {
  67    3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
  72   44:           UTF8String
         :             'Royal Institute of Public Key Infrastructure'
         :           }
         :         }
 118   43:       SET {
 120   41:         SEQUENCE {
 122    3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
 127   34:           UTF8String 'Post-Heffalump Research Department'
         :           }
         :         }
 163   24:       SET {
 165   22:         SEQUENCE {
 167    3:           OBJECT IDENTIFIER commonName (2 5 4 3)
 172   15:           UTF8String 'ECDSA Root - G1'
         :           }
         :         }
         :       }
 189   30:     SEQUENCE {
 191   13:       UTCTime 26/05/2023 13:06:31 GMT
 206   13:       UTCTime 22/05/2026 13:06:31 GMT
         :       }
 221   47:     SEQUENCE {
 223   11:       SET {
 225    9:         SEQUENCE {
 227    3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 232    2:           PrintableString 'XX'
         :           }
         :         }
 236   15:       SET {
 238   13:         SEQUENCE {
 240    3:           OBJECT IDENTIFIER surname (2 5 4 4)
 245    6:           UTF8String 'Yamada'
         :           }
         :         }
 253   15:       SET {
 255   13:         SEQUENCE {
 257    3:           OBJECT IDENTIFIER givenName (2 5 4 42)
 262    6:           UTF8String 'Hanako'
         :           }
         :         }
         :       }
 270   89:     SEQUENCE {
 272   19:       SEQUENCE {
 274    7:         OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 283    8:         OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
         :         }
 293   66:       BIT STRING
         :         04 42 25 48 F8 8F B7 82 FF B5 EC A3 74 44 52 C7
         :         2A 1E 55 8F BD 6F 73 BE 5E 48 E9 32 32 CC 45 C5
         :         B1 6C 4C D1 0C 4C B8 D5 B8 A1 71 39 E9 48 82 C8
         :         99 25 72 99 34 25 F4 14 19 AB 7E 90 A4 2A 49 42
         :         72
         :       }
 361 5648:     [3] {
 365 5644:       SEQUENCE {
 369   12:         SEQUENCE {
 371    3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
 376    1:           BOOLEAN TRUE
 379    2:           OCTET STRING, encapsulates {
 381    0:             SEQUENCE {}
         :             }
         :           }
 383   14:         SEQUENCE {
 385    3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
 390    1:           BOOLEAN TRUE
 393    4:           OCTET STRING, encapsulates {
 395    2:             BIT STRING 7 unused bits
         :               '1'B (bit 0)
         :             }
         :           }
 399   29:         SEQUENCE {
 401    3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
 406   22:           OCTET STRING, encapsulates {
 408   20:             OCTET STRING
         :               5B 70 A7 98 17 F7 9F F6 37 D2 F7 E3 DC 44 6C 21
         :               09 D7 BB D4
         :             }
         :           }
 430   31:         SEQUENCE {
 432    3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
 437   24:           OCTET STRING, encapsulates {
 439   22:             SEQUENCE {
 441   20:               [0]
         :                 8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
         :                 17 7D 9F BE
         :               }
         :             }
         :           }
 463 5546:         SEQUENCE {
 467   10:           OBJECT IDENTIFIER
         :             deltaCertificateDescriptor (2 16 840 1 114027 80 6 1)
 479 5530:           OCTET STRING, encapsulates {
 483 5526:             SEQUENCE {
 487   20:               INTEGER
         :                 0B 72 37 1C 20 28 E5 14 87 E3 9B 35 B0 7E 82 4B
         :                 EE 5E 01 DE
 509   13:               [0] {
 511   11:                 OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :                 }
 524  146:               [1] {
 527  143:                 SEQUENCE {
 530   11:                   SET {
 532    9:                     SEQUENCE {
 534    3:                       OBJECT IDENTIFIER countryName (2 5 4 6)
 539    2:                       PrintableString 'XX'
         :                       }
         :                     }
 543   53:                   SET {
 545   51:                     SEQUENCE {
 547    3:                       OBJECT IDENTIFIER organizationName (2 5 4 10)
 552   44:                       UTF8String
         :                   'Royal Institute of Public Key Infrastructure'
         :                       }
         :                     }
 598   43:                   SET {
 600   41:                     SEQUENCE {
 602    3:                       OBJECT IDENTIFIER
         :                         organizationalUnitName (2 5 4 11)
 607   34:                       UTF8String 'Post-Heffalump Research Department'
         :                       }
         :                     }
 643   28:                   SET {
 645   26:                     SEQUENCE {
 647    3:                       OBJECT IDENTIFIER commonName (2 5 4 3)
 652   19:                       UTF8String 'Dilithium Root - G1'
         :                       }
         :                     }
         :                   }
         :                 }
 673 1972:               SEQUENCE {
 677   13:                 SEQUENCE {
 679   11:                   OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 7 6 5'
         :                   }
 692 1953:                 BIT STRING
         :                   6C 8F 49 B8 98 2F D3 71 94 3C 63 36 4D 6F E6 9F
         :                   C1 42 67 9D 69 89 1E 9E 2A FA 34 D5 81 21 C6 76
         :                   18 32 93 9A 70 B5 65 46 79 BF A0 62 AC C5 25 01
         :                   8B BE D8 0B 52 CC 33 DE 2D 15 69 79 B9 8D F3 A4
         :                   C6 85 54 A2 7D E1 11 72 FE 4E 85 BD 0C B3 40 A9
         :                   9E FA AF DD 91 3D DC 3E F8 7D DC 98 9F BB B2 8B
         :                   21 62 2E 67 48 F2 E3 C4 94 78 8B 2E EB 92 E9 80
         :                   A5 1A A6 62 B6 DF 36 14 A6 92 94 FE 42 98 E9 BC
         :                           [ Another 1824 bytes skipped ]
         :                 }
2649   64:               [4] {
2651   29:                 SEQUENCE {
2653    3:                   OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2658   22:                   OCTET STRING, encapsulates {
2660   20:                     OCTET STRING
         :                     A3 5F EA B6 FA CB 63 81 3D D5 94 1F A8 41 2D F0
         :                     96 DB BA 5B
         :                     }
         :                   }
2682   31:                 SEQUENCE {
2684    3:                   OBJECT IDENTIFIER
         :                     authorityKeyIdentifier (2 5 29 35)
2689   24:                   OCTET STRING, encapsulates {
2691   22:                     SEQUENCE {
2693   20:                       [0]
         :                     11 D9 28 17 0B E0 2A 47 CD 33 97 35 B7 0E 2B 2D
         :                     9C 94 4C 4A
         :                       }
         :                     }
         :                   }
         :                 }
2715 3294:               BIT STRING
         :                 74 1D 80 C6 D0 26 06 E1 7F 1C B8 99 3A 02 C0 32
         :                 9A F4 75 71 A5 F8 AE AC E4 48 0D EF 77 97 6A 6A
         :                 CB AE BF 37 BD FA 68 B4 AC 37 D3 41 7A 10 9F F9
         :                 97 1A 16 90 32 48 3E 8E 6C A3 49 56 C3 D8 C8 5D
         :                 58 79 A4 13 BE AB 46 03 D1 85 92 64 27 04 5E B7
         :                 5E C6 65 CE 0A D4 9F 50 9A BA 0F 2B 35 67 75 2C
         :                 98 51 9B E2 19 7E 67 08 37 AB C4 05 99 50 A4 91
         :                 97 8C CF 6F F2 43 45 CD 77 6C BA 7F 94 F7 57 A6
         :                         [ Another 3165 bytes skipped ]
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
6013   10:   SEQUENCE {
6015    8:     OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
         :     }
6025  139:   BIT STRING, encapsulates {
6029  135:     SEQUENCE {
6032   65:       INTEGER
         :         24 53 DA 37 44 84 C7 2A 91 A5 51 BC 66 27 83 7F
         :         55 05 5B 56 56 62 FA C1 C5 66 4D F0 11 27 18 55
         :         D9 AF 64 AA 1B D6 2F 2E E7 F9 3F D7 35 97 F2 C5
         :         8E 66 57 D2 C8 AB E6 98 0E 70 10 2B 03 66 61 EE
         :         FF
6099   66:       INTEGER
         :         01 E5 11 06 BD B4 02 53 44 F0 56 BC 09 D9 E1 B7
         :         75 5D AE B0 4F 61 FD A2 56 4D 62 6F 18 CC CA CE
         :         95 FB 2A C8 A1 82 DC 7F 0E 9F 65 75 67 DD F6 C8
         :         B1 97 BF 9A E5 D7 35 99 0A 47 70 8A 2B 71 0F D5
         :         01 60
         :       }
         :     }
         :   }

~~~

## Dual use example

### EC signing end-entity certificate

This is an end-entity signing certificate which certifies an EC key.

~~~
-----BEGIN CERTIFICATE-----
MIICYTCCAcOgAwIBAgIUVcVNficoipRs4c6JBiF731VtDLAwCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDUyNjEzMDYzMVoXDTI2MDUyMjEzMDYzMVowLzELMAkGA1UEBhMCWFgxDzAN
BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV
uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcqNgMF4wDAYDVR0TAQH/BAIwADAOBgNV
HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFtwp5gX95/2N9L349xEbCEJ17vUMB8GA1Ud
IwQYMBaAFI7CFAlgduqQOOk5rhttUsQXfZ++MAoGCCqGSM49BAMEA4GLADCBhwJC
ATB+4mSAPRhLdoM3WSPx4l7PoZeuiYObCVZF7vV61bqmPhFskmZ+1aXSMIABfaNE
L5Tc+fiSFOXuZs4JSfWxyTlaAkFiK9X4q5kvyHWy97YbxkMOODeEq0ImwaMabmNO
Es40EGEHbEPLIHzW347BR8iZquPCA9wspc6y8edyXcBv/g2Yhw==
-----END CERTIFICATE-----

~~~

~~~
  0 609: SEQUENCE {
  4 451:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13  20:     INTEGER 55 C5 4D 7E 27 28 8A 94 6C E1 CE 89 06 21 7B DF 55 6D 0C B0
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
191  13:       UTCTime 26/05/2023 13:06:31 GMT
206  13:       UTCTime 22/05/2026 13:06:31 GMT
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
478  66:       INTEGER
       :         01 30 7E E2 64 80 3D 18 4B 76 83 37 59 23 F1 E2
       :         5E CF A1 97 AE 89 83 9B 09 56 45 EE F5 7A D5 BA
       :         A6 3E 11 6C 92 66 7E D5 A5 D2 30 80 01 7D A3 44
       :         2F 94 DC F9 F8 92 14 E5 EE 66 CE 09 49 F5 B1 C9
       :         39 5A
546  65:       INTEGER
       :         62 2B D5 F8 AB 99 2F C8 75 B2 F7 B6 1B C6 43 0E
       :         38 37 84 AB 42 26 C1 A3 1A 6E 63 4E 12 CE 34 10
       :         61 07 6C 43 CB 20 7C D6 DF 8E C1 47 C8 99 AA E3
       :         C2 03 DC 2C A5 CE B2 F1 E7 72 5D C0 6F FE 0D 98
       :         87
       :       }
       :     }
       :   }

~~~

### EC dual use end-entity certificate with encoded Delta Certificate

This is an end-entity key exchange certificate which certifies an EC
key. It contains a Delta Certificate Descriptor extension which includes
sufficient information to the recreate the EC signing end-entity
certificate.

~~~
-----BEGIN CERTIFICATE-----
MIIDyjCCAyygAwIBAgIUczxcVsNa7M9uSs598vuGatGLDuIwCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDUyNjEzMDYzMVoXDTI2MDUyMjEzMDYzMVowLzELMAkGA1UEBhMCWFgxDzAN
BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEWwkBuIUjKW65GdUP+hqcs3S8TUCVhigr/soRsdla27VHNK9XC/grcijP
ImvPTCXdvP47GjrTlDDv92Ph1o0uFR2Rcgt3lbWNprNGOWE6j7m1qNpIxnRxF/mR
noQk837Io4IBqjCCAaYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCAwgwHQYD
VR0OBBYEFArjoP6d1CV2mLXrcuvKDOe/PfXxMB8GA1UdIwQYMBaAFI7CFAlgduqQ
OOk5rhttUsQXfZ++MIIBRAYKYIZIAYb6a1AGAQSCATQwggEwAhRVxU1+JyiKlGzh
zokGIXvfVW0MsDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyj
dERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36Q
pCpJQnKkLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFtwp5gX95/2N9L349xE
bCEJ17vUA4GLADCBhwJCATB+4mSAPRhLdoM3WSPx4l7PoZeuiYObCVZF7vV61bqm
PhFskmZ+1aXSMIABfaNEL5Tc+fiSFOXuZs4JSfWxyTlaAkFiK9X4q5kvyHWy97Yb
xkMOODeEq0ImwaMabmNOEs40EGEHbEPLIHzW347BR8iZquPCA9wspc6y8edyXcBv
/g2YhzAKBggqhkjOPQQDBAOBiwAwgYcCQXY+Rtd1hMrl4tW7Is3cNjiwHNYs5L12
J5Rv+O78opL/a6UfbGpceiB1OIeBkjj/RyVCTTSQit67FWc/gmDkkyiMAkIB+YuM
wRXlfQVO3ivNdTluEOAI44SjpmXo63QjwqXLViTE66mOWZHBoXL6IilEtFajrkO/
HAuJrywI2E3RoOHS+lY=
-----END CERTIFICATE-----

~~~

~~~
  0 970: SEQUENCE {
  4 812:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13  20:     INTEGER 73 3C 5C 56 C3 5A EC CF 6E 4A CE 7D F2 FB 86 6A D1 8B 0E E2
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
191  13:       UTCTime 26/05/2023 13:06:31 GMT
206  13:       UTCTime 22/05/2026 13:06:31 GMT
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
496  10:           OBJECT IDENTIFIER
       :             deltaCertificateDescriptor (2 16 840 1 114027 80 6 1)
508 308:           OCTET STRING, encapsulates {
512 304:             SEQUENCE {
516  20:               INTEGER
       :                 55 C5 4D 7E 27 28 8A 94 6C E1 CE 89 06 21 7B DF
       :                 55 6D 0C B0
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
685  66:                   INTEGER
       :                     01 30 7E E2 64 80 3D 18 4B 76 83 37 59 23 F1 E2
       :                     5E CF A1 97 AE 89 83 9B 09 56 45 EE F5 7A D5 BA
       :                     A6 3E 11 6C 92 66 7E D5 A5 D2 30 80 01 7D A3 44
       :                     2F 94 DC F9 F8 92 14 E5 EE 66 CE 09 49 F5 B1 C9
       :                     39 5A
753  65:                   INTEGER
       :                     62 2B D5 F8 AB 99 2F C8 75 B2 F7 B6 1B C6 43 0E
       :                     38 37 84 AB 42 26 C1 A3 1A 6E 63 4E 12 CE 34 10
       :                     61 07 6C 43 CB 20 7C D6 DF 8E C1 47 C8 99 AA E3
       :                     C2 03 DC 2C A5 CE B2 F1 E7 72 5D C0 6F FE 0D 98
       :                     87
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
832 139:   BIT STRING, encapsulates {
836 135:     SEQUENCE {
839  65:       INTEGER
       :         76 3E 46 D7 75 84 CA E5 E2 D5 BB 22 CD DC 36 38
       :         B0 1C D6 2C E4 BD 76 27 94 6F F8 EE FC A2 92 FF
       :         6B A5 1F 6C 6A 5C 7A 20 75 38 87 81 92 38 FF 47
       :         25 42 4D 34 90 8A DE BB 15 67 3F 82 60 E4 93 28
       :         8C
906  66:       INTEGER
       :         01 F9 8B 8C C1 15 E5 7D 05 4E DE 2B CD 75 39 6E
       :         10 E0 08 E3 84 A3 A6 65 E8 EB 74 23 C2 A5 CB 56
       :         24 C4 EB A9 8E 59 91 C1 A1 72 FA 22 29 44 B4 56
       :         A3 AE 43 BF 1C 0B 89 AF 2C 08 D8 4D D1 A0 E1 D2
       :         FA 56
       :       }
       :     }
       :   }

~~~

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

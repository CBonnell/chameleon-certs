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
extension. Alternatively, if the sender understands the DCD extension
and knows that the receiver will only process the Delta Certificate,
the sender can reconstruct and send only the Delta Certificate. This
behavior is deferred to the software in use.

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

The signature field specifies the signature algorithm used by the
issuing certification authority to sign the Delta Certificate.
If the DER encoding of the value of the signature field of the Base
Certificate and Delta Certificate is the same, then this field MUST be
absent. Otherwise, it MUST contain the DER encoding of the value of the
signature field of the Delta Certificate.

The issuer field specifies the distinguished name of the
issuing certification authority which signed the Delta Certificate.
If the DER encoding of the value of the issuer field of the Base
Certificate and Delta Certificate is the same, then this field MUST be
absent. Otherwise, it MUST contain the DER encoding of the value of the
issuer field of the Delta Certificate.

The validity field specifies the validity period of the Delta
Certificate.
If the DER encoding of the value of the validity field of the Base
Certificate and Delta Certificate is the same, then this field MUST be
absent. Otherwise, it MUST contain the DER encoding of the value of the
validity field of the Delta Certificate.

The subject field specifies the distinguished name of the named subject
as encoded in the Delta Certificate.
If the DER encoding of the value of the subject field of the Base
Certificate and Delta Certificate is the same, then this field MUST be
absent. Otherwise, it MUST contain the DER encoding of the value of the
subject field of the Delta Certificate.

The subjectPublicKeyInfo field contains the public key certified
in the Delta Certificate. The value of this field MUST differ
from the value of the subjectPublicKeyInfo field of the Base
Certificate. In other words, the Base Certificate and Delta Certificate
MUST certify different keys.

The extensions field contains the extensions whose
criticality and/or DER-encoded value are different in the Delta
Certificate compared to the Base Certificate with the exception of the
DCD extension itself. If the extensions field is absent, then all
extensions in the Delta Certificate MUST have the same criticality and
DER-encoded value as the Base Certificate (except for the DCD extension,
which MUST be absent from the Delta Certificate). This field MUST NOT
contain any extension:

* which has the same criticality and DER-encoded value as encoded in the
  Base Certificate,
* whose type does not appear in the Base Certificate, or
* which is of the DCD extension type (recursive Delta Certificates are
  not permitted).

Additionally, the Base Certificate SHALL NOT include
any extensions which are not included in the Delta Certificate, with the
exception of the DCD extension itself. Likewise, there is no mechanism
to remove extensions from the Delta Certificate that are present in the
Base Certificate. Therefore, it is not possible to
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
Certificate. To simplify reconstruction of the Delta Certificate,
the signatures for Base and Delta Certificates MUST be calculated over
the DER encoding of the `TBSCertificate` structure.

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

As part of testing implementations of this specification,
implementers are encouraged to verify the signature of the
reconstructed Delta Certificate using the issuing Certification
Authority's public key to ensure that the Delta Certificate was
reconstructed correctly.

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
certification path validation algorithm defined in {{!RFC5280}}. In
particular, the certification path validation algorithm defined in
{{!RFC5280}} MUST be performed prior to using a Base or Delta
Certificate; it is not sufficient to reconstruct a Delta Certificate
and use it for any purpose without performing certification path
validation. If a use case requires it, a Delta Certificate can be
reconstructed specifically for the purposes of validation to ensure that
the Delta Certificate is valid for its intended purpose on final
reconstruction. That being said, some form of validation such as
revocation checking, and signature verification MUST always be assured
at the point the certificate is used.

There are some additional considerations for the software to
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
MIIDBTCCAmagAwIBAgIUDCQO4j68JeS6tggSujZ2W/+5RMAwCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDkxMjEyMTg0MVoXDTMzMDkwOTEyMTg0MVowgYsxCzAJBgNVBAYTAlhYMTUw
MwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVj
dHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVu
dDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMIGbMBAGByqGSM49AgEGBSuBBAAj
A4GGAAQAh+tYFO6c0kKrJ1Pu7Y6bApCvxk+urofls4ehqxKxMPDt5TGEGrTJo4RH
CaYClX7NUjrBbxWLlLH3TD+BOmDYAAMAvwrv/eTEr/bW4clFDvJMDRv+OLOeSjAm
nmbn+WVnlgxZZHz0S08BoXyY4MrAqRepmTPeW60gW9PaOAFRC8WqRJOjYzBhMA8G
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBR/FeuKivAa
Oj8kbsg6J0m5Pic4XTAfBgNVHSMEGDAWgBR/FeuKivAaOj8kbsg6J0m5Pic4XTAK
BggqhkjOPQQDBAOBjAAwgYgCQgDZrj2eo+LhmH8egdsT/uxO8wmOJ6SxOymzxAwf
TnbH0JsZmQOgrAtDNZ0sgMPi+GQP0BEHaIT5jeuBZvFHcZVTOwJCAN4urAjamN3N
KBObDovxaF3XWGW5AeIifkZrF6eJEH9k3vqLL+Wp8fEvm1X+o5NwTq9WetCLL5YS
vP9ln6snUlWC
-----END CERTIFICATE-----

~~~

~~~
  0 773: SEQUENCE {
  4 614:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13  20:     INTEGER 0C 24 0E E2 3E BC 25 E4 BA B6 08 12 BA 36 76 5B FF B9 44 C0
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
191  13:       UTCTime 12/09/2023 12:18:41 GMT
206  13:       UTCTime 09/09/2033 12:18:41 GMT
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
       :         04 00 87 EB 58 14 EE 9C D2 42 AB 27 53 EE ED 8E
       :         9B 02 90 AF C6 4F AE AE 87 E5 B3 87 A1 AB 12 B1
       :         30 F0 ED E5 31 84 1A B4 C9 A3 84 47 09 A6 02 95
       :         7E CD 52 3A C1 6F 15 8B 94 B1 F7 4C 3F 81 3A 60
       :         D8 00 03 00 BF 0A EF FD E4 C4 AF F6 D6 E1 C9 45
       :         0E F2 4C 0D 1B FE 38 B3 9E 4A 30 26 9E 66 E7 F9
       :         65 67 96 0C 59 64 7C F4 4B 4F 01 A1 7C 98 E0 CA
       :         C0 A9 17 A9 99 33 DE 5B AD 20 5B D3 DA 38 01 51
       :         0B C5 AA 44 93
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
       :               7F 15 EB 8A 8A F0 1A 3A 3F 24 6E C8 3A 27 49 B9
       :               3E 27 38 5D
       :             }
       :           }
589  31:         SEQUENCE {
591   3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
596  24:           OCTET STRING, encapsulates {
598  22:             SEQUENCE {
600  20:               [0]
       :                 7F 15 EB 8A 8A F0 1A 3A 3F 24 6E C8 3A 27 49 B9
       :                 3E 27 38 5D
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
       :         00 D9 AE 3D 9E A3 E2 E1 98 7F 1E 81 DB 13 FE EC
       :         4E F3 09 8E 27 A4 B1 3B 29 B3 C4 0C 1F 4E 76 C7
       :         D0 9B 19 99 03 A0 AC 0B 43 35 9D 2C 80 C3 E2 F8
       :         64 0F D0 11 07 68 84 F9 8D EB 81 66 F1 47 71 95
       :         53 3B
709  66:       INTEGER
       :         00 DE 2E AC 08 DA 98 DD CD 28 13 9B 0E 8B F1 68
       :         5D D7 58 65 B9 01 E2 22 7E 46 6B 17 A7 89 10 7F
       :         64 DE FA 8B 2F E5 A9 F1 F1 2F 9B 55 FE A3 93 70
       :         4E AF 56 7A D0 8B 2F 96 12 BC FF 65 9F AB 27 52
       :         55 82
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
MIIZbzCCDGqgAwIBAgIUFWd6hCxGhDNL+S1OL3UY7w+psbQwDQYLKwYBBAECggsM
BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg
UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1
bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg
LSBHMTAeFw0yMzA5MTIxMjE4NDFaFw0zMzA5MDkxMjE4NDFaMIGPMQswCQYDVQQG
EwJYWDE1MDMGA1UECgwsUm95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5m
cmFzdHJ1Y3R1cmUxKzApBgNVBAsMIlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERl
cGFydG1lbnQxHDAaBgNVBAMME0RpbGl0aGl1bSBSb290IC0gRzEwgge0MA0GCysG
AQQBAoILDAYFA4IHoQC/oCNTg2F5sHPzM6lP5YM2wLRNh9+mj3fwb8BHjwO+eXvy
W0lTDJuIXrcwXaNA+/Xjm6WSMZgYTe6ysIwLT4V6WZqc0L3bOOwnudfv7eK1OCvH
Sr/JMRhRQF7m65PdbCjoHr0/n2n/RKxe8BfhXqCeR1X7clovLS6Xam604qxAd4iX
WmMSV0KTZd/kdwSECeacRyUNjKGeegiaITwTPwU0BrGRfMPXZtcrirY4wAvElBEJ
1FzHls4C6PsceCQurgu0Y2WE85rxMTCUqJ2W13tx2AwtqDYttT8PgQDGAkVyYY8t
KnEqyP6owmaZsOb0XvFgPqHg5+0RuyNrKWfFFlZzahhAajfdh1+FGLsje/gCLJAW
3MabOFDuWOE0CfM7jYIiMvQ8PQEELNkF2zRt2Soy5tSQQN/h4VRQZzTrLPAtsGeP
Q1oUiP1+4TBLiRYV7EJDNLHp/6MVimfTkC2EdQQp691wxC40HrV3LZGwRMQLSNwS
XK+c3uxFSatja1dbaZR853Za9KlyBsVg1Fsbg0+NHvz6TgkxpK0EtDPpvOreZTGx
eqz/BS3jZCIlW4mvRDU0vFQ0FKzHVBAscwMYG8AcsT8n8JEGNma2NYwBZebMl6RV
ar/8jDoo5GHTxcD/tXuXI2A4nIvtmoLJojHufsK3ZnNWY5DWf+K2dRpTmeZHLr5o
iuyHDQiMKKkQbxiO3W0MYWgGLNNel19gnOMRzY/rh6kGjIewIJlWfnOSZMbZ5Sg9
y9W0fvU6JNtc5pf+USBpl6tqBWxS2Bq82rBVkleN+Nc5LYlzDO1AIgdxf4+uDXvc
iOGg+iTKoY5W92xASrmu54hy2J/4vZkMHshcQKfAQ8WXIM9nx8dWnwwTszOEMLcf
NH5Do9TR0VAfLB7LqNI2PB1F1BGEnyGLAzU0/We1Vun8XI9PqFlPMOfJrAVkT13e
YlntITKRLF7/Esj14ZCwGrIePrEwvbEVwVHE1Tl/M2FmZPCIYxa2HYEfytcTeWfd
oOYvklEk34no73O1bRh1D36Dp2KE6IVT37hBupGrJl4Dl8/qWJqjMMqLyTunlbH2
R8U6i4oX23qSz+IczarMfCEIwhmyUXaTAo5QnwAiLcsbOnyv69rGEMKZKtIPsGNC
raOArJ9+vjJj5X5eR/Trwv/y6NqBsKDQZypr0DNplyVOnuurSi9le5sZ4GIyuFXG
gP6NbIcX8pqZuPkCiJhxNfA3NrFac76OT6XqAusarhJ3gJycxxXjhssGDJ37ZruQ
oGk99+1CRxWEd6f4sKs/L50u9K02CvvK8NKyT6Gke2hPD4K/3Do8BveKx8wfeYbW
BDcFK+BX1b3WiggZaejBSMdFBwC3MsOsigNzmz45+G5QMJGedrPqJ4/fCEHhTBGz
UPjWOLTnnWQBEWITF8S4ayzqUACEL2XkQw7pSiNpkpgZL+uWpnAkpoJhlQnuURep
UyPuYPCGmLWDI0ePzLgpHwDmx38a9rJBM21HAzOdQnvkzisfXQNuWwxNb8Oy+800
hp/tK+MleGKGK6carCOWiPq5XhznHyNNtL4S4DGACssNvZBCjCh87cLtukFS2d0n
3XwyCxH9MqkPatUcJmarIc6H4875d/wZ7fE08uTuPu8oFJ2eQ/726OyUjYnMLZ+L
uWVnVilr9kEBR4chNp2QjIV90qGNDk5r+K+6pNresOEP5c1zNun20MC8/9hzncfC
F2C8WFcwrgBYXI3hE5KIeqZ/8/3mhmITzZFBGKj1Jj0FiZrVo89Z4gfOQh7G0/k2
USyQF0SHHN8W+gj5nOlUHWbJBrVl+qSrYEXmmzjp7dpC+lG28qcJ0hvN+gUewemy
lyguyUHd4yd+C5lkXyyhEKGgAeiO6Z3vpi0Gg4pM9UhznjBgaEH6y/gi+SFemNL0
CgdL+qXynTBOWTSwxE5gtQ9xhsML05jpR7pryfCoS9KawlpZeKkfO13Yt35MuMZ6
MlPPEKmdvWSr41xXPY3/ORbN7jLEiA5+Pu3MEPl6Hvt/eQuK2QRUunhdUU2908u1
aslaEjIrNEYhF//WhFYCJGDekNkrHeB/Y+3LTIq7v+e4JkhrHXg8hmkasusfPZIW
9D8k64Bn/UAMcpaFZYv7uSmKxKhM6ZEt9deD4OH6c71kNzD9BZy7EHCv1Mwdafgw
9XqTO6xq7ybaXoCli5T9DH1GLPiYQLxboePn6ly8Q2wYxVQdMRDRmI/W9Q41kc1D
INRSmZDmgXf2AR57aMIIz5x6PvEQHJtRWEyyyO5Uh0SMuTzH7GmlIjZylhzHbl+g
ve53FYRoJCLrouOiS+WgPO7l3YkPxc955Bn7FLWrfSqZ7/YRT88mswjUzKtAXMX9
LXlJNpz/eEngf29AeIcRLotgNroewRaOCc8PVPpTm1eLCc0toHzJam9HnKcmpQdb
6xKrGDJoVV5mk3MJDBz6BZEoap3zBcw/rjbdbJw/YnMl++3yFiKeSTQm8RSuRcYd
iWLTaCAl/7LVrNlRovaqZx0t4nqt8rkHSoPAFM288XyFJJbazs00lqxV1LneNYFc
Ps45I2mjtveHRrAVNzZV1H+AN+YsYhQVJ/5wood0ymg+e1gavkh9U753baJHn6OC
A0AwggM8MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQW
BBSneSj7WSclcRYCY0jLaShyMkGkbzAfBgNVHSMEGDAWgBSneSj7WSclcRYCY0jL
aShyMkGkbzCCAtcGCmCGSAGG+mtQBgEEggLHMIICwwIUDCQO4j68JeS6tggSujZ2
W/+5RMCgCgYIKoZIzj0EAwShgY4wgYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxS
b3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkG
A1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UE
AwwPRUNEU0EgUm9vdCAtIEcxo4GOMIGLMQswCQYDVQQGEwJYWDE1MDMGA1UECgws
Um95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5mcmFzdHJ1Y3R1cmUxKzAp
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
-----END CERTIFICATE-----

~~~

~~~
   0 6511: SEQUENCE {
   4 3178:   SEQUENCE {
   8    3:     [0] {
  10    1:       INTEGER 2
         :       }
  13   20:     INTEGER 15 67 7A 84 2C 46 84 33 4B F9 2D 4E 2F 75 18 EF 0F A9 B1 B4
  35   13:     SEQUENCE {
  37   11:       OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 12 6 5'
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
 198   13:       UTCTime 12/09/2023 12:18:41 GMT
 213   13:       UTCTime 09/09/2033 12:18:41 GMT
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
 380   11:         OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 12 6 5'
         :         }
 393 1953:       BIT STRING
         :         BF A0 23 53 83 61 79 B0 73 F3 33 A9 4F E5 83 36
         :         C0 B4 4D 87 DF A6 8F 77 F0 6F C0 47 8F 03 BE 79
         :         7B F2 5B 49 53 0C 9B 88 5E B7 30 5D A3 40 FB F5
         :         E3 9B A5 92 31 98 18 4D EE B2 B0 8C 0B 4F 85 7A
         :         59 9A 9C D0 BD DB 38 EC 27 B9 D7 EF ED E2 B5 38
         :         2B C7 4A BF C9 31 18 51 40 5E E6 EB 93 DD 6C 28
         :         E8 1E BD 3F 9F 69 FF 44 AC 5E F0 17 E1 5E A0 9E
         :         47 55 FB 72 5A 2F 2D 2E 97 6A 6E B4 E2 AC 40 77
         :                 [ Another 1824 bytes skipped ]
         :       }
2350  832:     [3] {
2354  828:       SEQUENCE {
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
         :               '1100001'B
         :             }
         :           }
2391   29:         SEQUENCE {
2393    3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2398   22:           OCTET STRING, encapsulates {
2400   20:             OCTET STRING
         :               A7 79 28 FB 59 27 25 71 16 02 63 48 CB 69 28 72
         :               32 41 A4 6F
         :             }
         :           }
2422   31:         SEQUENCE {
2424    3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
2429   24:           OCTET STRING, encapsulates {
2431   22:             SEQUENCE {
2433   20:               [0]
         :                 A7 79 28 FB 59 27 25 71 16 02 63 48 CB 69 28 72
         :                 32 41 A4 6F
         :               }
         :             }
         :           }
2455  727:         SEQUENCE {
2459   10:           OBJECT IDENTIFIER
         :             deltaCertificateDescriptor (2 16 840 1 114027 80 6 1)
2471  711:           OCTET STRING, encapsulates {
2475  707:             SEQUENCE {
2479   20:               INTEGER
         :                 0C 24 0E E2 3E BC 25 E4 BA B6 08 12 BA 36 76 5B
         :                 FF B9 44 C0
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
         :                   04 00 87 EB 58 14 EE 9C D2 42 AB 27 53 EE ED 8E
         :                   9B 02 90 AF C6 4F AE AE 87 E5 B3 87 A1 AB 12 B1
         :                   30 F0 ED E5 31 84 1A B4 C9 A3 84 47 09 A6 02 95
         :                   7E CD 52 3A C1 6F 15 8B 94 B1 F7 4C 3F 81 3A 60
         :                   D8 00 03 00 BF 0A EF FD E4 C4 AF F6 D6 E1 C9 45
         :                   0E F2 4C 0D 1B FE 38 B3 9E 4A 30 26 9E 66 E7 F9
         :                   65 67 96 0C 59 64 7C F4 4B 4F 01 A1 7C 98 E0 CA
         :                   C0 A9 17 A9 99 33 DE 5B AD 20 5B D3 DA 38 01 51
         :                   0B C5 AA 44 93
         :                 }
2961   80:               [4] {
2963   14:                 SEQUENCE {
2965    3:                   OBJECT IDENTIFIER keyUsage (2 5 29 15)
2970    1:                   BOOLEAN TRUE
2973    4:                   OCTET STRING, encapsulates {
2975    2:                     BIT STRING 1 unused bit
         :                       '1100000'B
         :                     }
         :                   }
2979   29:                 SEQUENCE {
2981    3:                   OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2986   22:                   OCTET STRING, encapsulates {
2988   20:                     OCTET STRING
         :                     7F 15 EB 8A 8A F0 1A 3A 3F 24 6E C8 3A 27 49 B9
         :                     3E 27 38 5D
         :                     }
         :                   }
3010   31:                 SEQUENCE {
3012    3:                   OBJECT IDENTIFIER
         :                     authorityKeyIdentifier (2 5 29 35)
3017   24:                   OCTET STRING, encapsulates {
3019   22:                     SEQUENCE {
3021   20:                       [0]
         :                     7F 15 EB 8A 8A F0 1A 3A 3F 24 6E C8 3A 27 49 B9
         :                     3E 27 38 5D
         :                       }
         :                     }
         :                   }
         :                 }
3043  140:               BIT STRING, encapsulates {
3047  136:                 SEQUENCE {
3050   66:                   INTEGER
         :                     00 D9 AE 3D 9E A3 E2 E1 98 7F 1E 81 DB 13 FE EC
         :                     4E F3 09 8E 27 A4 B1 3B 29 B3 C4 0C 1F 4E 76 C7
         :                     D0 9B 19 99 03 A0 AC 0B 43 35 9D 2C 80 C3 E2 F8
         :                     64 0F D0 11 07 68 84 F9 8D EB 81 66 F1 47 71 95
         :                     53 3B
3118   66:                   INTEGER
         :                     00 DE 2E AC 08 DA 98 DD CD 28 13 9B 0E 8B F1 68
         :                     5D D7 58 65 B9 01 E2 22 7E 46 6B 17 A7 89 10 7F
         :                     64 DE FA 8B 2F E5 A9 F1 F1 2F 9B 55 FE A3 93 70
         :                     4E AF 56 7A D0 8B 2F 96 12 BC FF 65 9F AB 27 52
         :                     55 82
         :                   }
         :                 }
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
3186   13:   SEQUENCE {
3188   11:     OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 12 6 5'
         :     }
3201 3310:   BIT STRING
         :     85 C2 9E 65 DC D3 24 B2 44 32 7C E9 CB FB 6C FD
         :     04 38 C1 98 FA 39 44 94 27 2A D0 FC 15 63 99 7F
         :     89 91 5D 56 20 12 E1 1C C4 09 D4 14 B8 E0 56 0A
         :     A1 B9 B7 6E F4 C8 8E B3 88 02 C7 EB 76 24 FA CD
         :     0D 73 46 C3 DA FE 05 90 CD FD 26 F3 9C 4D 47 FD
         :     7D A4 D7 55 56 4A A5 69 91 DC 1F 95 6E 93 3E 40
         :     09 07 34 EB E2 BA 42 29 29 47 96 E6 CB 49 06 C9
         :     CA A2 7D A9 93 23 3C 4D 8D 7E 16 5F FF 9D 5D E1
         :             [ Another 3181 bytes skipped ]
         :   }

~~~

## Algorithm migration example

### Dilithium signing end-entity certificate

This is an end-entity signing certificate which certifies a Dilithium
key.

~~~
-----BEGIN CERTIFICATE-----
MIIWLDCCCSegAwIBAgIUQZG8jQpzWDji9fN14AOMsoG89SIwDQYLKwYBBAECggsM
BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg
UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1
bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg
LSBHMTAeFw0yMzA5MTIxMjE4NDFaFw0zMzA5MDkxMjE4NDFaMC8xCzAJBgNVBAYT
AlhYMQ8wDQYDVQQEDAZZYW1hZGExDzANBgNVBCoMBkhhbmFrbzCCB7QwDQYLKwYB
BAECggsMBgUDggehAGciTkvYrra2rghjHQuBFbYgdVdKDF0pRu2BxotfWNFqUX2k
b3FybQ+cIEfZHSUersMUBWKGmssfPGK3jKQB4euFvXDYq1blurGimfEkxmQA8HsD
wEUSIe9WPl7oKH7VMrzFRdUB/0UHinZSsKQn5k3q5Vx7S1JfAsPuQB2iaKqe0jCS
7U8WQXwoE3H6rgVs1464WfYy8Gih8w3Melofi1O/77Hu0vXJ4X+vq4ILKnQyvvvh
6sMEa78VA5Ydf5cTh2BjOt535e5LRy6eQwOvVvuilQPxoFx3eH73YQU1sbVJGCAm
Ix3fUhwHruQSELUISO/z0twRNKw5EYeiDQKILzFzixSbJRWvaA14mNLBr+CkK/y1
7aE0fDNMjnrxkm81/puuXHTCZT/tHEm2dGjsAv5rvJHp4FuJurnEzDEv+ChALSqF
bl7T1+8KhHi8n1wAGheNHkbwl1oToUDLRmF705p1h1oT19SUnCy6r/arI29jboFO
ttPhquT4mqmcjpOqxvIIRLmQzFn8A6A97U3b20anlDlWeF3cIEda9E4xJzVT1ON6
JcfdGcF6okerqsKb0QF+VaUiEWPl+unlsHkiTq/IyCUKy/wQKh//zN0DvwbCIbAh
H8cqSycd5/rWRcc5Wfq+XAXllkkR7GL7XdVLj2e9ursprhyx4ID+nFMaqnf8xkVf
a2VmNdhC7nZoYEPFbcBZmPHkS0iSLiX76CLMDk3805jD7f+jJnI0tu0hcXqTeO21
YNmwEOeBm1s5/oSoFSqZ617GnqatysMNbmaH9YiTI06S2+I3YGf0K3vJhVs0nAqr
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
AAAAAAAAAAAAAAcTGiAjKA==
-----END CERTIFICATE-----

~~~

~~~
   0 5676: SEQUENCE {
   4 2343:   SEQUENCE {
   8    3:     [0] {
  10    1:       INTEGER 2
         :       }
  13   20:     INTEGER 41 91 BC 8D 0A 73 58 38 E2 F5 F3 75 E0 03 8C B2 81 BC F5 22
  35   13:     SEQUENCE {
  37   11:       OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 12 6 5'
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
 198   13:       UTCTime 12/09/2023 12:18:41 GMT
 213   13:       UTCTime 09/09/2033 12:18:41 GMT
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
 283   11:         OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 12 6 5'
         :         }
 296 1953:       BIT STRING
         :         67 22 4E 4B D8 AE B6 B6 AE 08 63 1D 0B 81 15 B6
         :         20 75 57 4A 0C 5D 29 46 ED 81 C6 8B 5F 58 D1 6A
         :         51 7D A4 6F 71 72 6D 0F 9C 20 47 D9 1D 25 1E AE
         :         C3 14 05 62 86 9A CB 1F 3C 62 B7 8C A4 01 E1 EB
         :         85 BD 70 D8 AB 56 E5 BA B1 A2 99 F1 24 C6 64 00
         :         F0 7B 03 C0 45 12 21 EF 56 3E 5E E8 28 7E D5 32
         :         BC C5 45 D5 01 FF 45 07 8A 76 52 B0 A4 27 E6 4D
         :         EA E5 5C 7B 4B 52 5F 02 C3 EE 40 1D A2 68 AA 9E
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
         :               45 47 41 95 AB AD C2 4E 3C 53 E1 65 91 94 8F 1C
         :               97 C8 63 AB
         :             }
         :           }
2318   31:         SEQUENCE {
2320    3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
2325   24:           OCTET STRING, encapsulates {
2327   22:             SEQUENCE {
2329   20:               [0]
         :                 A7 79 28 FB 59 27 25 71 16 02 63 48 CB 69 28 72
         :                 32 41 A4 6F
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
2351   13:   SEQUENCE {
2353   11:     OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 12 6 5'
         :     }
2366 3310:   BIT STRING
         :     55 2E 64 72 63 BC AC 70 A2 E3 ED C8 42 1E 44 40
         :     5C C2 1D 94 CC 76 0F 9E AB BD 16 41 CE ED AE 23
         :     78 2B 67 E7 45 0A 53 43 66 A9 B1 DC 74 89 29 9E
         :     D0 7E 20 94 FC 96 6D C3 0A 78 D1 6B EB F8 D6 54
         :     98 7B 59 AC 5E 4E BA 20 D5 EF 2E EA 91 99 2E EC
         :     B7 31 1B A4 E5 80 4A CB A4 13 86 75 68 F4 2B B8
         :     9E 97 E3 89 4C C3 B6 B2 67 62 D7 00 C8 E5 54 7B
         :     8D F6 3E 6D 7C A5 4B C4 5C AD 6D F8 38 72 A3 F2
         :             [ Another 3181 bytes skipped ]
         :   }

~~~

### EC signing end-entity certificate with encoded Delta Certificate

This is an end-entity signing certificate which certifies an EC key. It
contains a Delta Certificate Descriptor extension which includes
sufficient information to recreate the Dilithium signing end-entity
certificate.

~~~
-----BEGIN CERTIFICATE-----
MIIYIzCCF4WgAwIBAgIUQFy9NSVq9ZXG6QZyo14DJ/bew58wCgYIKoZIzj0EAwQw
gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X
DTIzMDkxMjEyMTg0MVoXDTMzMDkwOTEyMTg0MVowLzELMAkGA1UEBhMCWFgxDzAN
BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEbtX9IXsFmdqH4MWTDbifSOUFAUzd7HP5hnUObBqV0kXcuOwC99A0
4B87WQxjUKoawKtvu+LOJz1z7pQ5nUSxwaOCFiAwghYcMAwGA1UdEwEB/wQCMAAw
DgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBQW6srxnhU1Tq6zHIhrUWbDTXwQKTAf
BgNVHSMEGDAWgBR/FeuKivAaOj8kbsg6J0m5Pic4XTCCFboGCmCGSAGG+mtQBgEE
ghWqMIIVpgIUQZG8jQpzWDji9fN14AOMsoG89SKgDQYLKwYBBAECggsMBgWhgZIw
gY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi
bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg
UmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3QgLSBH
MTCCB7QwDQYLKwYBBAECggsMBgUDggehAGciTkvYrra2rghjHQuBFbYgdVdKDF0p
Ru2BxotfWNFqUX2kb3FybQ+cIEfZHSUersMUBWKGmssfPGK3jKQB4euFvXDYq1bl
urGimfEkxmQA8HsDwEUSIe9WPl7oKH7VMrzFRdUB/0UHinZSsKQn5k3q5Vx7S1Jf
AsPuQB2iaKqe0jCS7U8WQXwoE3H6rgVs1464WfYy8Gih8w3Melofi1O/77Hu0vXJ
4X+vq4ILKnQyvvvh6sMEa78VA5Ydf5cTh2BjOt535e5LRy6eQwOvVvuilQPxoFx3
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
-----END CERTIFICATE-----

~~~

~~~
   0 6179: SEQUENCE {
   4 6021:   SEQUENCE {
   8    3:     [0] {
  10    1:       INTEGER 2
         :       }
  13   20:     INTEGER 40 5C BD 35 25 6A F5 95 C6 E9 06 72 A3 5E 03 27 F6 DE C3 9F
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
 191   13:       UTCTime 12/09/2023 12:18:41 GMT
 206   13:       UTCTime 09/09/2033 12:18:41 GMT
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
         :         04 6E D5 FD 21 7B 05 99 DA 87 E0 C5 93 0D B8 9F
         :         48 E5 05 01 4C DD EC 73 F9 86 75 0E 6C 1A 95 D2
         :         45 DC B8 EC 02 F7 D0 34 E0 1F 3B 59 0C 63 50 AA
         :         1A C0 AB 6F BB E2 CE 27 3D 73 EE 94 39 9D 44 B1
         :         C1
         :       }
 361 5664:     [3] {
 365 5660:       SEQUENCE {
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
         :               16 EA CA F1 9E 15 35 4E AE B3 1C 88 6B 51 66 C3
         :               4D 7C 10 29
         :             }
         :           }
 430   31:         SEQUENCE {
 432    3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
 437   24:           OCTET STRING, encapsulates {
 439   22:             SEQUENCE {
 441   20:               [0]
         :                 7F 15 EB 8A 8A F0 1A 3A 3F 24 6E C8 3A 27 49 B9
         :                 3E 27 38 5D
         :               }
         :             }
         :           }
 463 5562:         SEQUENCE {
 467   10:           OBJECT IDENTIFIER
         :             deltaCertificateDescriptor (2 16 840 1 114027 80 6 1)
 479 5546:           OCTET STRING, encapsulates {
 483 5542:             SEQUENCE {
 487   20:               INTEGER
         :                 41 91 BC 8D 0A 73 58 38 E2 F5 F3 75 E0 03 8C B2
         :                 81 BC F5 22
 509   13:               [0] {
 511   11:                 OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 12 6 5'
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
 679   11:                   OBJECT IDENTIFIER '1 3 6 1 4 1 2 267 12 6 5'
         :                   }
 692 1953:                 BIT STRING
         :                   67 22 4E 4B D8 AE B6 B6 AE 08 63 1D 0B 81 15 B6
         :                   20 75 57 4A 0C 5D 29 46 ED 81 C6 8B 5F 58 D1 6A
         :                   51 7D A4 6F 71 72 6D 0F 9C 20 47 D9 1D 25 1E AE
         :                   C3 14 05 62 86 9A CB 1F 3C 62 B7 8C A4 01 E1 EB
         :                   85 BD 70 D8 AB 56 E5 BA B1 A2 99 F1 24 C6 64 00
         :                   F0 7B 03 C0 45 12 21 EF 56 3E 5E E8 28 7E D5 32
         :                   BC C5 45 D5 01 FF 45 07 8A 76 52 B0 A4 27 E6 4D
         :                   EA E5 5C 7B 4B 52 5F 02 C3 EE 40 1D A2 68 AA 9E
         :                           [ Another 1824 bytes skipped ]
         :                 }
2649   64:               [4] {
2651   29:                 SEQUENCE {
2653    3:                   OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
2658   22:                   OCTET STRING, encapsulates {
2660   20:                     OCTET STRING
         :                     45 47 41 95 AB AD C2 4E 3C 53 E1 65 91 94 8F 1C
         :                     97 C8 63 AB
         :                     }
         :                   }
2682   31:                 SEQUENCE {
2684    3:                   OBJECT IDENTIFIER
         :                     authorityKeyIdentifier (2 5 29 35)
2689   24:                   OCTET STRING, encapsulates {
2691   22:                     SEQUENCE {
2693   20:                       [0]
         :                     A7 79 28 FB 59 27 25 71 16 02 63 48 CB 69 28 72
         :                     32 41 A4 6F
         :                       }
         :                     }
         :                   }
         :                 }
2715 3310:               BIT STRING
         :                 55 2E 64 72 63 BC AC 70 A2 E3 ED C8 42 1E 44 40
         :                 5C C2 1D 94 CC 76 0F 9E AB BD 16 41 CE ED AE 23
         :                 78 2B 67 E7 45 0A 53 43 66 A9 B1 DC 74 89 29 9E
         :                 D0 7E 20 94 FC 96 6D C3 0A 78 D1 6B EB F8 D6 54
         :                 98 7B 59 AC 5E 4E BA 20 D5 EF 2E EA 91 99 2E EC
         :                 B7 31 1B A4 E5 80 4A CB A4 13 86 75 68 F4 2B B8
         :                 9E 97 E3 89 4C C3 B6 B2 67 62 D7 00 C8 E5 54 7B
         :                 8D F6 3E 6D 7C A5 4B C4 5C AD 6D F8 38 72 A3 F2
         :                         [ Another 3181 bytes skipped ]
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
6029   10:   SEQUENCE {
6031    8:     OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
         :     }
6041  139:   BIT STRING, encapsulates {
6045  135:     SEQUENCE {
6048   66:       INTEGER
         :         01 F7 8F DF D7 53 46 C3 FF 5B D8 75 76 DC A1 EE
         :         EE AB 09 65 D2 0E 52 24 7B C2 44 7E B7 ED FB 7E
         :         6E F9 71 BB 7B C9 09 3E 13 75 6F CB E0 47 AB D2
         :         01 81 37 EE 67 6F 83 BB 43 C4 66 3E 40 47 CE 7B
         :         B7 79
6116   65:       INTEGER
         :         4D CF B9 90 12 96 55 45 DE 0E 80 A7 FA 17 E6 ED
         :         AF 98 0E 98 C7 6B 57 6F 7B 3C 2F C9 5D 08 6D A0
         :         48 15 5B DA 9D 2F 48 18 B5 BF 70 0B 9B 84 E3 35
         :         BD 25 F8 FE F0 1B 00 72 71 0A A6 24 21 D5 8A 7C
         :         49
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

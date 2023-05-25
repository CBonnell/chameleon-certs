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

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

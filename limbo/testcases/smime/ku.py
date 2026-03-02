"""
S/MIME Key Usage (KU) tests.
"""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from limbo.assets import ext
from limbo.models import Feature, KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def signing_only_rsa_digital_signature(builder: Builder) -> None:
    """
    RSA EE with digitalSignature only. S/MIME BR 7.1.2.3(e):

    > For signing only, bit positions SHALL be set for digitalSignature.
    """

    root = builder.root_ca()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = builder.leaf_cert(
        root,
        key=leaf_key,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .succeeds()
    )


@testcase
def signing_only_rsa_with_nonrepudiation(builder: Builder) -> None:
    """
    RSA EE with digitalSignature + contentCommitment. S/MIME BR 7.1.2.3(e):

    > For signing only, bit positions SHALL be set for digitalSignature
    > and MAY be set for nonRepudiation.
    """

    root = builder.root_ca()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = builder.leaf_cert(
        root,
        key=leaf_key,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .succeeds()
    )


@testcase
def key_management_only_rsa(builder: Builder) -> None:
    """
    RSA EE with keyEncipherment only. S/MIME BR 7.1.2.3(e):

    > For key management only, bit positions SHALL be set for keyEncipherment.
    """

    root = builder.root_ca()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = builder.leaf_cert(
        root,
        key=leaf_key,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .succeeds()
    )


@testcase
def dual_use_rsa(builder: Builder) -> None:
    """
    RSA EE with digitalSignature + keyEncipherment. S/MIME BR 7.1.2.3(e):

    > For dual use, bit positions SHALL be set for digitalSignature
    > and keyEncipherment.
    """

    root = builder.root_ca()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = builder.leaf_cert(
        root,
        key=leaf_key,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .succeeds()
    )


@testcase
def signing_only_ec(builder: Builder) -> None:
    """
    EC EE with digitalSignature only. S/MIME BR 7.1.2.3(e):

    > For signing only, bit positions SHALL be set for digitalSignature.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .succeeds()
    )


@testcase
def key_management_only_ec(builder: Builder) -> None:
    """
    EC EE with keyAgreement only. S/MIME BR 7.1.2.3(e):

    > For key management only, bit positions SHALL be set for keyAgreement.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .succeeds()
    )


@testcase
def ee_key_cert_sign(builder: Builder) -> None:
    """
    The EE has keyCertSign set. S/MIME BR 7.1.2.3(e):

    > Other bit positions SHALL NOT be set.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def ee_missing_key_usage(builder: Builder) -> None:
    """
    The EE has no Key Usage extension. S/MIME BR 7.1.2.3(e):

    > keyUsage (SHALL be present)
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=None,
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def ee_key_usage_not_critical(builder: Builder) -> None:
    """
    The EE Key Usage extension is not marked critical. S/MIME BR 7.1.2.3(e):

    > This extension SHOULD be marked critical.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .features([Feature.pedantic_smime_eku])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def intermediate_missing_key_cert_sign(builder: Builder) -> None:
    """
    The ICA Key Usage lacks keyCertSign. S/MIME BR 7.1.2.2(e):

    > Bit positions for keyCertSign and cRLSign SHALL be set.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        pathlen=0,
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
        extra_extension=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def intermediate_missing_crl_sign(builder: Builder) -> None:
    """
    The ICA Key Usage lacks cRLSign. S/MIME BR 7.1.2.2(e):

    > Bit positions for keyCertSign and cRLSign SHALL be set.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        pathlen=0,
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
        extra_extension=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )

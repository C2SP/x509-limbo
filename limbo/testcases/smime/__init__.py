"""
S/MIME (CA/B Forum S/MIME Baseline Requirements) profile tests.
"""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from limbo.assets import ext
from limbo.models import Feature, KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase

from .eku import *  # noqa: F403
from .ku import *  # noqa: F403
from .san import *  # noqa: F403


@testcase
def valid_smime_chain(builder: Builder) -> None:
    """
    Valid S/MIME chain (root -> EE) with emailProtection EKU,
    rfc822Name SAN, and digitalSignature KU per S/MIME BR 7.1.2.3.
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
def valid_smime_chain_with_intermediate(builder: Builder) -> None:
    """
    Valid S/MIME chain (root -> ICA -> EE). The ICA has emailProtection
    EKU and keyCertSign + cRLSign per S/MIME BR 7.1.2.2(e,g).
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
        .succeeds()
    )


@testcase
def v1_cert(builder: Builder) -> None:
    """
    The EE cert is X.509 v1. S/MIME BR 7.1.1:

    > Certificates SHALL be of type X.509 v3.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(root, unchecked_version=x509.Version.v1, no_extensions=True)

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def ee_basicconstraints_ca_true(builder: Builder) -> None:
    """
    The EE has basicConstraints.cA=TRUE. S/MIME BR 7.1.2.3(d):

    > The cA field SHALL NOT be true.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        basic_constraints=ext(x509.BasicConstraints(True, None), critical=True),
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
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def ee_basicconstraints_pathlen_present(builder: Builder) -> None:
    """
    The EE has basicConstraints with pathLenConstraint. S/MIME BR 7.1.2.3(d):

    > pathLenConstraint field SHALL NOT be present.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        basic_constraints=ext(x509.BasicConstraints(True, 0), critical=True),
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
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def ca_as_leaf(builder: Builder) -> None:
    """
    A CA certificate (cA=TRUE, keyCertSign) is used as the leaf.
    S/MIME BR 7.1.2.3(d):

    > The cA field SHALL NOT be true.
    """

    root = builder.root_ca()
    ica_leaf = builder.intermediate_ca(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("ca@example.com")]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(ica_leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="ca@example.com"))
        .fails()
    )


@testcase
def forbidden_p192_leaf(builder: Builder) -> None:
    """
    The EE has a P-192 key. S/MIME BR 6.1.5:

    > [ECDSA] Ensure that the key represents a valid point on the NIST P-256,
    > NIST P-384, or NIST P-521 elliptic curve.
    """

    root = builder.root_ca()

    leaf_key = ec.generate_private_key(ec.SECP192R1())
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
    )

    builder = (
        builder.client_validation()
        .features([Feature.pedantic_smime_subscriber_key])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def forbidden_p192_root(builder: Builder) -> None:
    """
    The root has a P-192 key. S/MIME BR 6.1.5:

    > [ECDSA] Ensure that the key represents a valid point on the NIST P-256,
    > NIST P-384, or NIST P-521 elliptic curve.
    """

    root_key = ec.generate_private_key(ec.SECP192R1())
    root = builder.root_ca(key=root_key)

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
def forbidden_dsa_leaf(builder: Builder) -> None:
    """
    The EE has a DSA key. S/MIME BR 6.1.5:

    > No other algorithms or key sizes are permitted.
    """

    root = builder.root_ca()

    leaf_key = dsa.generate_private_key(3072)
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
    )

    builder = (
        builder.client_validation()
        .features([Feature.pedantic_smime_subscriber_key])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def forbidden_dsa_root(builder: Builder) -> None:
    """
    The root has a DSA key. S/MIME BR 6.1.5:

    > No other algorithms or key sizes are permitted.
    """

    root_key = dsa.generate_private_key(key_size=3072)
    root = builder.root_ca(key=root_key)

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
def forbidden_weak_rsa_key_in_root(builder: Builder) -> None:
    """
    The root has an RSA-1024 key. S/MIME BR 6.1.5:

    > [RSA] Ensure that the modulus size, when encoded, is at least 2048 bits.
    """

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    root = builder.root_ca(key=root_key)

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
def forbidden_weak_rsa_in_leaf(builder: Builder) -> None:
    """
    The EE has an RSA-1024 key. S/MIME BR 6.1.5:

    > [RSA] Ensure that the modulus size, when encoded, is at least 2048 bits.
    """

    root = builder.root_ca()

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
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
    )

    builder = (
        builder.client_validation()
        .features([Feature.pedantic_smime_subscriber_key])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def forbidden_rsa_not_divisible_by_8_in_root(builder: Builder) -> None:
    """
    The root has an RSA-2052 key. S/MIME BR 6.1.5:

    > [RSA] Ensure that the modulus size, in bits, is evenly divisible by 8.
    """

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2052)
    root = builder.root_ca(key=root_key)

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
def forbidden_rsa_key_not_divisible_by_8_in_leaf(builder: Builder) -> None:
    """
    The EE has an RSA-2052 key. S/MIME BR 6.1.5:

    > [RSA] Ensure that the modulus size, in bits, is evenly divisible by 8.
    """

    root = builder.root_ca()

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2052)
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
    )

    builder = (
        builder.client_validation()
        .features([Feature.pedantic_smime_subscriber_key])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )

"""
S/MIME Subject Alternative Name (SAN) tests.
"""

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from limbo.assets import ext
from limbo.models import KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def exact_rfc822_san(builder: Builder) -> None:
    """
    Valid S/MIME EE with rfc822Name SAN per S/MIME BR 7.1.4.2.1:

    > This extension SHALL contain at least one GeneralName entry
    > of [...] Rfc822Name.
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
def no_san(builder: Builder) -> None:
    """
    The EE has no SAN extension. S/MIME BR 7.1.2.3(h):

    > subjectAlternativeName (SHALL be present)
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=user@example.com"),
        san=None,
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
def san_without_rfc822name(builder: Builder) -> None:
    """
    The EE SAN has only a dNSName, no rfc822Name. S/MIME BR 7.1.4.2.1:

    > This extension SHALL contain at least one GeneralName entry
    > of [...] Rfc822Name.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
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
def san_critical_with_nonempty_subject(builder: Builder) -> None:
    """
    The EE has a critical SAN with a non-empty subject. S/MIME BR 7.1.2.3(h):

    > This extension SHOULD NOT be marked critical unless the subject
    > field is an empty sequence.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=user@example.com"),
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=True,
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
def san_critical_with_empty_subject(builder: Builder) -> None:
    """
    The EE has a critical SAN with an empty subject. S/MIME BR 7.1.2.3(h):

    > This extension SHOULD NOT be marked critical unless the subject
    > field is an empty sequence.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        subject=None,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=True,
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
def mismatch_rfc822_san(builder: Builder) -> None:
    """
    The EE has rfc822Name "user@example.com" but verification is
    against "other@example.com".
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
        .expected_peer_names(PeerName(kind="RFC822", value="other@example.com"))
        .fails()
    )


@testcase
def mismatch_domain_rfc822_san(builder: Builder) -> None:
    """
    The EE has rfc822Name "user@example.com" but verification is
    against "user@example.org".
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
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.org"))
        .fails()
    )


@testcase
def multiple_rfc822_sans(builder: Builder) -> None:
    """
    The EE has multiple rfc822Names; verification matches one of them.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("other@example.com"),
                    x509.RFC822Name("user@example.com"),
                ]
            ),
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

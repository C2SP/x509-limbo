"""
S/MIME Extended Key Usage (EKU) tests.
"""

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from limbo.assets import ext
from limbo.models import Feature, KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def ee_email_protection(builder: Builder) -> None:
    """
    Valid S/MIME EE with emailProtection EKU per S/MIME BR 7.1.2.3(f):

    > id-kp-emailProtection SHALL be present.
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
def ee_missing_email_protection(builder: Builder) -> None:
    """
    The EE has clientAuth but not emailProtection. S/MIME BR 7.1.2.3(f):

    > id-kp-emailProtection SHALL be present.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
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
def ee_without_eku(builder: Builder) -> None:
    """
    The EE has no EKU extension. S/MIME BR 7.1.2.3(f):

    > extKeyUsage (SHALL be present)
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=None,
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
def ee_has_server_auth(builder: Builder) -> None:
    """
    The EE has emailProtection + serverAuth. S/MIME BR 7.1.2.3(f):

    > id-kp-serverAuth [...] SHALL NOT be present.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.SERVER_AUTH]
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
def ee_has_code_signing(builder: Builder) -> None:
    """
    The EE has emailProtection + codeSigning. S/MIME BR 7.1.2.3(f):

    > id-kp-codeSigning [...] SHALL NOT be present.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.CODE_SIGNING]
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
def ee_has_time_stamping(builder: Builder) -> None:
    """
    The EE has emailProtection + timeStamping. S/MIME BR 7.1.2.3(f):

    > id-kp-timeStamping [...] SHALL NOT be present.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.TIME_STAMPING]
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
def ee_has_any_eku(builder: Builder) -> None:
    """
    The EE has emailProtection + anyExtendedKeyUsage. S/MIME BR 7.1.2.3(f):

    > anyExtendedKeyUsage SHALL NOT be present.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
                ]
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
def root_has_eku(builder: Builder) -> None:
    """
    The root has an extKeyUsage extension. S/MIME BR 7.1.2.1(d):

    > extKeyUsage [...] SHALL NOT be present.
    """

    root = builder.root_ca(
        extra_extension=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
    )
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
        .features([Feature.pedantic_smime_eku])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def intermediate_missing_email_protection(builder: Builder) -> None:
    """
    The ICA has serverAuth but not emailProtection. S/MIME BR 7.1.2.2(g):

    > id-kp-emailProtection SHALL be present.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        pathlen=0,
        extra_extension=ext(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
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
        .features([Feature.pedantic_smime_eku])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def intermediate_has_server_auth(builder: Builder) -> None:
    """
    The ICA has emailProtection + serverAuth. S/MIME BR 7.1.2.2(g):

    > id-kp-serverAuth [...] SHALL NOT be present.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        pathlen=0,
        extra_extension=ext(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
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
        .features([Feature.pedantic_smime_eku])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def intermediate_has_any_eku(builder: Builder) -> None:
    """
    The ICA has emailProtection + anyExtendedKeyUsage. S/MIME BR 7.1.2.2(g):

    > anyExtendedKeyUsage [...] SHALL NOT be present.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        pathlen=0,
        extra_extension=ext(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
                ]
            ),
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
        .features([Feature.pedantic_smime_eku])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def intermediate_has_code_signing(builder: Builder) -> None:
    """
    The ICA has emailProtection + codeSigning. S/MIME BR 7.1.2.2(g):

    > id-kp-codeSigning [...] SHALL NOT be present.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        pathlen=0,
        extra_extension=ext(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.CODE_SIGNING]
            ),
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
        .features([Feature.pedantic_smime_eku])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def intermediate_has_time_stamping(builder: Builder) -> None:
    """
    The ICA has emailProtection + timeStamping. S/MIME BR 7.1.2.2(g):

    > id-kp-timeStamping [...] SHALL NOT be present.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        pathlen=0,
        extra_extension=ext(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.TIME_STAMPING]
            ),
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
        .features([Feature.pedantic_smime_eku])
        .extended_key_usage([KnownEKUs.email_protection])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )

"""
CRL structure tests.
"""

from datetime import datetime, timedelta

from cryptography import x509

from limbo.assets import EPOCH
from limbo.models import Feature, PeerKind, PeerName
from limbo.testcases._core import Builder, ext, testcase


@testcase
def crl_invalid_signature(builder: Builder) -> None:
    """
    Tests an invalid CRL that revokes the leaf but has a signature that does not
    correspond to the root.

    The CRL claims to be issued by the root CA (matching issuer name and AKI),
    but is actually signed by a random ephemeral key.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)

    aki = ext(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root.key.public_key()),
        critical=False,
    )

    # Revoke a random certificate, not the leaf. We need to distinguish between a failure to build
    # the chain and a failure to parse the CRL.
    crl = builder.crl(
        signer=None,
        issuer=root.cert.subject,
        aki=aki,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl
    ).validation_time(validation_time).fails()


@testcase
def crl_wrong_signing_key(builder: Builder) -> None:
    """
    Tests that an invalid CRL signed by the wrong key is rejected.

    Two root CAs are trusted. The CRL's issuer name matches root_ca_1 but the
    CRL is signed with root_ca_2's key. Validators MUST reject the CRL because
    the signature does not verify against root_ca_1's public key.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root_ca_1 = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Root CA 1")]),
    )

    root_ca_2 = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Root CA 2")]),
    )
    leaf = builder.leaf_cert(parent=root_ca_1)

    crl = builder.crl(
        signer=root_ca_2,
        issuer=root_ca_1.cert.subject,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(
        root_ca_1, root_ca_2
    ).peer_certificate(leaf).expected_peer_name(
        PeerName(kind=PeerKind.DNS, value="example.com")
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def crl_empty(builder: Builder) -> None:
    """
    Tests that an valid but empty CRL (with no revocation entries) is accepted.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)
    crl = builder.crl(signer=root, revoked=[])

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl
    ).validation_time(validation_time).succeeds()


@testcase
def crl_very_large(builder: Builder) -> None:
    """
    Tests that a valid CRL with 10,000 revoked entries is accepted.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    leaf = builder.leaf_cert(parent=root)

    revoked = [
        x509.RevokedCertificateBuilder()
        .serial_number(x509.random_serial_number())
        .revocation_date(EPOCH)
        .build()
        for _ in range(10_000)
    ]

    crl = builder.crl(signer=root, revoked=revoked)

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl
    ).validation_time(validation_time).succeeds()


@testcase
def crl_unknown_critical_extension(builder: Builder) -> None:
    """
    Tests that a CRL with an unknown critical extension is rejected.

    Per RFC 5280 5.2, CRLs that contain unknown critical extensions MUST NOT be
    used to determine the revocation status of certificates.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)

    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.1"), b""),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl
    ).validation_time(validation_time).fails()


@testcase
def crl_unknown_noncritical_extension(builder: Builder) -> None:
    """
    Tests that a CRL with an unknown non-critical extension is accepted.

    Per RFC 5280 5.2, unknown non-critical extensions MUST be ignored. The CRL
    should be accepted by the validator and the chain should build.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)

    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.1"), b""),
            critical=False,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl
    ).validation_time(validation_time).succeeds()


@testcase
def crl_duplicate_revoked_serial(builder: Builder) -> None:
    """
    Tests that a CRL with a duplicate revoked serial number is rejected.

    For more context, see <https://github.com/cabforum/servercert/issues/589>.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)

    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(x509.random_serial_number())
        .revocation_date(validation_time - timedelta(days=1))
        .build()
    )
    crl = builder.crl(signer=root, revoked=[revoked, revoked])

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl
    ).validation_time(validation_time).fails()

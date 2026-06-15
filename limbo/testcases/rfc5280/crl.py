"""
RFC 5280 CRL tests.
"""

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from limbo.assets import EPOCH
from limbo.models import Feature, Importance, PeerKind, PeerName
from limbo.testcases._core import Builder, ext, testcase


@testcase
def revoked_certificate_with_crl(builder: Builder) -> None:
    """
    Tests a Certificate Revocation List (CRL) that revokes a certificate.

    Produces a simple test case where a certificate has been revoked by the CA
    through a CRL. The CA certificate and CRL are provided, and the leaf certificate
    is expected to be rejected due to its revoked status.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    # Create a root CA
    root = builder.root_ca()

    # Create a leaf certificate
    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "revoked.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("revoked.example.com")]), critical=False),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.cert.serial_number)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind=PeerKind.DNS, value="revoked.example.com")
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def crlnumber_missing(builder: Builder) -> None:
    """
    Tests handling of a CRL that's missing the `CRLNumber` extension.

    Per RFC 5280 5.2.3 this extension MUST be included in a CRL.
    """

    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "missing-crlnumber.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("missing-crlnumber.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate here, not the leaf,
            # to ensure that we fail because the CRL is invalid,
            # not because the leaf is revoked.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(leaf.cert.not_valid_before_utc + timedelta(seconds=1))
            .build()
        ],
        crl_number=None,
    )

    builder = (
        builder.features([Feature.has_crl])
        .importance(Importance.HIGH)
        .server_validation()
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind=PeerKind.DNS, value="missing-crlnumber.example.com"))
        .crls(crl)
        .validation_time(leaf.cert.not_valid_before_utc + timedelta(seconds=2))
        .fails()
    )


@testcase
def certificate_not_on_crl(builder: Builder) -> None:
    """
    Tests a certificate that is not present on any of the CRLs.

    The leaf certificate should be accepted per the procedure in RFC 5280 6.3.3.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build(),
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=2))
            .build(),
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind=PeerKind.DNS, value="example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def certificate_serial_on_crl_different_issuer(builder: Builder) -> None:
    """
    Tests a certificate whose serial number is found on a CRL, but that CRL
    has a different issuer than the certificate. This leaf certificate should
    be accepted per the procedure in RFC 5280 6.3.3.

    Produces a test case where a certificate's serial number appears on a CRL,
    but the CRL is issued by a different CA than the one that issued the
    certificate. The certificate should be accepted since the CRL from a
    different issuer should not affect this certificate's validity.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root_ca_1 = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA 1")]),
    )

    root_ca_2 = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA 2")]),
    )

    leaf = builder.leaf_cert(
        parent=root_ca_1,
    )

    crl1 = builder.crl(
        signer=root_ca_1,
        revoked=[],
    )

    crl2 = builder.crl(
        signer=root_ca_2,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.cert.serial_number)  # Same serial as our leaf
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root_ca_1, root_ca_2).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl1, crl2
    ).validation_time(validation_time).succeeds()


@testcase
def crlnumber_critical(builder: Builder) -> None:
    """
    Tests handling of a CRL that has a critical `CRLNumber` extension.

    Per RFC 5280 5.2.3, the `CRLNumber` extension is mandatory but MUST
    be marked as non-critical.
    """

    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "crlnumber-critical.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("crlnumber-critical.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate here, not the leaf,
            # to ensure that we fail because the CRL is invalid,
            # not because the leaf is revoked.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(leaf.cert.not_valid_before_utc + timedelta(seconds=1))
            .build()
        ],
        crl_number=ext(x509.CRLNumber(12345), critical=True),
    )

    builder = (
        builder.features([Feature.has_crl])
        .importance(Importance.HIGH)
        .server_validation()
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind=PeerKind.DNS, value="crlnumber-critical.example.com"))
        .crls(crl)
        .validation_time(leaf.cert.not_valid_before_utc + timedelta(seconds=2))
        .fails()
    )


@testcase
def issuer_missing_crlsign(builder: Builder) -> None:
    """
    Tests CRL validation when the CA issuer has a keyUsage extension with only
    `keyCertSign` set (no `cRLSign`).

    Per RFC 5280 Section 4.2.1.3, if the keyUsage extension is present in a CA
    certificate, the `cRLSign` bit MUST be set if the CA will be issuing CRLs.
    A CRL signed by a CA without the `cRLSign` bit should be rejected.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(
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
            critical=False,
        ),
    )

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "issuer-missing-crlsign.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("issuer-missing-crlsign.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate, not the leaf, to ensure failure is due
            # to issuer authorization, not revocation status.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind=PeerKind.DNS, value="issuer-missing-crlsign.example.com")
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def issuer_no_keyusage_extension(builder: Builder) -> None:
    """
    Tests CRL validation when the CA issuer has no keyUsage extension.

    Per RFC 5280 Section 6.3.3(f), the CRL validation algorithm states:
    "If a key usage extension is present in the CRL issuer's certificate,
    verify that the cRLSign bit is set." This conditional check means that
    when keyUsage is absent, there is no cRLSign verification to perform.

    Note: RFC 5280 Section 4.2.1.3 states that "Conforming CAs MUST include
    this extension in certificates that contain public keys that are used to
    validate digital signatures on other public key certificates or CRLs."
    However, this is a certificate issuance requirement, not a validation
    requirement. The validation algorithm in Section 6.3.3(f) explicitly uses
    conditional language ("If... is present").
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(
        key_usage=None,
    )

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "issuer-no-keyusage.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("issuer-no-keyusage.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate, not the leaf.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind=PeerKind.DNS, value="issuer-no-keyusage.example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def issuer_valid_crlsign_and_keycertsign(builder: Builder) -> None:
    """
    Tests CRL validation when the CA issuer has a keyUsage extension with both
    `keyCertSign` and `cRLSign` bits set.

    This is the standard configuration for a CA that issues both certificates
    and CRLs. The CRL should be accepted.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(
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
            critical=False,
        ),
    )

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "issuer-valid-crlsign.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("issuer-valid-crlsign.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate, not the leaf.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind=PeerKind.DNS, value="issuer-valid-crlsign.example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def crl_invalid_signature(builder: Builder) -> None:
    """
    Tests an invalid CRL that revokes the leaf but has a signature that does not
    correspond to the root. Per RFC 5280 6.3.3(g), this CRL should not be
    considered as authoritative for the leaf.

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
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def crl_wrong_signing_key(builder: Builder) -> None:
    """
    Tests that an invalid CRL signed by the wrong key is rejected per
    RFC 5280 6.3.3(g).

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
    ).peer_certificate(leaf).crls(crl).validation_time(validation_time).fails()


@testcase
def crl_empty(builder: Builder) -> None:
    """
    Tests that an valid but empty CRL (with no revocation entries) is accepted,
    per RFC 5280 5.1.2.6.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)
    crl = builder.crl(signer=root, revoked=[])

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).succeeds()


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
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def crl_unknown_critical_extension(builder: Builder) -> None:
    """
    Tests that a CRL with an unknown critical top-level extension is rejected.

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
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def crl_unknown_noncritical_extension(builder: Builder) -> None:
    """
    Tests that a CRL with an unknown non-critical top-level extension is accepted.

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
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def entry_unknown_critical_extension(builder: Builder) -> None:
    """
    Tests that a CRL entry with an unknown critical extension is rejected per
    RFC 5280 5.3.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)

    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf.cert.serial_number)
        .revocation_date(validation_time - timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.1"), b""),
            critical=True,
        )
        .build()
    )
    crl = builder.crl(
        signer=root,
        revoked=[revoked],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def entry_unknown_noncritical_extension(builder: Builder) -> None:
    """
    Tests that a CRL entry with an unknown non-critical extension is accepted
    and revokes the certificate per RFC 5280 5.3.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)

    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf.cert.serial_number)
        .revocation_date(validation_time - timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.1"), b""),
            critical=False,
        )
        .build()
    )
    crl = builder.crl(
        signer=root,
        revoked=[revoked],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


def _cdp_names(names: list[x509.GeneralName]) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=names,
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )


def _idp(
    *,
    full_name: list[x509.GeneralName] | None = None,
    only_contains_user_certs: bool = False,
    only_contains_ca_certs: bool = False,
    only_contains_attribute_certs: bool = False,
) -> x509.IssuingDistributionPoint:
    return x509.IssuingDistributionPoint(
        full_name=full_name,
        relative_name=None,
        only_contains_user_certs=only_contains_user_certs,
        only_contains_ca_certs=only_contains_ca_certs,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=only_contains_attribute_certs,
    )


@testcase
def idp_cdp_scope_mismatch(builder: Builder) -> None:
    """
    Tests a CRL whose issuing distribution point does not match the certificate CDP.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, the certificate distribution
    point name must match the CRL issuing distribution point name when both are
    present.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    cdp_uri = "http://example.com/cdp.crl"
    idp_uri = "http://example.com/other.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(
            _cdp_names([x509.UniformResourceIdentifier(cdp_uri)]),
            critical=False,
        ),
    )
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(idp_uri)]),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_cdp_scope_match(builder: Builder) -> None:
    """
    Tests a CRL whose issuing distribution point matches the certificate CDP.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, a CRL whose issuing distribution
    point name matches the certificate distribution point name is applicable.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    uri = "http://example.com/partition.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(
            _cdp_names([x509.UniformResourceIdentifier(uri)]),
            critical=False,
        ),
    )
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(uri)]),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def idp_only_contains_user_certs_ca_target(builder: Builder) -> None:
    """
    Tests an IDP scoped to user certificates against a CA certificate target.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, CRLs whose IDP scope excludes
    the target certificate must be rejected.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
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
            critical=False,
        ),
    )
    leaf = builder.leaf_cert(intermediate)
    root_crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(_idp(only_contains_user_certs=True), critical=True),
    )
    # Also generate a CRL authoritative for our leaf to satisfy path builders that require CRLs
    # for all candidate certificates.
    intermediate_crl = builder.crl(signer=intermediate, revoked=[])

    builder.features([Feature.has_crl]).server_validation().trusted_certs(
        root
    ).untrusted_intermediates(intermediate).peer_certificate(leaf).crls(
        root_crl, intermediate_crl
    ).validation_time(validation_time).fails()


@testcase
def idp_only_contains_ca_certs_ee_target(builder: Builder) -> None:
    """
    Tests an IDP scoped to CA certificates against an EE certificate target.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, CRLs whose IDP scope excludes
    the target certificate must be rejected.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(_idp(only_contains_ca_certs=True), critical=True),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_present_certificate_missing_cdp(builder: Builder) -> None:
    """
    Tests a CRL whose issuing distribution point cannot match because the
    certificate has no CRL distribution points extension.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, an iDP-scoped CRL must match the
    certificate distribution point.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    uri = "http://example.com/partition.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(uri)]),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_only_contains_attribute_certs(builder: Builder) -> None:
    """
    Tests an IDP scoped to attribute certificates against a public-key certificate.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, CRLs whose IDP scope excludes
    the target certificate must be rejected.
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
        extra_extension=ext(_idp(only_contains_attribute_certs=True), critical=True),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def this_update_in_future(builder: Builder) -> None:
    """
    Tests a future-dated CRL with thisUpdate set after the validation time.

    Validation should fail as the CRL is not yet effective.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )

    # No revoked certificates; validation should fail by virtue of the CRL being
    # invalid with regards to the validation time.
    crl = builder.crl(
        signer=root,
        last_update=validation_time + timedelta(days=1),
        next_update=validation_time + timedelta(days=30),
        revoked=[],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def next_update_in_past(builder: Builder) -> None:
    """
    Tests an expired CRL with nextUpdate set before validation time.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )

    crl = builder.crl(
        signer=root,
        last_update=validation_time - timedelta(days=60),
        next_update=validation_time - timedelta(days=30),
        revoked=[],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def revocation_date_in_future(builder: Builder) -> None:
    """
    Tests that a CRL entry with a revocationDate in the future causes validation failure.

    The certificate is still considered revoked since its serial appears in the CRL,
    even though the revocation date is set after the validation time.

    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )

    revoked_cert = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf.cert.serial_number)
        .revocation_date(validation_time + timedelta(days=1))
        .build()
    )

    crl = builder.crl(
        signer=root,
        last_update=validation_time - timedelta(days=1),
        next_update=validation_time + timedelta(days=30),
        revoked=[revoked_cert],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def revocation_date_before_not_before(builder: Builder) -> None:
    """
    Tests that a CRL entry with a revocationDate before the certificate's notBefore
    causes validation failure.

    The certificate is still considered revoked since its serial appears in the CRL,
    even though the revocation date predates the certificate's existence.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        not_before=validation_time - timedelta(days=30),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )

    revoked_cert = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf.cert.serial_number)
        .revocation_date(validation_time - timedelta(days=60))
        .build()
    )

    crl = builder.crl(
        signer=root,
        last_update=validation_time - timedelta(days=1),
        next_update=validation_time + timedelta(days=30),
        revoked=[revoked_cert],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def crl_validity_no_overlap(builder: Builder) -> None:
    """
    Tests that a CRL whose validity period entirely predates the leaf certificate's
    notBefore causes validation failure.

    The certificate was issued after the CRL's validity window closed, so there is
    no applicable CRL for the certificate's validity period. Validators should reject
    this as there is no current or applicable CRL.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    # Build the CRL first, covering a past period
    crl = builder.crl(
        signer=root,
        last_update=validation_time - timedelta(days=365),
        next_update=validation_time - timedelta(days=180),
        revoked=[],
    )

    # Leaf cert was issued after the CRL expired
    leaf = builder.leaf_cert(
        parent=root,
        not_before=validation_time - timedelta(days=30),
        not_after=validation_time + timedelta(days=30),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()

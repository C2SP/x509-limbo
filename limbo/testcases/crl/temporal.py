"""
CRL temporal tests: validity periods, revocation dates, etc.
"""

from datetime import datetime, timedelta

from cryptography import x509

from limbo.models import Feature, Importance
from limbo.testcases._core import Builder, ext, testcase


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

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).crls(crl).validation_time(
        validation_time
    ).fails()


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

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).crls(crl).validation_time(
        validation_time
    ).fails()


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

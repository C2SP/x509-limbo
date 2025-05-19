"""
CRL (Certificate Revocation List) tests.
"""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .. import models
from ..models import Feature, Importance, PeerKind
from ._core import Builder, ext, testcase


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

    # Create a CRL revoking the leaf certificate
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(root.cert.subject)
    crl_builder = crl_builder.last_update(validation_time - timedelta(days=30))
    crl_builder = crl_builder.next_update(validation_time + timedelta(days=30))

    # Add the revoked certificate with its serial number
    revoked_cert = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf.cert.serial_number)
        .revocation_date(validation_time - timedelta(days=1))
        .build()
    )
    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    # Sign the CRL with the root key
    crl = crl_builder.sign(root.key, hashes.SHA256())

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="revoked.example.com")
    ).crls(crl).validation_time(validation_time).fails()

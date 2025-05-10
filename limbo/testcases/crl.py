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

    # Create a root CA
    root = builder.root_ca(
        basic_constraints=ext(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ),
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "X.509 Limbo CRL Test CA"),
            ]
        ),
    )

    serial_number = 1000

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
        serial=serial_number,
    )

    # Issue a time in the past
    now = datetime.now(timezone.utc)
    revocation_date = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

    # Create a CRL revoking the leaf certificate
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(root.cert.subject)
    crl_builder = crl_builder.last_update(revocation_date)
    crl_builder = crl_builder.next_update(revocation_date + timedelta(days=30))

    # Add the revoked certificate with its serial number
    revoked_cert = (
        x509.RevokedCertificateBuilder()
        .serial_number(serial_number)
        .revocation_date(revocation_date)
        .build()
    )
    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    # Sign the CRL with the root key
    crl = crl_builder.sign(root.key, hashes.SHA256())

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).untrusted_intermediates().peer_certificate(
        leaf
    ).key_usage([]).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="revoked.example.com")
    ).expected_peer_names().extended_key_usage([]).signature_algorithms([]).crls(crl).fails()

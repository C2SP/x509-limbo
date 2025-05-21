"""
CRL (Certificate Revocation List) tests.
"""

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from limbo.assets import ASSETS_PATH, PEMCertificate

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
            critical=True,
        )
    )

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


def _external_crl_testcase(builder: Builder, name: str) -> Builder:
    validation_time = datetime.fromisoformat("2025-01-15T00:00:00Z")
    root = (ASSETS_PATH / "crl_cases_ca.pem").read_text()
    leaf = (ASSETS_PATH / "crl_cases_leaf.pem").read_text()
    crl = (ASSETS_PATH / f"{name}.crl").read_bytes()

    return (
        builder.features([Feature.has_crl])
        .importance(Importance.HIGH)
        .server_validation()
        .trusted_certs(PEMCertificate(root))
        .peer_certificate(PEMCertificate(leaf))
        .expected_peer_name(models.PeerName(kind=PeerKind.DNS, value="revoked.example.com"))
        .crls(crl)
        .validation_time(validation_time)
    )


@testcase
def crl_invalid_version(builder: Builder) -> None:
    """
    Tests a Certificate Revocation List (CRL) with an invalid version.

    Encapsulates a simple test case where a certificate has been revoked by the CA
    through a malformed CRL with an invalid `version` field. The CA certificate
    and CRL are provided, and the leaf certificate is expected to be accepted as
    the CRL is invalid.
    """

    _external_crl_testcase(builder, "bad_version").succeeds()


@testcase
def crl_update_generalizedtime_2025(builder: Builder) -> None:
    """
    Tests a Certificate Revocation List (CRL) with invalid (re)issue date encodings.

    The CRL includes `This Update` and `Next Update` fields encoding dates in the year
    2025 as `GeneralizedTime`. This is forbidden per RFC 5280 5.2.1.4 and 5.2.1.5, thus
    the leaf certificate that the CRL revokes should be accepted.
    """

    _external_crl_testcase(builder, "generalized_time_2025").succeeds()

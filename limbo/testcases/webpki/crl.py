"""
CABF Baseline Requirements CRL tests.
"""

from datetime import datetime, timedelta

from cryptography import x509

from limbo.models import Feature
from limbo.testcases._core import Builder, testcase


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
    ).crls(crl).validation_time(validation_time).fails()

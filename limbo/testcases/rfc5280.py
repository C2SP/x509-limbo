"""
RFC5280 profile tests.
"""

from cryptography import x509

from limbo.assets import ee_cert
from limbo.testcases._core import Builder, testcase

# TODO: Intentionally mis-matching algorithm fields.


@testcase
def test_empty_issuer(builder: Builder) -> None:
    # Intentionally empty issuer name.
    issuer = x509.Name([])
    subject = x509.Name.from_rfc4514_string("CN=empty-issuer")
    root = builder.root_ca(issuer=issuer, subject=subject)
    leaf = ee_cert(root)

    builder = builder.client_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


# TODO: Empty serial number, overlength serial number.

# TODO: Critical AKI

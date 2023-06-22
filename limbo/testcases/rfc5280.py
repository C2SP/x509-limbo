"""
RFC5280 profile tests.
"""

from cryptography import x509

from limbo.assets import ee_cert
from limbo.testcases._core import Builder, testcase

# TODO: Intentionally mis-matching algorithm fields.


@testcase
def empty_issuer(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is invalid solely because of the EE cert's construction:
    it has an empty issuer name, which isn't allowed under the RFC 5280 profile.
    """
    # Intentionally empty issuer name.
    issuer = x509.Name([])
    subject = x509.Name.from_rfc4514_string("CN=empty-issuer")
    root = builder.root_ca(issuer=issuer, subject=subject)
    leaf = ee_cert(root)

    builder = builder.client_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


# TODO: Empty serial number, overlength serial number.

# TODO: Critical AKI

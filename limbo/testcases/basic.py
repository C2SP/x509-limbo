"""
Basic certificate parsing and handling tests.
"""

from cryptography import x509

from limbo.assets import ext
from limbo.testcases._core import Builder, testcase


@testcase
def duplicate_extensions(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is invalid solely because of the EE cert's construction:
    it contains multiple X.509v3 extensions with the same OID, which
    is prohibited.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
        extra_extension=ext(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()

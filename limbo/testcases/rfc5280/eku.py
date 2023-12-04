"""
RFC5280 Extended Key Usage (EKU) tests.
"""


from cryptography import x509

from limbo.assets import ext
from limbo.models import KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def ee_wrong_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The chain is correctly constructed, but the EE cert contains
    an Extended Key Usage extension that contains just `id-kp-clientAuth`
    while the validator expects `id-kp-serverAuth`.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .extended_key_usage([KnownEKUs.server_auth])
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .fails()
    )


@testcase
def ee_without_eku(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> EE
    ```

    The EE is missing an extKeyUsage extension, which is permitted under
    RFC 5280 4.2.1.12.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(root, eku=None)

    builder = (
        builder.conflicts_with("webpki::eku::ee-without-eku")
        .server_validation()
        .trusted_certs(root)
        .peer_certificate(leaf)
        .succeeds()
    )

"""
RFC 5280 Subject Key Identifier (SKI) testcases.
"""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from limbo.testcases._core import Builder, ext, testcase


@testcase
def critical_ski(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert has an SKI extension marked as critical, which is disallowed
    under the [RFC 5280 profile].

    > Conforming CAs MUST mark this extension as non-critical.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    """
    key = ec.generate_private_key(ec.SECP256R1())
    root = builder.root_ca(
        ski=ext(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=True),
    )
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def root_missing_ski(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert is missing the SKI extension, which is disallowed under the
    [RFC 5280 profile].

    > To facilitate certification path construction, this extension MUST
    > appear in all conforming CA certificates, that is, all certificates
    > including the basic constraints extension (Section 4.2.1.9) where the
    > value of cA is TRUE.

    Note: for roots, the SKI should be the same value as the AKI, therefore,
    this extension isn't strictly necessary, although required by the RFC.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    """
    root = builder.root_ca(ski=None)
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def intermediate_missing_ski(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The intermediate cert is missing the SKI extension, which is disallowed under the
    [RFC 5280 profile].

    > To facilitate certification path construction, this extension MUST
    > appear in all conforming CA certificates, that is, all certificates
    > including the basic constraints extension (Section 4.2.1.9) where the
    > value of cA is TRUE.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    """
    root = builder.root_ca()
    intermediate = builder.intermediate_ca(root, ski=None)
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .fails()
    )

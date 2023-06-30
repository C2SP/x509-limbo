"""
RFC5280 profile tests.
"""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from limbo.assets import ee_cert, ext
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


@testcase
def unknown_critical_extension(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert has an extension, 1.3.6.1.4.1.55738.666.1, that no implementation
    should recognize. As this unrecognized extension is marked as critical, a
    chain should not be built with this EE.
    """
    root = builder.root_ca()
    leaf = ee_cert(
        root,
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.1"), b""),
            critical=True,
        ),
    )

    builder = builder.client_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


# TODO: Empty serial number, overlength serial number.


@testcase
def critical_aki(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert has an AKI extension marked as critical, which is disallowed
    under the RFC 5280 profile.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    root = builder.root_ca(
        key=key,
        aki=ext(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=True
        ),
    )
    leaf = ee_cert(root)

    builder = builder.client_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()

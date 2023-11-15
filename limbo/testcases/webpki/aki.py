"""
Authority Key Identifier (AKI)-specific Web PKI tests.
"""

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec

from limbo.assets import ext
from limbo.testcases._core import Builder, testcase


@testcase
def root_with_aki_missing_keyidentifier(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert incudes the authorityKeyIdentifier extension but without
    the keyIdentifier field, which is required under the [CA/B BR profile]:

    > 7.1.2.1.3 Root CA Authority Key Identifier
    > Field                 Description
    > ...
    > keyIdentifier         MUST be present. MUST be identical to the subjectKeyIdentifier field.

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
    """

    aki = x509.AuthorityKeyIdentifier(
        key_identifier=None, authority_cert_issuer=None, authority_cert_serial_number=None
    )
    root = builder.root_ca(aki=ext(aki, critical=False))
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def root_with_aki_authoritycertissuer(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert includes the authorityKeyIdentifier extension with the
    authorityCertIssuer field, which is forbidden under the [CA/B BR profile]:

    > 7.1.2.1.3 Root CA Authority Key Identifier
    > Field                 Description
    > ...
    > authorityCertIssuer   MUST NOT be present

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
    """

    key = ec.generate_private_key(ec.SECP256R1())
    dirname = x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myCN")]))
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
    # Manually add the authorityCertIssuer field, since cryptography's API doesn't allow to
    # add it without also specifying the authorityCertSerialNumber field
    aki._authority_cert_issuer = [dirname]

    root = builder.root_ca(key=key, aki=ext(aki, critical=False))
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def root_with_aki_authoritycertserialnumber(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert includes the authorityKeyIdentifier extension with the
    authorityCertSerialNumber field, which is forbidden under the
    [CA/B BR profile]:

    > 7.1.2.1.3 Root CA Authority Key Identifier
    > Field                         Description
    > ...
    > authorityCertSerialNumber     MUST NOT be present

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
    """

    key = ec.generate_private_key(ec.SECP256R1())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
    # Manually add the authorityCertSerialNumber field, since cryptography's
    # API doesn't allow to add it without also specifying the
    # authorityCertIssuer field
    aki._authority_cert_serial_number = 1234

    root = builder.root_ca(key=key, aki=ext(aki, critical=False))
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def root_with_aki_all_fields(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert includes the authorityKeyIdentifier extension with the
    authorityCertIssuer and authorityCertSerialNumber fields, which is
    forbidden under the [CA/B BR profile]:

    > 7.1.2.1.3 Root CA Authority Key Identifier
    > Field                         Description
    > ...
    > authorityCertIssuer           MUST NOT be present
    > authorityCertSerialNumber     MUST NOT be present

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
    """

    key = ec.generate_private_key(ec.SECP256R1())
    key_identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        key.public_key()
    ).key_identifier
    dirname = x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myCN")]))
    aki = x509.AuthorityKeyIdentifier(key_identifier, [dirname], 1234)
    root = builder.root_ca(key=key, aki=ext(aki, critical=False))
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def root_with_aki_ski_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert is self-signed contains an authorityKeyIdentifier, but
    the keyIdentifier field doesn't match the subjectKeyIdentifier field
    as required under the CA/B BR profile.
    """
    throwaway_key = ec.generate_private_key(ec.SECP256R1())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(throwaway_key.public_key())
    root = builder.root_ca(aki=ext(aki, critical=False), ski=True)
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()

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
    the keyIdentifier field, which is required under CABF:

    > 7.1.2.1.3 Root CA Authority Key Identifier
    > Field                 Description
    > ...
    > keyIdentifier         MUST be present. MUST be identical to the subjectKeyIdentifier field.
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
    authorityCertIssuer field, which is forbidden under CABF:

    > 7.1.2.1.3 Root CA Authority Key Identifier
    > Field                 Description
    > ...
    > authorityCertIssuer   MUST NOT be present

    RFC 5280 requires authorityCertIssuer and authorityCertSerialNumber to
    appear together (see the AuthorityKeyIdentifier definition in Appendix A.1):

    > authorityCertIssuer and authorityCertSerialNumber MUST both
    > be present or both be absent

    The authorityCertSerialNumber field is therefore present as well, so that
    the extension is well-formed and the chain fails because of the CABF rule
    and not because of an RFC 5280 syntax violation.
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

    RFC 5280 requires authorityCertIssuer and authorityCertSerialNumber to
    appear together (see the AuthorityKeyIdentifier definition in Appendix A.1):

    > authorityCertIssuer and authorityCertSerialNumber MUST both
    > be present or both be absent

    The authorityCertIssuer field is therefore present as well, so that the
    extension is well-formed and the chain fails because of the CABF rule and
    not because of an RFC 5280 syntax violation.
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
def root_with_aki_all_fields(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert includes the authorityKeyIdentifier extension with the
    authorityCertIssuer and authorityCertSerialNumber fields, which is
    forbidden under CABF:

    > 7.1.2.1.3 Root CA Authority Key Identifier
    > Field                         Description
    > ...
    > authorityCertIssuer           MUST NOT be present
    > authorityCertSerialNumber     MUST NOT be present
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
    as required under CABF.
    """
    throwaway_key = ec.generate_private_key(ec.SECP256R1())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(throwaway_key.public_key())
    root = builder.root_ca(aki=ext(aki, critical=False), ski=True)
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()

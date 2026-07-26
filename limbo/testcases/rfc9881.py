"""
RFC 9881 (ML-DSA in X.509) testcases.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import mldsa

from limbo.assets import ext
from limbo.models import Feature, Importance, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def ml_dsa_44(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> EE
    ```

    Both certificates convey ML-DSA-44 keys, and the root signs for the EE with
    its ML-DSA-44 key, as described in RFC 9881 3 and RFC 9881 4.
    """
    root = builder.root_ca(key=mldsa.MLDSA44PrivateKey.generate())
    leaf = builder.leaf_cert(root, key=mldsa.MLDSA44PrivateKey.generate())

    builder = builder.server_validation().features([Feature.has_mldsa])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def ml_dsa_65(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> EE
    ```

    Both certificates convey ML-DSA-65 keys, and the root signs for the EE with
    its ML-DSA-65 key, as described in RFC 9881 3 and RFC 9881 4.
    """
    root = builder.root_ca(key=mldsa.MLDSA65PrivateKey.generate())
    leaf = builder.leaf_cert(root, key=mldsa.MLDSA65PrivateKey.generate())

    builder = builder.server_validation().features([Feature.has_mldsa])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def ml_dsa_87(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> EE
    ```

    Both certificates convey ML-DSA-87 keys, and the root signs for the EE with
    its ML-DSA-87 key, as described in RFC 9881 3 and RFC 9881 4.
    """
    root = builder.root_ca(key=mldsa.MLDSA87PrivateKey.generate())
    leaf = builder.leaf_cert(root, key=mldsa.MLDSA87PrivateKey.generate())

    builder = builder.server_validation().features([Feature.has_mldsa])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def ml_dsa_44_bad_signature(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE certificate names the root as its issuer, but is signed with an
    ML-DSA-44 key that isn't the root's. Implementations that don't actually
    verify ML-DSA signatures will accept this chain.
    """
    root_key = mldsa.MLDSA44PrivateKey.generate()
    root = builder.root_ca(key=root_key)

    # NOTE: The impostor shares the root's subject, so that the EE below still
    # chains up to the (trusted) root by name. Its AKI is overridden to the
    # root's key identifier for the same reason.
    impostor = builder.root_ca(key=mldsa.MLDSA44PrivateKey.generate())
    leaf = builder.leaf_cert(
        impostor,
        key=mldsa.MLDSA44PrivateKey.generate(),
        aki=ext(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.has_mldsa])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def ml_dsa_44_key_encipherment(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE conveys an ML-DSA-44 key, but asserts `keyEncipherment` in its
    `keyUsage` extension. ML-DSA keys can't encrypt data, so this is forbidden
    under RFC 9881 5:

    > ML-DSA subject public keys cannot be used to establish keys or encrypt
    > data, so the keyUsage extension MUST NOT have any of the following bits
    > set: keyEncipherment, dataEncipherment, keyAgreement, encipherOnly,
    > decipherOnly

    Most implementations don't check the asserted key usages against the
    subject key's type, and will accept this chain.
    """
    root = builder.root_ca(key=mldsa.MLDSA44PrivateKey.generate())
    leaf = builder.leaf_cert(
        root,
        key=mldsa.MLDSA44PrivateKey.generate(),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )

    builder = (
        builder.server_validation()
        .features([Feature.has_mldsa, Feature.pedantic_rfc5280])
        .importance(Importance.LOW)
    )
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def ml_dsa_44_key_agreement(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE conveys an ML-DSA-44 key, but asserts `keyAgreement` in its
    `keyUsage` extension. ML-DSA keys can't establish keys, so this is
    forbidden under RFC 9881 5:

    > ML-DSA subject public keys cannot be used to establish keys or encrypt
    > data, so the keyUsage extension MUST NOT have any of the following bits
    > set: keyEncipherment, dataEncipherment, keyAgreement, encipherOnly,
    > decipherOnly

    Most implementations don't check the asserted key usages against the
    subject key's type, and will accept this chain.
    """
    root = builder.root_ca(key=mldsa.MLDSA44PrivateKey.generate())
    leaf = builder.leaf_cert(
        root,
        key=mldsa.MLDSA44PrivateKey.generate(),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )

    builder = (
        builder.server_validation()
        .features([Feature.has_mldsa, Feature.pedantic_rfc5280])
        .importance(Importance.LOW)
    )
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()

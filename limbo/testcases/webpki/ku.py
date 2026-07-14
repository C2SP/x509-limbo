"""
CABF BRs for keyUsage.
"""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from limbo.assets import ext
from limbo.testcases._core import Builder, testcase


@testcase
def ee_rsa_without_any_usages(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert
    conveys an RSA key without setting any explicit `keyUsage`.

    Per CABF 7.1.2.7.11, at least one Key Usage MUST be set
    on subscriber certificates conveying RSA keys.
    """

    root = builder.root_ca()
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ee = builder.leaf_cert(
        root,
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
        key=ee_key,
    )

    builder.server_validation().trusted_certs(root).peer_certificate(ee).fails()


@testcase
def ee_ecc_without_digitalsignature(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert
    conveys an ECC key without setting `keyUsage:digitalSignature`.

    Per CABF 7.1.2.7.11, the `digitalSignature` usage MUST be set
    on subscriber certificates conveying ECC keys.
    """

    root = builder.root_ca()
    ee_key = ec.generate_private_key(ec.SECP256R1())
    ee = builder.leaf_cert(
        root,
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ),
        key=ee_key,
    )

    builder.server_validation().trusted_certs(root).peer_certificate(ee).fails()

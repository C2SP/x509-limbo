"""
Pathological chain-building testcases.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from limbo.assets import EPOCH, ONE_THOUSAND_YEARS_OF_TORMENT, CertificatePair
from limbo.testcases._core import Builder, testcase


@testcase
def intermediate_cycle_distinct_cas(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -/-> (ICA' <-> ICA'') -> EE
    ```

    `ICA'` and `ICA''` are separate logical CAs that sign for each other.
    Neither chains up to the root.
    """

    root = builder.root_ca()

    ica_1_key = ec.generate_private_key(ec.SECP256R1())
    ica_2_key = ec.generate_private_key(ec.SECP256R1())

    # NOTE: Uses CertificateBuilder directly to sidestep the certificate dep cycle.
    ica_1 = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .issuer_name(x509.Name.from_rfc4514_string("CN=intermediate-cycle-distinct-ca2"))
        .subject_name(x509.Name.from_rfc4514_string("CN=intermediate-cycle-distinct-ca1"))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ica_2_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ica_1_key.public_key()), critical=False
        )
        .public_key(ica_1_key.public_key())
    ).sign(ica_2_key, algorithm=hashes.SHA256())
    ica_1_pair = CertificatePair(ica_1, ica_1_key)

    ica_2 = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .issuer_name(x509.Name.from_rfc4514_string("CN=intermediate-cycle-distinct-ca1"))
        .subject_name(x509.Name.from_rfc4514_string("CN=intermediate-cycle-distinct-ca2"))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ica_1_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ica_2_key.public_key()), critical=False
        )
        .public_key(ica_2_key.public_key())
    ).sign(ica_1_key, algorithm=hashes.SHA256())
    ica_2_pair = CertificatePair(ica_2, ica_2_key)

    # Sanity check
    ica_1.verify_directly_issued_by(ica_2)
    ica_2.verify_directly_issued_by(ica_1)

    leaf = builder.leaf_cert(ica_1_pair)
    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica_1_pair, ica_2_pair)
        .peer_certificate(leaf)
        .fails()
    )


@testcase
def intermediate_cycle_same_logical_ca(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -/-> (ICA <-> ICA) -> EE
    ```

    The two ICA certificates are from the same logical CA (same subject),
    but have different keys and sign for each other, forming a cycle.
    Neither chains up to the root.
    """

    root = builder.root_ca()

    ica_1_key = ec.generate_private_key(ec.SECP256R1())
    ica_2_key = ec.generate_private_key(ec.SECP256R1())

    # NOTE: Uses CertificateBuilder directly to sidestep the certificate dep cycle.
    ica_1 = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .issuer_name(x509.Name.from_rfc4514_string("CN=intermediate-cycle-same-logical-ca"))
        .subject_name(x509.Name.from_rfc4514_string("CN=intermediate-cycle-same-logical-ca"))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ica_2_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ica_1_key.public_key()), critical=False
        )
        .public_key(ica_1_key.public_key())
    ).sign(ica_2_key, algorithm=hashes.SHA256())
    ica_1_pair = CertificatePair(ica_1, ica_1_key)

    ica_2 = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .issuer_name(x509.Name.from_rfc4514_string("CN=intermediate-cycle-same-logical-ca"))
        .subject_name(x509.Name.from_rfc4514_string("CN=intermediate-cycle-same-logical-ca"))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ica_1_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ica_2_key.public_key()), critical=False
        )
        .public_key(ica_2_key.public_key())
    ).sign(ica_1_key, algorithm=hashes.SHA256())
    ica_2_pair = CertificatePair(ica_2, ica_2_key)

    # Sanity check
    ica_1.verify_directly_issued_by(ica_2)
    ica_2.verify_directly_issued_by(ica_1)

    leaf = builder.leaf_cert(ica_1_pair)
    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica_1_pair, ica_2_pair)
        .peer_certificate(leaf)
        .fails()
    )

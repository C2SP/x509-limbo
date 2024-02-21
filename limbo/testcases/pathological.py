"""
Pathological chain-building testcases.
"""

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from limbo.assets import EPOCH, ONE_THOUSAND_YEARS_OF_TORMENT, CertificatePair, ext
from limbo.models import Feature, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def multiple_chains_expired_intermediate(builder: Builder) -> None:
    """
    Produces the following chain:

    ```
    root 2 -> intermediate (expired) -> root -> EE
    ```

    Both roots are trusted. A chain should be built successfully, disregarding
    the expired intermediate certificate and the second root. This scenario is
    known as the "chain of pain"; for further reference, see
    <https://www.agwa.name/blog/post/fixing_the_addtrust_root_expiration>.
    """
    root = builder.root_ca()
    root_two = builder.root_ca(issuer=x509.Name.from_rfc4514_string("CN=x509-limbo-root-2"))
    ski = x509.SubjectKeyIdentifier.from_public_key(root.key.public_key())
    expired_intermediate = builder.intermediate_ca(
        root_two,
        pathlen=1,
        subject=root.cert.subject,
        not_after=datetime.fromisoformat("1988-11-25T00:00:00Z"),
        key=root.key,
        ski=ext(ski, critical=False),
    )
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root, root_two).untrusted_intermediates(
        expired_intermediate
    ).peer_certificate(leaf).succeeds()


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

    basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
    key_usage = x509.KeyUsage(
        digital_signature=False,
        key_cert_sign=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

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
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
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
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
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
def intermediate_cycle_distinct_cas_max_depth(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -/-> (ICA' <-> ICA'') -> EE
    ```

    `ICA'` and `ICA''` are separate logical CAs that sign for each other.
    Neither chains up to the root.

    This testcase is identical to `intermediate-cycle-distinct-cas`, except
    that it specifies a large explicit max depth.
    """

    root = builder.root_ca()

    basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
    key_usage = x509.KeyUsage(
        digital_signature=False,
        key_cert_sign=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

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
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
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
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
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
        # NOTE: This chain depth exercises an overflow check in pyca/cryptography.
        .max_chain_depth(255)
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


@testcase
def nc_dos_1(builder: Builder) -> None:
    """
    Produces the following chain:

    ```
    root [many constraints] -> EE [many names]
    ```

    The root CA contains over 1000 permits and excludes name constraints, which
    are checked against the EE's 512 SANs. This is typically rejected by
    implementations due to quadratic blowup.

    This testcase is a reproduction of OpenSSL's `(many-names1.pem, many-constraints.pem)`
    testcase, via <https://github.com/openssl/openssl/pull/4393>.
    """
    # Permit t{0-512}.test, as well as blanket permit all subdomains of .test
    permitteds = [x509.DNSName(f"t{i}.test") for i in range(513)]
    permitteds.append(x509.DNSName(".test"))

    # Forbid x{0-512}.test.
    excludeds = [x509.DNSName(f"x{i}.test") for i in range(513)]

    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(permitted_subtrees=permitteds, excluded_subtrees=excludeds),
            critical=True,
        ),
    )

    leaf = builder.leaf_cert(
        root, subject=x509.Name([]), san=ext(x509.SubjectAlternativeName(permitteds), critical=True)
    )

    builder = (
        builder.server_validation()
        .features([Feature.denial_of_service])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="t0.test"))
        .fails()
    )

"""
Public CVE testcases.
"""


from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from limbo.assets import EPOCH, ONE_THOUSAND_YEARS_OF_TORMENT, CertificatePair, ext
from limbo.models import PeerKind, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def cve_2024_0567(builder: Builder) -> None:
    """
    Tests CVE-2024-0567.

    Produces the following **valid** trust graph:

    ```
    leaf -> A1 -> (A <-> B <-> C) -> Root A
    ```

    In other words: `leaf` is signed by intermediate `A1`, which in turn is signed
    by `A`, which is mutually cross-signed by CAs `B` and `C`. This naively results
    in a cycle, which can be resolved because `A` is also present as a self-signed
    root in the trusted set.

    `B` and `C` also have subordinate CAs (`B1` and `C1`), but these do not factor
    into the constructed chain.

    Affects GnuTLS prior to 3.8.3.

    * Announcement: <https://lists.gnupg.org/pipermail/gnutls-help/2024-January/004841.html>
    * Patch: <https://gitlab.com/gnutls/gnutls/-/commit/9edbdaa84e38b1bfb53a7d72c1de44f8de373405>

    This testcase is an independent recreation of the testcase in the patch, for CABF
    conformance.
    """

    # Self-signed Root A
    root = builder.root_ca(subject=x509.Name.from_rfc4514_string("CN=Root A"))
    key_a = root.key

    # Keys for CAs B and C
    key_b = ec.generate_private_key(ec.SECP256R1())
    key_c = ec.generate_private_key(ec.SECP256R1())

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

    # Intermediate A1, signed by Root A
    key_a1 = ec.generate_private_key(ec.SECP256R1())
    intermediate_a1_by_a = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Intermediate A1"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root A"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_a.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_a1.public_key()), critical=False
        )
        .public_key(key_a1.public_key())
    ).sign(key_a, algorithm=hashes.SHA256())
    intermediate_a1_by_a_pair = CertificatePair(intermediate_a1_by_a, key_a1)

    # Root A, signed by Root B
    root_a_by_b = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Root A"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root B"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_b.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_a.public_key()), critical=False
        )
        .public_key(key_a.public_key())
    ).sign(key_b, algorithm=hashes.SHA256())
    a_by_b_pair = CertificatePair(root_a_by_b, key_a)

    # Root A, signed by Root C
    root_a_by_c = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Root A"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root C"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_c.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_a.public_key()), critical=False
        )
        .public_key(key_a.public_key())
    ).sign(key_c, algorithm=hashes.SHA256())
    a_by_c_pair = CertificatePair(root_a_by_c, key_a)

    # Intermediate B1, signed by Root B
    key_b1 = ec.generate_private_key(ec.SECP256R1())
    intermediate_b1_by_b = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Intermediate B1"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root B"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_b.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_b1.public_key()), critical=False
        )
        .public_key(key_b1.public_key())
    ).sign(key_b, algorithm=hashes.SHA256())
    intermediate_b1_by_b_pair = CertificatePair(intermediate_b1_by_b, key_b1)

    # Root B, signed by Root A
    root_b_by_a = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Root B"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root A"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_a.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_b.public_key()), critical=False
        )
        .public_key(key_b.public_key())
    ).sign(key_a, algorithm=hashes.SHA256())
    b_by_a_pair = CertificatePair(root_b_by_a, key_b)

    # Root B, signed by Root C
    root_b_by_c = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Root B"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root C"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_c.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_b.public_key()), critical=False
        )
        .public_key(key_b.public_key())
    ).sign(key_c, algorithm=hashes.SHA256())
    b_by_c_pair = CertificatePair(root_b_by_c, key_b)

    # Intermediate C1, signed by Root C
    key_c1 = ec.generate_private_key(ec.SECP256R1())
    intermediate_c1_by_c = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Intermediate C1"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root C"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_c.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_c1.public_key()), critical=False
        )
        .public_key(key_c1.public_key())
    ).sign(key_c, algorithm=hashes.SHA256())
    intermediate_c1_by_c_pair = CertificatePair(intermediate_c1_by_c, key_c1)

    # Root C, signed by Root A
    root_c_by_a = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Root C"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root A"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_a.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_c.public_key()), critical=False
        )
        .public_key(key_c.public_key())
    ).sign(key_a, algorithm=hashes.SHA256())
    c_by_a_pair = CertificatePair(root_c_by_a, key_c)

    # Root C, signed by Root B
    root_c_by_b = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(EPOCH)
        .not_valid_after(ONE_THOUSAND_YEARS_OF_TORMENT)
        .subject_name(x509.Name.from_rfc4514_string("CN=Root C"))
        .issuer_name(x509.Name.from_rfc4514_string("CN=Root B"))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key_b.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key_c.public_key()), critical=False
        )
        .public_key(key_c.public_key())
    ).sign(key_b, algorithm=hashes.SHA256())
    c_by_b_pair = CertificatePair(root_c_by_b, key_c)

    intermediates = [
        intermediate_a1_by_a_pair,
        a_by_b_pair,
        a_by_c_pair,
        intermediate_b1_by_b_pair,
        b_by_a_pair,
        b_by_c_pair,
        intermediate_c1_by_c_pair,
        c_by_a_pair,
        c_by_b_pair,
    ]

    # Leaf cve-2024-0567.example.com, signed by Intermediate A1
    leaf = builder.leaf_cert(
        intermediate_a1_by_a_pair,
        subject=None,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("cve-2024-0567.example.com")]), critical=True
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(*intermediates)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind=PeerKind.DNS, value="cve-2024-0567.example.com"))
        .succeeds()
    )

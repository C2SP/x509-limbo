"""
RFC 5280 Subject Alternative Name (SAN) testcases.
"""

from cryptography import x509

from limbo.assets import ext
from limbo.models import PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def malformed(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert has a SubjectAlternativeName with a value in ASCII bytes, rather
    than in the expected DER encoding.
    """
    root = builder.root_ca()
    malformed_san = ext(
        x509.UnrecognizedExtension(x509.OID_SUBJECT_ALTERNATIVE_NAME, b"example.com"),
        critical=False,
    )
    leaf = builder.leaf_cert(root, san=None, extra_extension=malformed_san)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def noncritical_with_empty_subject(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert.

    The EE cert contains a non-critical Subject Alternative Name extension,
    which is disallowed when the cert's Subject is empty under
    RFC 5280:

    > If the subject field contains an empty sequence, then the issuing CA MUST
    > include a subjectAltName extension that is marked as critical.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name([]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def underscore_dns(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert.

    The EE cert contains a Subject Alternative Name extension that
    contains an underscore, which is disallowed under RFC 5280 4.2.1.6:

    > When the subjectAltName extension contains a domain name system
    > label, the domain name MUST be stored in the dNSName (an IA5String).
    > The name MUST be in the "preferred name syntax", as specified by
    > Section 3.5 of RFC 1034 and as modified by Section 2.1 of
    > RFC 1123.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo_bar.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="foo_bar.example.com")
    ).fails()


@testcase
def ip_in_dns(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert.

    The EE certain contains a Subject Alternative Name extension that
    contains an IP address as a DNSName rather than as an IPAddress,
    which is disallowed under RFC 5280 4.2.1.6.

    See: <https://bugzilla.mozilla.org/show_bug.cgi?id=1448986> for a public
    example of this kind of misissuance.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName._init_without_validation("8.8.8.8")]),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="8.8.8.8")
    ).fails()

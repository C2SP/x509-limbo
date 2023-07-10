"""
Web PKI (CA/B Forum) profile tests.
"""

from datetime import datetime
from cryptography import x509

from limbo.assets import Certificate, ee_cert, ext, _ASSETS_PATH
from limbo.models import PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def cryptographydotio_chain(builder: Builder) -> None:
    """
    Verifies against a saved copy of `cryptography.io`'s chain. This should
    trivially succeed.
    """
    chain_path = _ASSETS_PATH / "cryptography.io.cer"
    chain = [Certificate(c) for c in x509.load_pem_x509_certificates(chain_path.read_bytes())]

    leaf, root = chain.pop(0), chain.pop(-1)
    builder = builder.client_validation().validation_time(
        datetime.fromisoformat("2023-07-10T00:00:00Z")
    )
    builder.trusted_certs(root).peer_certificate(leaf).untrusted_intermediates(*chain).succeeds()


@testcase
def exact_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName "example.com".
    This should verify successfully against the domain "example.com", per the
    [RFC 6125 profile].

    [RFC 6125 profile]: https://www.rfc-editor.org/rfc/rfc6125.html#section-6.4.1
    """

    root = builder.root_ca()
    leaf = ee_cert(
        root, ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    )

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
    ).succeeds()


@testcase
def leftmost_wildcard_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName "*.example.com".
    This should verify successfully against the domain "foo.example.com", per the
    [RFC 6125 profile].

    [RFC 6125 profile]: https://www.rfc-editor.org/rfc/rfc6125.html#section-6.4.3
    """

    root = builder.root_ca()
    leaf = ee_cert(
        root, ext(x509.SubjectAlternativeName([x509.DNSName("*.example.com")]), critical=False)
    )

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="foo.example.com"))
    ).succeeds()


@testcase
def wildcard_embedded_leftmost_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName "ba*.example.com".
    This should **fail to verify** against the domain "baz.example.com", per the
    [CA/B BR profile].

    > Wildcard Domain Name: A string starting with “*.” (U+002A ASTERISK, U+002E FULL STOP)
    > immediately followed by a Fully-Qualified Domain Name.

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
    """

    root = builder.root_ca()
    leaf = ee_cert(
        root, ext(x509.SubjectAlternativeName([x509.DNSName("ba*.example.com")]), critical=False)
    )

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="baz.example.com"))
    ).fails()


@testcase
def wildcard_not_in_leftmost_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName "foo.*.example.com".
    This should **fail to verify** against the domain "foo.bar.example.com", per the
    [RFC 6125 profile].

    > The client SHOULD NOT attempt to match a presented identifier in
    > which the wildcard character comprises a label other than the
    > left-most label (e.g., do not match bar.*.example.net).

    [RFC 6125 profile]: https://www.rfc-editor.org/rfc/rfc6125.html#section-6.4.3
    """
    root = builder.root_ca()
    leaf = ee_cert(
        root,
        ext(x509.SubjectAlternativeName([x509.DNSName("foo.*.example.com")]), critical=False),
    )

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="foo.bar.example.com"))
    ).fails()


@testcase
def wildcard_match_across_labels_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName "*.example.com".
    This should **fail to verify** against the domain "foo.bar.example.com", per the
    [RFC 6125 profile].

    > If the wildcard character is the only character of the left-most
    > label in the presented identifier, the client SHOULD NOT compare
    > against anything but the left-most label of the reference
    > identifier (e.g., *.example.com would match foo.example.com but
    > not bar.foo.example.com or example.com).

    [RFC 6125 profile]: https://www.rfc-editor.org/rfc/rfc6125.html#section-6.4.3
    """
    root = builder.root_ca()
    leaf = ee_cert(
        root,
        ext(x509.SubjectAlternativeName([x509.DNSName("*.example.com")]), critical=False),
    )

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="foo.bar.example.com"))
    ).fails()


@testcase
def wildcard_embedded_ulabel_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName
    "xn--*-1b3c148a.example.com". This should **fail to verify** against the domain
    "xn--bliss-1b3c148a.example.com", per the [RFC 6125 profile].

    > ... the client SHOULD NOT attempt to match a presented identifier
    > where the wildcard character is embedded within an A-label or
    > U-label [IDNA-DEFS] of an internationalized domain name [IDNA-PROTO].

    [RFC 6125 profile]: https://www.rfc-editor.org/rfc/rfc6125.html#section-6.4.1
    """
    root = builder.root_ca()
    leaf = ee_cert(
        root,
        ext(
            x509.SubjectAlternativeName([x509.DNSName("xn--*-1b3c148a.example.com")]),
            critical=False,
        ),
    )

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="xn--bliss-1b3c148a.example.com"))
    ).fails()


@testcase
def unicode_emoji_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName "😜.example.com",
    This should **fail to verify** against the domain "xn--628h.example.com", per the
    [RFC 5280 profile].

    > IA5String is limited to the set of ASCII characters.  To accommodate
    > internationalized domain names in the current structure, conforming
    > implementations MUST convert internationalized domain names to the
    > ASCII Compatible Encoding (ACE) format as specified in Section 4 of
    > RFC 3490 before storage in the dNSName field.

    [RFC 5280 profile]: https://www.rfc-editor.org/rfc/rfc5280#section-7.2
    """

    root = builder.root_ca()
    leaf = ee_cert(
        root,
        ext(
            x509.SubjectAlternativeName([x509.DNSName._init_without_validation("😜.example.com")]),
            critical=False,
        ),
    )

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="xn--628h.example.com"))
    ).fails()


@testcase
def malformed_aia(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains an Authority Information Access extension with malformed
    contents. This is **invalid** per the [CA/B BR profile].

    > The AuthorityInfoAccessSyntax MUST contain one or more AccessDescriptions.

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
    """
    root = builder.root_ca()
    leaf = ee_cert(
        root,
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.OID_AUTHORITY_INFORMATION_ACCESS, b"malformed"),
            critical=False,
        ),
    )

    builder = builder.client_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()

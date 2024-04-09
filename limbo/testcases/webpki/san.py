"""
Subject Alternative Name (SAN)-specific Web PKI tests.
"""

import ipaddress

from cryptography import x509

from limbo.assets import ext
from limbo.models import Feature, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def exact_dns_san(builder: Builder) -> None:
    """
    Produces a chain with a valid EE cert for `example.com`.

    This EE cert contains a Subject Alternative Name with the dNSName "example.com".
    This should verify successfully against the domain "example.com", per
    RFC 6125 6.4.1.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root, san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
    ).succeeds()


@testcase
def exact_localhost_ip_san(builder: Builder) -> None:
    """
    Produces a chain with a valid EE cert, for IP 127.0.0.1, i.e. localhost.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="IP", value="127.0.0.1"))
    ).succeeds()


@testcase
def mismatch_domain_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `example.com`.
    This should **fail to verify** against the domain `example2.com`, per RFC 6125 6.4.1.

    > Each label MUST match in order for the names to be considered to match,
    > except as supplemented by the rule about checking of wildcard labels.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example2.com")
    ).fails()


@testcase
def mismatch_subdomain_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `abc.example.com`.
    This should **fail to verify** against the domain `def.example.com`, per RFC 6125 6.4.1.

    > Each label MUST match in order for the names to be considered to match,
    > except as supplemented by the rule about checking of wildcard labels.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("abc.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="def.example.com")
    ).fails()


@testcase
def mismatch_subdomain_apex_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `example.com`.
    This should **fail to verify** against the domain `abc.example.com`, per RFC 6125 6.4.1.

    > Each label MUST match in order for the names to be considered to match,
    > except as supplemented by the rule about checking of wildcard labels.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="abc.example.com")
    ).fails()


@testcase
def mismatch_apex_subdomain_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `abc.example.com`.
    This should **fail to verify** against the domain `example.com`, per RFC 6125 6.4.1.

    > Each label MUST match in order for the names to be considered to match,
    > except as supplemented by the rule about checking of wildcard labels.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("abc.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def public_suffix_wildcard_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative name with the dNSName `*.com`.
    Conformant CAs should not issue such a certificate, according to CABF:

    > If the FQDN portion of any Wildcard Domain Name is “registry‐controlled”
    > or is a “public suffix”, CAs MUST refuse issuance unless the Applicant
    > proves its rightful control of the entire Domain Namespace.

    While the Baseline Requirements do not specify how clients should behave
    when given such a certificate, it is generally safe to assume that wildcard
    certificates spanning a gTLD are malicious, and clients should reject them.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("*.com")]), critical=False),
    )

    builder = builder.server_validation().features([Feature.pedantic_public_suffix_wildcard])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def leftmost_wildcard_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `*.example.com`.
    This should verify successfully against the domain `foo.example.com`, per RFC 6125 6.4.3.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root, san=ext(x509.SubjectAlternativeName([x509.DNSName("*.example.com")]), critical=False)
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="foo.example.com"))
    ).succeeds()


@testcase
def wildcard_embedded_leftmost_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `ba*.example.com`.
    This should **fail to verify** against the domain `baz.example.com`, per CABF.

    > Wildcard Domain Name: A string starting with “*.” (U+002A ASTERISK, U+002E FULL STOP)
    > immediately followed by a Fully-Qualified Domain Name.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("ba*.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="baz.example.com"))
    ).fails()


@testcase
def wildcard_not_in_leftmost_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `foo.*.example.com`.
    This should **fail to verify** against the domain `foo.bar.example.com`, per RFC 6125 6.4.3.

    > The client SHOULD NOT attempt to match a presented identifier in
    > which the wildcard character comprises a label other than the
    > left-most label (e.g., do not match bar.*.example.net).
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo.*.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="foo.bar.example.com"))
    ).fails()


@testcase
def wildcard_match_across_labels_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `*.example.com`.
    This should **fail to verify** against the domain `foo.bar.example.com`, per RFC 6125 6.4.3.

    > If the wildcard character is the only character of the left-most
    > label in the presented identifier, the client SHOULD NOT compare
    > against anything but the left-most label of the reference
    > identifier (e.g., *.example.com would match foo.example.com but
    > not bar.foo.example.com or example.com).
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("*.example.com")]), critical=False),
    )

    builder = builder.server_validation()
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
    `xn--*-1b3c148a.example.com`. This should **fail to verify** against the domain
    `xn--bliss-1b3c148a.example.com`, per RFC 6125 6.4.3:

    > ... the client SHOULD NOT attempt to match a presented identifier
    > where the wildcard character is embedded within an A-label or
    > U-label [IDNA-DEFS] of an internationalized domain name [IDNA-PROTO].
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("xn--*-1b3c148a.example.com")]),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="xn--bliss-1b3c148a.example.com"))
    ).fails()


@testcase
def unicode_emoji_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName `😜.example.com`,
    This should **fail to verify** against the domain `xn--628h.example.com`,
    per RFC 5280 7.2:

    > IA5String is limited to the set of ASCII characters.  To accommodate
    > internationalized domain names in the current structure, conforming
    > implementations MUST convert internationalized domain names to the
    > ASCII Compatible Encoding (ACE) format as specified in Section 4 of
    > RFC 3490 before storage in the dNSName field.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName._init_without_validation("😜.example.com")]),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="xn--628h.example.com"))
    ).fails()


@testcase
def no_san(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The chain is correctly constructed, but the EE cert does not have a
    Subject Alternative Name, which is required. This is invalid even when
    the Subject contains a valid domain name in its Common Name component.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root, subject=x509.Name.from_rfc4514_string("CN=example.com"), san=None
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def san_critical_with_nonempty_subject(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert includes a critical subjectAlternativeName extension, which
    is forbidden under CABF when the subject is non-empty:

    > If the subject field of the certificate is an empty SEQUENCE, this
    > extension MUST be marked critical, as specified in RFC 5280,
    > Section 4.2.1.6. Otherwise, this extension MUST NOT be marked
    > critical.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=something-else"),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=True),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def san_wildcard_only(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert contains a SAN of just `DNS:*`, which should be rejected.

    The reason for this is subtle: CABF 3.2.2.6 notes that certs with
    wildcards on public suffixes should not be issued, and `.` (i.e. the DNS
    root) is effectively a public suffix. This is true even though the DNS
    root is not itself on the PSL.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("*")]),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
    ).fails()


@testcase
def san_wildcard_only_tld(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert contains a SAN of just `DNS:*`, which should be rejected.

    The reason for this is subtle: CABF 3.2.2.6 notes that certs with
    wildcards on public suffixes should not be issued, and `.` (i.e. the DNS
    root) is effectively a public suffix. This is true even though the DNS
    root is not itself on the PSL.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("*")]),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="com"))
    ).fails()

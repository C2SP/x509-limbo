"""
Web PKI (CA/B Forum) profile tests.
"""

from datetime import datetime

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives.asymmetric import dsa, ec

from limbo.assets import _ASSETS_PATH, Certificate, ext
from limbo.models import Feature, KeyUsage, KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def cryptographydotio_chain(builder: Builder) -> None:
    """
    Verifies against a saved copy of `cryptography.io`'s chain. This should
    trivially succeed.
    """
    chain_path = _ASSETS_PATH / "cryptography.io.pem"
    chain = [Certificate(c) for c in x509.load_pem_x509_certificates(chain_path.read_bytes())]

    leaf, root = chain.pop(0), chain.pop(-1)
    builder = builder.server_validation().validation_time(
        datetime.fromisoformat("2023-07-10T00:00:00Z")
    )
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .untrusted_intermediates(*chain)
        .expected_peer_name(PeerName(kind="DNS", value="cryptography.io"))
        .key_usage([KeyUsage.digital_signature])
    ).succeeds()


@testcase
def cryptographydotio_chain_missing_intermediate(builder: Builder) -> None:
    """
    Verifies against a saved copy of `cryptography.io`'s chain, but without its
    intermediates. This should trivially fail.
    """
    chain_path = _ASSETS_PATH / "cryptography.io.pem"
    chain = [Certificate(c) for c in x509.load_pem_x509_certificates(chain_path.read_bytes())]

    leaf, root = chain.pop(0), chain.pop(-1)
    builder = builder.server_validation().validation_time(
        datetime.fromisoformat("2023-07-10T00:00:00Z")
    )
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="cryptography.io"))
        .key_usage([KeyUsage.digital_signature])
    ).fails()


@testcase
def exact_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName "example.com".
    This should verify successfully against the domain "example.com", per the
    [RFC 6125 profile].

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.1
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
def mismatch_domain_san(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains a Subject Alternative Name with the dNSName "example.com".
    This should **fail to verify** against the domain "example2.com", per the
    [RFC 6125 profile].

    > Each label MUST match in order for the names to be considered to match,
    > except as supplemented by the rule about checking of wildcard labels.

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.1
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

    This EE cert contains a Subject Alternative Name with the dNSName "abc.example.com".
    This should **fail to verify** against the domain "def.example.com", per the
    [RFC 6125 profile].

    > Each label MUST match in order for the names to be considered to match,
    > except as supplemented by the rule about checking of wildcard labels.

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.1
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

    This EE cert contains a Subject Alternative Name with the dNSName "example.com".
    This should **fail to verify** against the domain "abc.example.com", per the
    [RFC 6125 profile].

    > Each label MUST match in order for the names to be considered to match,
    > except as supplemented by the rule about checking of wildcard labels.

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.1
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

    This EE cert contains a Subject Alternative Name with the dNSName "abc.example.com".
    This should **fail to verify** against the domain "example.com", per the
    [RFC 6125 profile].

    > Each label MUST match in order for the names to be considered to match,
    > except as supplemented by the rule about checking of wildcard labels.

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.1
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

    This EE cert contains a Subject Alternative name with the dNSName "*.com".
    Conformant CAs should not issue such a certificate, according to the
    [CA/B BR profile]:

    > If the FQDN portion of any Wildcard Domain Name is “registry‐controlled”
    > or is a “public suffix”, CAs MUST refuse issuance unless the Applicant
    > proves its rightful control of the entire Domain Namespace.

    While the Baseline Requirements do not specify how clients should behave
    when given such a certificate, it is generally safe to assume that wildcard
    certificates spanning a gTLD are malicious, and clients should reject them.

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
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

    This EE cert contains a Subject Alternative Name with the dNSName "*.example.com".
    This should verify successfully against the domain "foo.example.com", per the
    [RFC 6125 profile].

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3
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

    This EE cert contains a Subject Alternative Name with the dNSName "ba*.example.com".
    This should **fail to verify** against the domain "baz.example.com", per the
    [CA/B BR profile].

    > Wildcard Domain Name: A string starting with “*.” (U+002A ASTERISK, U+002E FULL STOP)
    > immediately followed by a Fully-Qualified Domain Name.

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
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

    This EE cert contains a Subject Alternative Name with the dNSName "foo.*.example.com".
    This should **fail to verify** against the domain "foo.bar.example.com", per the
    [RFC 6125 profile].

    > The client SHOULD NOT attempt to match a presented identifier in
    > which the wildcard character comprises a label other than the
    > left-most label (e.g., do not match bar.*.example.net).

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3
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

    This EE cert contains a Subject Alternative Name with the dNSName "*.example.com".
    This should **fail to verify** against the domain "foo.bar.example.com", per the
    [RFC 6125 profile].

    > If the wildcard character is the only character of the left-most
    > label in the presented identifier, the client SHOULD NOT compare
    > against anything but the left-most label of the reference
    > identifier (e.g., *.example.com would match foo.example.com but
    > not bar.foo.example.com or example.com).

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3
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
    "xn--*-1b3c148a.example.com". This should **fail to verify** against the domain
    "xn--bliss-1b3c148a.example.com", per the [RFC 6125 profile].

    > ... the client SHOULD NOT attempt to match a presented identifier
    > where the wildcard character is embedded within an A-label or
    > U-label [IDNA-DEFS] of an internationalized domain name [IDNA-PROTO].

    [RFC 6125 profile]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.1
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

    This EE cert contains a Subject Alternative Name with the dNSName "😜.example.com",
    This should **fail to verify** against the domain "xn--628h.example.com", per the
    [RFC 5280 profile].

    > IA5String is limited to the set of ASCII characters.  To accommodate
    > internationalized domain names in the current structure, conforming
    > implementations MUST convert internationalized domain names to the
    > ASCII Compatible Encoding (ACE) format as specified in Section 4 of
    > RFC 3490 before storage in the dNSName field.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-7.2
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
def malformed_aia(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains an Authority Information Access extension with malformed
    contents. This is **invalid** per the [CA/B BR profile].

    > The AuthorityInfoAccessSyntax MUST contain one or more AccessDescriptions.

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        ),
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.OID_AUTHORITY_INFORMATION_ACCESS, b"malformed"),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def root_with_extkeyusage(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert includes the extKeyUsage extension, which is forbidden
    under the [CA/B BR profile]:

    > 7.1.2.1.2 Root CA Extensions
    > Extension     Presence        Critical
    > ...
    > extKeyUsage   MUST NOT        N

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
    """

    root = builder.root_ca(
        extra_extension=ext(x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]), critical=False)
    )
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation().features([Feature.eku])
    builder = (
        builder.trusted_certs(root)
        .extended_key_usage([KnownEKUs.server_auth])
        .peer_certificate(leaf)
        .fails()
    )


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
def san_critical_with_nonempty_subject(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert includes a critical subjectAlternativeName extension, which
    is forbidden under the [CA/B BR profile]:

    > If the subject field of the certificate is an empty SEQUENCE, this
    > extension MUST be marked critical, as specified in RFC 5280,
    > Section 4.2.1.6. Otherwise, this extension MUST NOT be marked
    > critical.

    [CA/B BR profile]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
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
def forbidden_p192_spki_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert is signed with a P-192 key, which is not one of the permitted
    public keys under the CA/B BR profile.
    """

    root = builder.root_ca()

    leaf_key = ec.generate_private_key(ec.SECP192R1())
    leaf = builder.leaf_cert(root, key=leaf_key)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_dsa_spki_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert is signed with a DSA key, which is not one of the permitted
    public keys under the CA/B BR profile.
    """

    root = builder.root_ca()

    leaf_key = dsa.generate_private_key(3072)
    leaf = builder.leaf_cert(root, key=leaf_key)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_signature_algorithm_in_root(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert is signed with a DSA-3072 key, which is not one of the
    permitted signature algorithms under the CA/B BR profile.
    """

    root_key = dsa.generate_private_key(3072)
    root = builder.root_ca(key=root_key)
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_signature_algorithm_in_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert is signed with a DSA-3072 key, which is not one of the
    permitted signature algorithms under the CA/B BR profile.

    This case is distinct from `forbidden_signature_algorithm_in_root`,
    as DSA keys are forbidden in both places but not all implementations
    check both.
    """

    root = builder.root_ca()

    leaf_key = dsa.generate_private_key(3072)
    leaf = builder.leaf_cert(root, key=leaf_key)

    # NOTE: Currently marked as "pedantic" because the correct behavior
    # here for a path validator is unclear: DSA keys are not allowed
    # in any certificates under CABF, but path validation logically
    # does not require checking the EE's key.
    builder = builder.server_validation().features([Feature.pedantic_webpki])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
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
def v1_cert(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert is marked with
    version 2 (ordinal 1) rather than version 3 (ordinal 2). This is invalid,
    per CA/B 7.1.1:

    > Certificates MUST be of type X.509 v3.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(root, unchecked_version=x509.Version.v1, no_extensions=True)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def eku_contains_anyeku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that contains `anyExtendedKeyUsage`,
    which is explicitly forbidden under CA/B 7.1.2.7.10.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()

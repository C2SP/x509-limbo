"""
RFC 5280 Name Constraints (NC) testcases.
"""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from cryptography import x509

from limbo.assets import ext
from limbo.models import Feature, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def permitted_dns_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName
    "example.com", whereas the leaf certificate has a SubjectAlternativeName with a
    dNSName of "not-example.com".
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def excluded_dns_match(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded dNSName of
    "example.com", matching the leaf's SubjectAlternativeName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None, excluded_subtrees=[x509.DNSName("example.com")]
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root, san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def permitted_dns_match(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", matching the leaf's SubjectAlternativeName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root, san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def permitted_dns_match_noncritical(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", matching the leaf's SubjectAlternativeName. However,
    the NameConstraints extension is not marked as critical, which is required by
    the RFC 5280 profile.

    NOTE: This exact chain is valid under the CABF profile.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=False,
        )
    )
    leaf = builder.leaf_cert(
        root, san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    )

    builder = builder.server_validation().features([Feature.rfc5280_incompatible_with_webpki])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def permitted_dns_match_more(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com". The leaf's "foo.bar.example.com" satisfies this constraint
    per the [RFC 5280 profile]:

    > DNS name restrictions are expressed as host.example.com.  Any DNS
    > name that can be constructed by simply adding zero or more labels to
    > the left-hand side of the name satisfies the name constraint.  For
    > example, www.host.example.com would satisfy the constraint but
    > host1.example.com would not.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo.bar.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="foo.bar.example.com")
    ).succeeds()


@testcase
def excluded_dns_match_second(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded dNSName of
    "not-allowed.example.com". This should match the leaf's second
    SubjectAlternativeName entry.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None, excluded_subtrees=[x509.DNSName("not-allowed.example.com")]
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DNSName("example.com"), x509.DNSName("not-allowed.example.com")]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def permitted_ip_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted iPAddress of
    192.0.2.0/24, which does not match the iPAddress in the SubjectAlternativeName
    of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("192.0.3.1"))]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.0.3.1")
    ).fails()


@testcase
def excluded_ipv4_match(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded iPAddress of
    192.0.2.0/24, matching the iPAddress in the SubjectAlternativeName of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("192.0.2.1"))]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.0.2.1")
    ).fails()


@testcase
def excluded_ipv6_match(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded iPAddress of
    ::1/128, matching the iPAddress in the SubjectAlternativeName of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.IPAddress(IPv6Network("::1/128"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.IPAddress(IPv6Address("::1"))]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="::1")
    ).fails()


@testcase
def permitted_ipv4_match(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted iPAddress of
    192.0.2.0/24, which matches the iPAddress in the SubjectAlternativeName
    of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("192.0.2.1"))]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.0.2.1")
    ).succeeds()


@testcase
def permitted_ipv6_match(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted iPAddress of
    ::1/128, which matches the iPAddress in the SubjectAlternativeName
    of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv6Network("::1/128"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.IPAddress(IPv6Address("::1"))]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="::1")
    ).succeeds()


@testcase
def permitted_dn_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted DirectoryName
    of "CN=foo". This should not match the child's DirectoryName of "CN=not-foo".
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=not-foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=not-foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def excluded_dn_match(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded DirectoryName
    of "CN=foo", matching the leaf's SubjectAlternativeName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def permitted_dn_match(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted DirectoryName
    of "CN=foo", matching the leaf's SubjectAlternativeName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).succeeds()


@testcase
def permitted_dn_match_subject_san_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted DirectoryName
    of "CN=foo", matching the leaf's SubjectAlternativeName but not its subject.
    The leaf must be rejected per the [RFC5280 profile] due to this mismatch:

    > Restrictions of the form directoryName MUST be applied to the subject
    > field in the certificate (when the certificate includes a non-empty
    > subject field) and to any names of type directoryName in the
    > subjectAltName extension.

    [RFC5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=not-foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def excluded_dn_match_sub_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded DirectoryName
    of "CN=foo", matching the leaf's subject but not its SubjectAlternativeName.
    The leaf must be rejected per the [RFC5280 profile] due to this match:

    > Restrictions of the form directoryName MUST be applied to the subject
    > field in the certificate (when the certificate includes a non-empty
    > subject field) and to any names of type directoryName in the
    > subjectAltName extension.

    [RFC5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=not-foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).fails()


# NOTE: The following tests aren't specific to any name constraint type.
# We could potentially parametrize this for different constraint types.
@testcase
def permitted_self_issued(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> intermediate -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", whereas the intermediate certificate has a
    SubjectAlternativeName with a dNSName of "not-example.com".

    Normally, this would mean that the chain would be rejected, however the
    intermediate is self-issued so name constraints don't apply to it.

    > Name constraints are not applied to self-issued certificates (unless
    > the certificate is the final certificate in the path).  (This could
    > prevent CAs that use name constraints from employing self-issued
    > certificates to implement key rollover.)
    """
    root = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )
    intermediate = builder.intermediate_ca(
        root,
        issuer=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
    )
    leaf = builder.leaf_cert(intermediate)
    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).succeeds()


@testcase
def excluded_self_issued_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", whereas the leaf certificate has a SubjectAlternativeName
    with a dNSName of "not-example.com".

    In this case, the chain would still be rejected as name constraints do apply
    to self-issued certificates if they are in the leaf position.

    > Name constraints are not applied to self-issued certificates (unless
    > the certificate is the final certificate in the path).  (This could
    > prevent CAs that use name constraints from employing self-issued
    > certificates to implement key rollover.)
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
    )
    leaf = builder.leaf_cert(
        intermediate,
        issuer=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
    )
    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="not-example.com")).fails()


@testcase
def excluded_match_permitted_and_excluded(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted and excluded
    dNSName of "example.com", both of which match the leaf's
    SubjectAlternativeName.

    The excluded constraint takes precedence over the the permitted so this
    chain should be marked as invalid.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=[x509.DNSName("example.com")],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )
    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def permitted_different_constraint_type(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted iPAddress of
    192.0.2.0/24, while the leaf's SubjectAlternativeName is a dNSName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )
    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def excluded_different_constraint_type(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded iPAddress of
    192.0.2.0/24, while the leaf's SubjectAlternativeName is a dNSName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )
    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def invalid_dnsname(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a malformed dNSName
    (uses a wildcard pattern, which is not permitted under RFC 5280).
    """

    # NOTE: Set `_permitted_subtrees` directly to avoid validation.
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("unrelated.cryptography.io")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [x509.DNSName("*.example.com")]

    root = builder.root_ca(name_constraints=ext(name_constraints, critical=True))
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="foo.example.com")
    ).fails()


@testcase
def invalid_ipv4_address(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a malformed IPv4
    iPAddress (not in CIDR form).
    """

    # NOTE: Set `_permitted_subtrees` directly to avoid validation.
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.IPAddress(IPv4Network("0.0.0.0/8"))], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [x509.IPAddress(IPv4Address("127.0.0.1"))]

    root = builder.root_ca(name_constraints=ext(name_constraints, critical=True))
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="127.0.0.1")
    ).fails()


@testcase
def invalid_ipv6_address(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a malformed IPv6
    iPAddress (not in CIDR form).
    """

    # NOTE: Set `_permitted_subtrees` directly to avoid validation.
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.IPAddress(IPv6Network("::1/128"))], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [x509.IPAddress(IPv6Address("::1"))]

    root = builder.root_ca(name_constraints=ext(name_constraints, critical=True))
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.IPAddress(IPv6Address("::1"))]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="::1")
    ).fails()


@testcase
def not_allowed_in_ee_noncritical(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE contains a non-critical NameConstraints extension, which is not
    permitted under the RFC 5280 profile:

    > The name constraints extension, which MUST be used only in a CA certificate
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        extra_extension=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=None,
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def not_allowed_in_ee_critical(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE contains a critical NameConstraints extension, which is not
    permitted under the RFC 5280 profile:

    > The name constraints extension, which MUST be used only in a CA certificate
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        extra_extension=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()

from cryptography import x509

from limbo.assets import ext
from limbo.models import PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def permitted_dns_match_noncritical(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", matching the leaf's SubjectAlternativeName.
    The NameConstraints extension is marked as non-critical, which would
    be a violation of RFC 5280, but CABF explicitly permits this as an
    exception to RFC 5280:

    > As an explicit exception from RFC 5280, this extension SHOULD be marked
    > critical, but MAY be marked non-critical if compatibility with certain
    > legacy applications that do not support Name Constraints is necessary.
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

    builder = (
        builder.server_validation()
        .conflicts_with("rfc5280::nc::permitted-dns-match-noncritical")
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .succeeds()
    )


@testcase
def intermediate_permitted_excluded_subtrees_both_null(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> leaf
    ```

    The intermediate contains a NameConstraints extension with `ASN.1 NULL` for
    both permittedSubtrees and excludedSubtrees, which is forbidden under
    CABF 7.1.2.5.2.
    """

    # NOTE: Set inner attributes directly to bypass validation.
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
    )
    nc._permitted_subtrees = None
    nc._excluded_subtrees = None

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        name_constraints=ext(nc, critical=True),
    )
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).fails()


@testcase
def intermediate_permitted_excluded_subtrees_both_empty_sequences(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> leaf
    ```

    The intermediate contains a NameConstraints extension with empty sequences for
    both permittedSubtrees and excludedSubtrees, which is forbidden under
    CABF 7.1.2.5.2.
    """

    # NOTE: Set inner attributes directly to bypass validation.
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
    )
    nc._permitted_subtrees = []
    nc._excluded_subtrees = []

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        name_constraints=ext(nc, critical=True),
    )
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).fails()

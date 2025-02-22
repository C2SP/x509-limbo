"""
Testcases for path length constraints, as well as chain depth constraints.
"""

from limbo.models import Feature
from limbo.testcases._core import Builder, testcase


@testcase
def ee_with_intermediate_pathlen_0(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> intermediate (pathlen:0) -> EE
    ```

    This is a "trivial" verification: the intermediate has a `pathlen:0`
    constraint, but the leaf is an end entity and is therefore allowed.
    """
    root = builder.root_ca()
    intermediate = builder.intermediate_ca(root, pathlen=0)
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .succeeds()
    )


@testcase
def ee_with_intermediate_pathlen_1(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> intermediate (pathlen:1) -> EE
    ```

    This is a "trivial" verification: the intermediate has a `pathlen:1`
    constraint, but the leaf is an end entity and is therefore allowed.
    """

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(root, pathlen=1)
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .succeeds()
    )


@testcase
def ee_with_intermediate_pathlen_2(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> intermediate (pathlen:2) -> EE
    ```

    This is a "trivial" verification: the intermediate has a `pathlen:2`
    constraint, but the leaf is an end entity and is therefore allowed.
    """

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(root, pathlen=2)
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .succeeds()
    )


@testcase
def validation_ignores_pathlen_in_leaf(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> intermediate (pathlen:0) -> intermediate (pathlen:0)
    ```

    This is, unintuitively, a valid chain construction: RFC 5280 4.2.1.9
    notes that the leaf certificate in a validation path is definitionally
    not an intermediate, meaning that it is not included in the maximum
    number of intermediate certificates that may follow a path length
    constrained CA certificate:

    > Note: The last certificate in the certification path is not an intermediate
    > certificate, and is not included in this limit.  Usually, the last certificate
    > is an end entity certificate, but it can be a CA certificate.
    """

    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root, pathlen=0)
    second_intermediate = builder.intermediate_ca(first_intermediate, pathlen=0)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate)
        .peer_certificate(second_intermediate)
        .succeeds()
    )


@testcase
def intermediate_violates_pathlen_0(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate (pathlen:0) -> intermediate (pathlen:0) -> EE
    ```

    This violates the first intermediate's `pathlen:0` constraint,
    which requires that any subsequent certificate be an end-entity and not
    a CA itself.
    """

    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root, pathlen=0)
    second_intermediate = builder.intermediate_ca(first_intermediate, pathlen=0)
    leaf = builder.leaf_cert(second_intermediate)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate)
        .peer_certificate(leaf)
        .fails()
    )


@testcase
def intermediate_pathlen_may_increase(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> intermediate (pathlen:1) -> intermediate (pathlen:2) -> EE
    ```

    This is a less straightforward case as the second intermediate's `pathlen:2`
    constraint seems to contradict the first intermediate's `pathlen:1`
    constraint.

    RFC 5280 permits this as part of supporting multiple validation paths.
    """

    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root, pathlen=1)
    second_intermediate = builder.intermediate_ca(first_intermediate, pathlen=2)
    leaf = builder.leaf_cert(second_intermediate)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate)
        .peer_certificate(leaf)
        .succeeds()
    )


@testcase
def intermediate_pathlen_too_long(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate (pathlen:1) -> intermediate (pathlen:0) -> intermediate (pathlen:0) -> EE
    ```

    This violates the second intermediate's `pathlen:0` constraint, which
    forbids any subsequent issuing certificates (which the third intermediate
    is).
    """

    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root, pathlen=1)
    second_intermediate = builder.intermediate_ca(first_intermediate, pathlen=0)
    third_intermediate = builder.intermediate_ca(second_intermediate, pathlen=0)
    leaf = builder.leaf_cert(third_intermediate)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate, third_intermediate)
        .peer_certificate(leaf)
        .fails()
    )


@testcase
def self_issued_certs_pathlen(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> ICA' (pathlen:1) -> ICA' (pathlen:1) -> ICA'' (pathlen:0) -> EE
    ```

    The second ICA' intermediate is a self-issued certificate. Self-issued certificates
    are certificates with identical issuers and subjects. While this chain trivially
    seems to violate the assigned path length constraints, the RFC 5280 4.2.1.9
    states that self issued certificates should not be counted.
    """

    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root, pathlen=1)
    second_intermediate = builder.intermediate_ca(
        first_intermediate, pathlen=1, subject=first_intermediate.cert.subject
    )
    third_intermediate = builder.intermediate_ca(second_intermediate, pathlen=0)
    leaf = builder.leaf_cert(third_intermediate)

    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(
        first_intermediate, second_intermediate, third_intermediate
    ).peer_certificate(leaf).succeeds()


@testcase
def max_chain_depth_0(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    When validating with a maximum chain depth of 0, there may not be any
    intermediates.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation().features([Feature.max_chain_depth])
    builder = builder.trusted_certs(root).peer_certificate(leaf).max_chain_depth(0).succeeds()


@testcase
def max_chain_depth_0_exhausted(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA' -> leaf
    ```

    When validating with a maximum chain depth of 0, there may not be any
    intermediates.
    """
    root = builder.root_ca()
    intermediate = builder.intermediate_ca(root)
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation().features([Feature.max_chain_depth])
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .max_chain_depth(0)
        .fails()
    )


@testcase
def max_chain_depth_1(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> ICA' -> leaf
    ```

    When validating with a maximum chain depth of 1, there may only be one
    logical intermediate.
    """
    root = builder.root_ca()
    intermediate = builder.intermediate_ca(root)
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation().features([Feature.max_chain_depth])
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .max_chain_depth(1)
        .succeeds()
    )


@testcase
def max_chain_depth_1_exhausted(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA' -> ICA'' -> leaf
    ```

    When validating with a maximum chain depth of 1, there may only be one
    logical intermediate.
    """
    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root)
    second_intermediate = builder.intermediate_ca(first_intermediate)
    leaf = builder.leaf_cert(second_intermediate)

    builder = builder.server_validation().features([Feature.max_chain_depth])
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate)
        .peer_certificate(leaf)
        .max_chain_depth(1)
        .fails()
    )


@testcase
def max_chain_depth_1_self_issued(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> ICA' -> ICA' -> leaf
    ```

    When validating with a maximum chain depth of 1, there may only be one
    logical intermediate.
    """
    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root)
    second_intermediate = builder.intermediate_ca(
        first_intermediate, subject=first_intermediate.cert.subject
    )
    leaf = builder.leaf_cert(second_intermediate)

    builder = builder.server_validation().features([Feature.max_chain_depth])
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate)
        .peer_certificate(leaf)
        .max_chain_depth(1)
        .succeeds()
    )

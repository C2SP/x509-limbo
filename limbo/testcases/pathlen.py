from limbo.assets import ee_cert
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
    leaf = ee_cert(intermediate)

    builder = builder.client_validation()
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
    leaf = ee_cert(intermediate)

    builder = builder.client_validation()
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
    leaf = ee_cert(intermediate)

    builder = builder.client_validation()
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

    This is, unintuitively, a valid chain construction: [RFC 5280 4.2.1.9]
    notes that the leaf certificate in a validation path is definitionally
    not an intermediate, meaning that it is not included in the maximum
    number of intermediate certificates that may follow a path length
    constrained CA certificate:

    > Note: The last certificate in the certification path is not an intermediate
    > certificate, and is not included in this limit.  Usually, the last certificate
    > is an end entity certificate, but it can be a CA certificate.

    [RFC 5280 4.2.1.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    """

    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root, pathlen=0)
    second_intermediate = builder.intermediate_ca(first_intermediate, pathlen=0)

    builder = builder.client_validation()
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
    leaf = ee_cert(second_intermediate)

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate)
        .peer_certificate(leaf)
        .fails()
    )


@testcase
def intermediate_pathlen_must_not_increase(builder: Builder) -> None:
    """
    Produces the following **ambiguous** chain:

    ```
    root -> intermediate (pathlen:1) -> intermediate (pathlen:2) -> EE
    ```

    This violates the first intermediate's `pathlen:1` constraint,
    which allows a subsequent intermediate but not one that widens
    the `pathlen` (as `pathlen:2` does).

    RFC 5280 doesn't specify what clients should do about widened path
    length constraints, which is why this testcase is marked as "pedantic."
    """

    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root, pathlen=1)
    second_intermediate = builder.intermediate_ca(first_intermediate, pathlen=2)
    leaf = ee_cert(second_intermediate)

    builder = builder.client_validation().features([Feature.pedantic_pathlen])
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate)
        .peer_certificate(leaf)
        .fails()
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
    leaf = ee_cert(third_intermediate)

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate, third_intermediate)
        .peer_certificate(leaf)
        .fails()
    )

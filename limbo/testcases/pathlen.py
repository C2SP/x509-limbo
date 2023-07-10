from limbo.assets import ee_cert
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
    intermediate = builder.intermediate_ca(root, 0)
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
    intermediate = builder.intermediate_ca(root, 1)
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
    intermediate = builder.intermediate_ca(root, 2)
    leaf = ee_cert(intermediate)

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .succeeds()
    )


# TODO: Distinct success testcase for `root -> inter (path:0) -> inter (path:0)`
# See the note in RFC 5280 4.2.1.9; when an intermediate is in the leaf
# position, it is not treated as an intermediate and its pathlen constraint
# has no effect.


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
    first_intermediate = builder.intermediate_ca(root, 0)
    second_intermediate = builder.intermediate_ca(root, 0)
    leaf = ee_cert(second_intermediate)

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate)
        .peer_certificate(leaf)
        .fails()
    )


# TODO: Evaluate the correctness of this testcase: RFC 5280 doesn't technically
# forbid broadening pathlen constraints; they're just nonsense.
@testcase
def intermediate_pathlen_must_not_increase(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate (pathlen:1) -> intermediate (pathlen:2) -> EE
    ```

    This violates the first intermediate's `pathlen:1` constraint,
    which allows a subsequent intermediate but not one that widens
    the `pathlen` (as `pathlen:2` does).
    """

    root = builder.root_ca()
    first_intermediate = builder.intermediate_ca(root, 1)
    second_intermediate = builder.intermediate_ca(first_intermediate, 2)
    leaf = ee_cert(second_intermediate)

    builder = builder.client_validation()
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
    first_intermediate = builder.intermediate_ca(root, 1)
    second_intermediate = builder.intermediate_ca(first_intermediate, 0)
    third_intermediate = builder.intermediate_ca(second_intermediate, 0)
    leaf = ee_cert(third_intermediate)

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate, second_intermediate, third_intermediate)
        .peer_certificate(leaf)
        .fails()
    )

from limbo.assets import ee_cert, intermediate_ca_pathlen_n, v3_root_ca
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
    root = v3_root_ca()
    intermediate = intermediate_ca_pathlen_n(root, 0)
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

    root = v3_root_ca()
    intermediate = intermediate_ca_pathlen_n(root, 1)
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

    root = v3_root_ca()
    intermediate = intermediate_ca_pathlen_n(root, 2)
    leaf = ee_cert(intermediate)

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .succeeds()
    )


@testcase
def intermediate_violates_pathlen_0(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate (pathlen:0) -> intermediate (pathlen:0)
    ```

    This violates the first intermediate's `pathlen:0` constraint,
    which requires that any subsequent certificate be an end-entity and not
    a CA itself.
    """

    root = v3_root_ca()
    first_intermediate = intermediate_ca_pathlen_n(root, 0)
    second_intermediate = intermediate_ca_pathlen_n(first_intermediate, 0)

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate)
        .peer_certificate(second_intermediate)
        .fails()
    )


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

    root = v3_root_ca()
    first_intermediate = intermediate_ca_pathlen_n(root, 1)
    second_intermediate = intermediate_ca_pathlen_n(first_intermediate, 2)

    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(first_intermediate)
        .peer_certificate(second_intermediate)
        .fails()
    )

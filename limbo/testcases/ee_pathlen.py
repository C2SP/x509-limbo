from limbo.assets import ee_cert, intermediate_ca_pathlen_n, v3_root_ca
from limbo.testcases._core import Builder, testcase


@testcase
def ee_with_intermediate_pathlen_0(builder: Builder) -> None:
    """
    Verifies an EE certificate with the following chains:

    ```
    EE -> intermediate (pathlen:0) -> root
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

    builder.succeeds()


@testcase
def ee_with_intermediate_pathlen_1(builder: Builder) -> None:
    """
    Verifies an EE certificate with the following chains:

    ```
    EE -> intermediate (pathlen:1) -> root
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

    builder.succeeds()


@testcase
def ee_with_intermediate_pathlen_2(builder: Builder) -> None:
    """
    Verifies an EE certificate with the following chains:

    ```
    EE -> intermediate (pathlen:2) -> root
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

    builder.succeeds()

from limbo.assets import ee_cert_from_intermediate_pathlen_n, intermediate_ca_pathlen_n, v3_root_ca
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
    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(v3_root_ca())
        .untrusted_intermediates(intermediate_ca_pathlen_n(0))
        .peer_certificate(ee_cert_from_intermediate_pathlen_n(0))
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
    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(v3_root_ca())
        .untrusted_intermediates(intermediate_ca_pathlen_n(1))
        .peer_certificate(ee_cert_from_intermediate_pathlen_n(1))
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
    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(v3_root_ca())
        .untrusted_intermediates(intermediate_ca_pathlen_n(2))
        .peer_certificate(ee_cert_from_intermediate_pathlen_n(2))
        .succeeds()
    )

    builder.succeeds()

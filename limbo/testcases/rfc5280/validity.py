"""
RFC 5280 validity testcases.
"""


from datetime import datetime

from limbo.testcases._core import Builder, testcase


@testcase
def expired_root(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> EE
    ```

    All three certificates are well-formed, but the root
    (and only the root) is expired at the validation time.
    """

    # Root is valid from 2016 to 2020.
    root = builder.root_ca(
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2020-01-01T00:00:00Z"),
    )

    # Intermediate is valid from 2016 to 2026.
    intermediate = builder.intermediate_ca(
        root,
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )

    # Leaf is valid from 2018 to 2023.
    leaf = builder.leaf_cert(
        intermediate,
        not_before=datetime.fromisoformat("2018-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2023-01-01T00:00:00Z"),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        # We validate in 2022, which is valid for the intermediate and leaf
        # but not the root.
        .validation_time(datetime.fromisoformat("2022-01-01T00:00:00Z"))
        .fails()
    )


@testcase
def expired_intermediate(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> EE
    ```

    All three certificates are well-formed, but the intermediate
    (and only the intermediate) is expired at the validation time.
    """

    # Root is valid from 2016 to 2026.
    root = builder.root_ca(
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )

    # Intermediate is valid from 2016 to 2020.
    intermediate = builder.intermediate_ca(
        root,
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2020-01-01T00:00:00Z"),
    )

    # Leaf is valid from 2018 to 2023.
    leaf = builder.leaf_cert(
        intermediate,
        not_before=datetime.fromisoformat("2018-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2023-01-01T00:00:00Z"),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        # We validate in 2022, which is valid for the root and leaf
        # but not the intermediate.
        .validation_time(datetime.fromisoformat("2022-01-01T00:00:00Z"))
        .fails()
    )


@testcase
def expired_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> EE
    ```

    All three certificates are well-formed, but the leaf
    (and only the leaf) is expired at the validation time.
    """

    # Root is valid from 2016 to 2026.
    root = builder.root_ca(
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )

    # Intermediate is valid from 2016 to 2026.
    intermediate = builder.intermediate_ca(
        root,
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )

    # Leaf is valid from 2018 to 2021.
    leaf = builder.leaf_cert(
        intermediate,
        not_before=datetime.fromisoformat("2018-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2021-01-01T00:00:00Z"),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        # We validate in 2022, which is valid for the root and intermediate
        # but not the leaf.
        .validation_time(datetime.fromisoformat("2022-01-01T00:00:00Z"))
        .fails()
    )

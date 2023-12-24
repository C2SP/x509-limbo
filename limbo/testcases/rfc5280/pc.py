"""
RFC 5280 Policy Constraints (PC) testcases.
"""

from cryptography import x509

from limbo.models import Feature
from limbo.testcases._core import Builder, ext, testcase


@testcase
def ica_noncritical_pc(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The ICA has a `PolicyConstraints` extension marked as non-critical,
    which is disallowed under RFC 5280 4.2.1.11:

    > Conforming CAs MUST mark this extension as critical.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        extra_extension=ext(
            x509.PolicyConstraints(require_explicit_policy=3, inhibit_policy_mapping=None),
            critical=False,
        ),
    )
    leaf = builder.leaf_cert(ica)

    builder = (
        builder.server_validation()
        .features([Feature.has_policy_constraints])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .fails()
    )

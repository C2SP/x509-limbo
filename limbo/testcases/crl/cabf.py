"""
CABF Baseline Requirements CRL tests.
"""

from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID

from limbo.models import Feature
from limbo.testcases._core import Builder, ext, testcase

from .idp import _cdp_names


def _idp(
    *,
    full_name: list[x509.GeneralName] | None = None,
    relative_name: x509.RelativeDistinguishedName | None = None,
    only_some_reasons: frozenset[x509.ReasonFlags] | None = None,
    indirect_crl: bool = False,
) -> x509.IssuingDistributionPoint:
    return x509.IssuingDistributionPoint(
        full_name=full_name,
        relative_name=relative_name,
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        only_some_reasons=only_some_reasons,
        indirect_crl=indirect_crl,
        only_contains_attribute_certs=False,
    )


@testcase
def idp_name_relative_to_crl_issuer(builder: Builder) -> None:
    """
    Tests a partitioned CRL whose IDP uses nameRelativeToCRLIssuer.

    Per CABF 7.2.2.1, partitioned CRL issuing distribution points must use
    distributionPoint.fullName.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(
                relative_name=x509.RelativeDistinguishedName(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "partition")]
                )
            ),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_fullname_non_uri_generalname(builder: Builder) -> None:
    """
    Tests a partitioned CRL whose IDP fullName includes a non-URI GeneralName.

    Per CABF 7.2.2.1, partitioned CRL issuing distribution points must not
    contain non-URI GeneralNames.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    uri = "http://example.com/partition.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(_cdp_names([x509.UniformResourceIdentifier(uri)]), critical=False),
    )
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(uri), x509.DNSName("example.com")]),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_indirect_crl(builder: Builder) -> None:
    """
    Tests a partitioned CRL whose IDP asserts indirectCRL.

    Per CABF 7.2.2.1, partitioned CRLs must not assert indirectCRL.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    uri = "http://example.com/partition.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(_cdp_names([x509.UniformResourceIdentifier(uri)]), critical=False),
    )
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(uri)], indirect_crl=True),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_only_some_reasons_no_complete_crl(builder: Builder) -> None:
    """
    Tests a partitioned CRL whose IDP includes onlySomeReasons without a complete CRL.

    Per CABF 7.2.2.1, onlySomeReasons should not be included; if included,
    the CA must provide another CRL covering all revocation reasons.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    uri = "http://example.com/partition.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(_cdp_names([x509.UniformResourceIdentifier(uri)]), critical=False),
    )
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(
                full_name=[x509.UniformResourceIdentifier(uri)],
                only_some_reasons=frozenset([x509.ReasonFlags.key_compromise]),
            ),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_uri_not_byte_identical(builder: Builder) -> None:
    """
    Tests a partitioned CRL whose IDP URI is semantically but not byte-identical to CDP.

    Per CABF 7.2.2.1, the IDP uniformResourceIdentifier encoding must be
    byte-for-byte identical to the certificate CDP URI encoding.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    cdp_uri = "http://example.com/crls/%73hard.crl"
    idp_uri = "http://example.com/crls/shard.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(_cdp_names([x509.UniformResourceIdentifier(cdp_uri)]), critical=False),
    )
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(idp_uri)]),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()

"""
CRL Issuing Distribution Point tests.
"""

from datetime import datetime, timedelta

from cryptography import x509

from limbo.models import Feature
from limbo.testcases._core import Builder, ext, testcase


def _cdp_names(names: list[x509.GeneralName]) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=names,
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )


def _idp(
    *,
    full_name: list[x509.GeneralName] | None = None,
    only_contains_user_certs: bool = False,
    only_contains_ca_certs: bool = False,
    only_contains_attribute_certs: bool = False,
) -> x509.IssuingDistributionPoint:
    return x509.IssuingDistributionPoint(
        full_name=full_name,
        relative_name=None,
        only_contains_user_certs=only_contains_user_certs,
        only_contains_ca_certs=only_contains_ca_certs,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=only_contains_attribute_certs,
    )


@testcase
def idp_cdp_scope_mismatch(builder: Builder) -> None:
    """
    Tests a CRL whose issuing distribution point does not match the certificate CDP.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, the certificate distribution
    point name must match the CRL issuing distribution point name when both are
    present.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    cdp_uri = "http://example.com/cdp.crl"
    idp_uri = "http://example.com/other.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(
            _cdp_names([x509.UniformResourceIdentifier(cdp_uri)]),
            critical=False,
        ),
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


@testcase
def idp_cdp_scope_match(builder: Builder) -> None:
    """
    Tests a CRL whose issuing distribution point matches the certificate CDP.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, a CRL whose issuing distribution
    point name matches the certificate distribution point name is applicable.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    uri = "http://example.com/partition.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(
            _cdp_names([x509.UniformResourceIdentifier(uri)]),
            critical=False,
        ),
    )
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(uri)]),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def idp_only_contains_user_certs_ca_target(builder: Builder) -> None:
    """
    Tests an IDP scoped to user certificates against a CA certificate target.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, CRLs whose IDP scope excludes
    the target certificate must be rejected.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )
    leaf = builder.leaf_cert(intermediate)
    root_crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(_idp(only_contains_user_certs=True), critical=True),
    )
    # Also generate a CRL authoritative for our leaf to satisfy path builders that require CRLs
    # for all candidate certificates.
    intermediate_crl = builder.crl(signer=intermediate, revoked=[])

    builder.features([Feature.has_crl]).server_validation().trusted_certs(
        root
    ).untrusted_intermediates(intermediate).peer_certificate(leaf).crls(
        root_crl, intermediate_crl
    ).validation_time(validation_time).fails()


@testcase
def idp_only_contains_ca_certs_ee_target(builder: Builder) -> None:
    """
    Tests an IDP scoped to CA certificates against an EE certificate target.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, CRLs whose IDP scope excludes
    the target certificate must be rejected.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(_idp(only_contains_ca_certs=True), critical=True),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_present_certificate_missing_cdp(builder: Builder) -> None:
    """
    Tests a CRL whose issuing distribution point cannot match because the
    certificate has no CRL distribution points extension.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, an iDP-scoped CRL must match the
    certificate distribution point.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    uri = "http://example.com/partition.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(uri)]),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_present_certificate_cdp_non_uri_generalname(builder: Builder) -> None:
    """
    Tests a CRL whose issuing distribution point cannot match because the
    certificate CDP includes a non-URI GeneralName.

    CABF 7.1.2.11.2 requires distributionPoint.fullName to contain only uniformResourceIdentifier
    names.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")
    uri = "http://example.com/partition.crl"

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        extra_extension=ext(
            _cdp_names([x509.UniformResourceIdentifier(uri), x509.DNSName("example.com")]),
            critical=False,
        ),
    )
    crl = builder.crl(
        signer=root,
        revoked=[],
        extra_extension=ext(
            _idp(full_name=[x509.UniformResourceIdentifier(uri)]),
            critical=True,
        ),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def idp_only_contains_attribute_certs(builder: Builder) -> None:
    """
    Tests an IDP scoped to attribute certificates against a public-key certificate.

    Per RFC 5280 5.2.5 and RFC 5280 6.3.3, CRLs whose IDP scope excludes
    the target certificate must be rejected.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()
    leaf = builder.leaf_cert(parent=root)
    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
        extra_extension=ext(_idp(only_contains_attribute_certs=True), critical=True),
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).crls(crl).validation_time(validation_time).fails()

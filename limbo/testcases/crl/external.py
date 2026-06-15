from datetime import datetime

from cryptography import x509

from limbo.assets import ASSETS_PATH, Certificate
from limbo.models import Feature, Importance, PeerKind, PeerName
from limbo.testcases._core import Builder, testcase


def _external_crl_testcase(builder: Builder, name: str) -> Builder:
    validation_time = datetime.fromisoformat("2025-01-15T00:00:00Z")
    root = ASSETS_PATH / "crl" / "crl_cases_ca.pem"
    leaf = ASSETS_PATH / "crl" / "crl_cases_leaf.pem"
    crl = ASSETS_PATH / "crl" / f"{name}.crl"

    return (
        builder.features([Feature.has_crl])
        .importance(Importance.HIGH)
        .server_validation()
        .trusted_certs(Certificate(x509.load_pem_x509_certificate(root.read_bytes())))
        .peer_certificate(Certificate(x509.load_pem_x509_certificate(leaf.read_bytes())))
        .expected_peer_name(PeerName(kind=PeerKind.DNS, value="revoked.example.com"))
        .crls(crl.read_bytes())
        .validation_time(validation_time)
    )


@testcase
def crl_invalid_version(builder: Builder) -> None:
    """
    Tests a Certificate Revocation List (CRL) with an invalid version.

    Encapsulates a simple test case where a certificate has been revoked by the CA
    through a malformed CRL with an invalid `version` field. The CA certificate
    and CRL are provided, and the leaf certificate is expected to be accepted as
    the CRL is invalid.
    """

    _external_crl_testcase(builder, "bad_version").succeeds()


@testcase
def crl_update_generalizedtime_2025(builder: Builder) -> None:
    """
    Tests a Certificate Revocation List (CRL) with invalid (re)issue date encodings.

    The CRL includes `This Update` and `Next Update` fields encoding dates in the year
    2025 as `GeneralizedTime`. This is forbidden per RFC 5280 5.2.1.4 and 5.2.1.5, thus
    the leaf certificate that the CRL revokes should be accepted.
    """

    _external_crl_testcase(builder, "generalized_time_2025").succeeds()


@testcase
def crl_missing_next_update(builder: Builder) -> None:
    """
    Tests a Certificate Revocation List (CRL) missing the nextUpdate field.

    The CRL revokes the leaf certificate but omits `nextUpdate`. This is forbidden
    per RFC 5280 5.1.2.5, thus the leaf certificate should be accepted as the CRL
    is invalid.
    """

    _external_crl_testcase(builder, "missing_next_update").succeeds()

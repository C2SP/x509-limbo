"""
RFC5280 profile serial number tests.
"""

import random
from datetime import datetime

from cryptography import x509

from limbo.assets import ASSETS_PATH, Certificate
from limbo.models import Feature, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def serial_number_too_long(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert.

    The EE cert contains a serial number longer than 20 octets, which is
    disallowed under RFC 5280.
    """

    root = builder.root_ca()
    # NOTE: Intentionally generate 22 octets, since many implementations are
    # permissive of 21-octet encodings due to signedness errors.
    leaf = builder.leaf_cert(root, serial=int.from_bytes(random.randbytes(22), signed=False))

    builder = builder.server_validation().features([Feature.pedantic_serial_number])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def serial_number_zero(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert.

    The EE cert contains a serial number of zero, which is disallowed
    under RFC 5280.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(root, serial=0)

    builder = builder.server_validation().features([Feature.pedantic_serial_number])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def serial_number_negative(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert. Verifies against a
    saved copy of a certificate with a negative serial number from the
    `cryptography.io` test suite since the API won't allow us to create
    certificates with negative serial numbers.

    The EE cert contains a negative serial number, which is disallowed
    under RFC 5280.
    """

    # TODO(ww): Make this a "bare" testcase, to avoid round-tripping
    # through `load_pem_x509_certificate` (which will soon begin rejecting
    # negative serials).

    cert_path = ASSETS_PATH / "negative_serial.pem"
    cert = Certificate(x509.load_pem_x509_certificate(cert_path.read_bytes()))

    builder = builder.server_validation().features([Feature.pedantic_serial_number])
    builder.trusted_certs(cert).peer_certificate(cert).expected_peer_name(
        PeerName(kind="DNS", value="gov.us")
    ).validation_time(datetime.fromisoformat("2016-09-01T00:00:00Z")).fails()

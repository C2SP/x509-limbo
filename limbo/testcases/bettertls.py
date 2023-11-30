"""
BetterTLS testcases.

These are derived from Netflix's BetterTLS testsuite:
<https://github.com/Netflix/bettertls>, which is licensed under the
terms of the Apache 2 License.
"""

import base64
import functools
import ipaddress
import json
import logging
from datetime import timedelta, timezone

from cryptography import x509

from limbo.assets import ASSETS_PATH, Certificate
from limbo.models import PeerKind, PeerName, Testcase
from limbo.testcases import registry
from limbo.testcases._core import Builder

BETTERTLS_JSON = ASSETS_PATH / "bettertls.json"

logger = logging.getLogger(__name__)


def _bettertls_testcase(id_: str, testcase: dict) -> Testcase:
    logger.info(f"generating {id_}")
    builder = Builder(
        id=id_,
        description=f"Testcase `{testcase['id']}` from the BetterTLS `{testcase['suite']}` suite.",
    )

    certs = [
        Certificate(x509.load_der_x509_certificate(base64.b64decode(cert)))
        for cert in testcase["certificates"]
    ]
    leaf, *intermediates, root = certs

    try:
        addr = ipaddress.ip_address(testcase["hostname"])
        peer = PeerName(kind=PeerKind.DNS, value=str(addr))
    except ValueError:
        peer = PeerName(kind=PeerKind.DNS, value=testcase["hostname"])

    validation_time = leaf.cert.not_valid_before.replace(tzinfo=timezone.utc) + timedelta(seconds=1)

    builder = (
        builder.server_validation()
        .peer_certificate(leaf)
        .untrusted_intermediates(*intermediates)
        .trusted_certs(root)
        .expected_peer_name(peer)
        .validation_time(validation_time)
    )

    if testcase["expected"] == "ACCEPT":
        builder = builder.succeeds()
    else:
        assert testcase["expected"] == "REJECT"
        builder = builder.fails()

    return builder.build()


def register_testcases() -> None:
    bettertls: dict = json.loads(BETTERTLS_JSON.read_text())
    for suite_name, suite in bettertls["suites"].items():
        for testcase in suite["testCases"]:
            id_ = f"bettertls::{suite_name}::tc{testcase['id']}"
            registry[id_] = functools.partial(_bettertls_testcase, id_, testcase)

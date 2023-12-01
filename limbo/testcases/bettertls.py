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


def _bettertls_testcase(id_: str, root: Certificate, testcase: dict) -> Testcase:
    logger.info(f"generating {id_}")
    builder = Builder(
        id=id_,
        description=f"Testcase `{testcase['id']}` from the BetterTLS `{testcase['suite']}` suite.",
    )

    certs = [
        Certificate(x509.load_der_x509_certificate(base64.b64decode(cert)))
        for cert in testcase["certificates"]
    ]
    leaf, *intermediates = certs

    # NOTE(ww): The nameconstraints suite appears to list the root in the intermediate set,
    # while the pathbuilding suite doesn't. This has no practical effect, so we remove it.
    if root in intermediates:
        intermediates.remove(root)

    try:
        addr = ipaddress.ip_address(testcase["hostname"])
        peer = PeerName(kind=PeerKind.IP, value=str(addr))
    except ValueError:
        peer = PeerName(kind=PeerKind.DNS, value=testcase["hostname"])

    expected = testcase["expected"]
    # TODO: Handle failureIsWarning.
    if expected == "ACCEPT":
        builder = builder.succeeds()
    else:
        assert expected == "REJECT"
        builder = builder.fails()

    if "INVALID_REASON_EXPIRED" in testcase["requiredFeatures"] and expected == "REJECT":
        # If the testcase is explicitly exercising expiry logic, set our
        # validation time to something that must fail.
        validation_time = leaf.cert.not_valid_after.replace(tzinfo=timezone.utc) + timedelta(
            seconds=1
        )
    else:
        # Otherwise, pick a validation time that should be valid for the whole chain.
        validation_time = leaf.cert.not_valid_before.replace(tzinfo=timezone.utc) + timedelta(
            seconds=1
        )

    builder = (
        builder.server_validation()
        .peer_certificate(leaf)
        .untrusted_intermediates(*intermediates)
        .trusted_certs(root)
        .expected_peer_name(peer)
        .validation_time(validation_time)
    )

    return builder.build()


def register_testcases() -> None:
    bettertls: dict = json.loads(BETTERTLS_JSON.read_text())
    root = Certificate(x509.load_der_x509_certificate(base64.b64decode(bettertls["trustRoot"])))
    for suite_name, suite in bettertls["suites"].items():
        for testcase in suite["testCases"]:
            id_ = f"bettertls::{suite_name}::tc{testcase['id']}"
            registry[id_] = functools.partial(_bettertls_testcase, id_, root, testcase)

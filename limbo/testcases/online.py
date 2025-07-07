import logging
import socket
from datetime import UTC, timedelta

import certifi
from OpenSSL import SSL

from limbo._assets import ASSETS_DIR_RW
from limbo.assets import ASSETS_PATH, Certificate
from limbo.models import PeerName, Testcase
from limbo.testcases import registry
from limbo.testcases._core import Builder

logger = logging.getLogger(__name__)

# Top websites, chosen semi-arbitrarily.
_TOPSITES = [
    "google.com",
    "stackoverflow.com",
    "facebook.com",
    "docs.python.org",
    "cloudflare.com",
    "fastly.com",
    "akamai.com",
    "storage.googleapis.com",
    "amazon.com",
    "aws.amazon.com",
    "s3.amazonaws.com",
    "apple.com",
    "microsoft.com",
    "bing.com",
]


def _peer_chain(*, host: str, port: int = 443, cafile: str = certifi.where()) -> list[Certificate]:
    """
    Returns the peer certificate and intermediate chain for a given TLS connection
    on `(host, post)`.
    """
    ctx = SSL.Context(method=SSL.TLS_METHOD)
    ctx.load_verify_locations(cafile=cafile)

    conn = SSL.Connection(ctx, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.set_tlsext_host_name(host.encode())
    conn.connect((host, port))
    conn.do_handshake()

    chain = conn.get_verified_chain()
    assert chain is not None

    return [Certificate(c.to_cryptography()) for c in chain]


def compile() -> None:
    # NOTE: Uses `ASSETS_DIR_RW` instead of `ASSETS_PATH` since the latter
    # is a read-only API for package resources.
    online_assets = ASSETS_DIR_RW / "online"
    online_assets.mkdir(exist_ok=True)

    for host in _TOPSITES:
        logger.info(f"generating online testcase for {host}")

        peer_chain = _peer_chain(host=host)

        # NOTE: We use the peer certificate's own state to produce our expected
        #  validation time. This would be incorrect in a normal path validation operation,
        # but the point of these testcases is to exercise consistent verification of known-good
        # inputs. Using the peer's own states helps make our generation more reproducible here.
        peer_cert = peer_chain[0]
        peer_cert_validation_time = peer_cert.cert.not_valid_before.replace(tzinfo=UTC) + timedelta(
            seconds=1
        )

        builder = (
            Builder(id=f"online::{host}", description=f"A valid chain for `{host}`.")
            .server_validation()
            .peer_certificate(peer_cert)
            .untrusted_intermediates(*peer_chain[1:-1])
            .trusted_certs(*peer_chain[-1:])
            .expected_peer_name(PeerName(kind="DNS", value=host))
            .validation_time(peer_cert_validation_time)
            .succeeds()
        )

        testcase = builder.build()
        path = online_assets / f"{host}.limbo.json"
        path.write_text(testcase.model_dump_json(indent=2))


def register_testcases() -> None:
    online_assets = ASSETS_PATH / "online"
    for tc_path in online_assets.iterdir():
        testcase = Testcase.model_validate_json(tc_path.read_text())

        print(f"loading pre-generated testcase: {testcase.id}")

        # Python lambdas capture variables, not values, so we need
        # an explicit capture on the current local.
        registry[testcase.id] = lambda testcase=testcase: testcase

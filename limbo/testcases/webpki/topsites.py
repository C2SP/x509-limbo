import socket
from datetime import datetime, timezone
from typing import Callable

import certifi
from OpenSSL import SSL

from limbo.assets import Certificate
from limbo.models import PeerName
from limbo.testcases._core import Builder, testcase

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
]


def _rename(name: str) -> Callable:
    def deco(f: Callable) -> Callable:
        f.__name__ = name
        return f

    return deco


def build_testcases() -> None:
    for site in _TOPSITES:

        @testcase
        @_rename(site)
        def _(builder: Builder) -> None:
            # TODO: Figure out the docstring here at some point.
            ctx = SSL.Context(method=SSL.TLS_METHOD)
            ctx.load_verify_locations(cafile=certifi.where())

            conn = SSL.Connection(ctx, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.set_tlsext_host_name(site.encode())
            conn.connect((site, 443))
            conn.do_handshake()

            peer_chain = [
                Certificate(c.to_cryptography()) for c in (conn.get_verified_chain() or [])
            ]

            builder = (
                builder.server_validation()
                .peer_certificate(peer_chain[0])
                .untrusted_intermediates(*peer_chain[1:-1])
                .trusted_certs(*peer_chain[-1:])
                .expected_peer_name(PeerName(kind="DNS", value=site))
                .validation_time(datetime.now(timezone.utc))
            )
            builder.succeeds()


build_testcases()

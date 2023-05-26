"""
Models and definitions for generating Limbo testcases.
"""

from __future__ import annotations

from datetime import datetime
from textwrap import dedent
from typing import Callable, Self

from limbo.assets import (
    Asset,
    ee_cert_from_intermediate_pathlen_n,
    intermediate_ca_pathlen_n,
    v3_root_ca,
)
from limbo.models import OID, KeyUsage, KnownEKUs, PeerName, SignatureAlgorithm, Testcase


class _TestcaseBuilder:
    def __init__(self, id: str, description: str):
        self._id = id
        self._description = description
        self._validation_kind: str | None = None
        self._trusted_certs: list[str] = []
        self._untrusted_intermediates: list[str] = []
        self._peer_certificate: str | None = None
        self._validation_time: datetime | None = None
        self._signature_algorithms: list[SignatureAlgorithm] = []
        self._key_usage: list[KeyUsage] | None = None
        self._extended_key_usage: list[KnownEKUs | OID] | None = None

        self._expected_result: str | None = None
        self._expected_peer_name: PeerName | None = None
        self._expected_peer_names: list[PeerName] | None = None

    def client_validation(self) -> Self:
        self._validation_kind = "CLIENT"
        return self

    def server_validation(self) -> Self:
        self._validation_kind = "SERVER"
        return self

    def trusted_certs(self, *certs: list[Asset]) -> Self:
        self._trusted_certs = [c.contents.decode() for c in certs]
        return self

    def untrusted_intermediates(self, *certs: list[Asset]) -> Self:
        self._untrusted_intermediates = [c.contents.decode() for c in certs]
        return self

    def peer_certificate(self, cert: Asset) -> Self:
        self._peer_certificate = cert.contents.decode()
        return self

    def validation_time(self, time: datetime) -> Self:
        self._validation_time = time
        return self

    def signature_algorithms(self, algos: list[SignatureAlgorithm]) -> Self:
        self._signature_algorithms = algos
        return self

    def key_usage(self, usage: list[KeyUsage]) -> Self:
        self._key_usage = usage
        return self

    def extended_key_usage(self, usage: list[KnownEKUs | OID]) -> Self:
        self._extended_key_usage = usage
        return self

    def succeeds(self) -> Self:
        self._expected_result = "SUCCESS"
        return self

    def fails(self) -> Self:
        self._expected_result = "FAILURE"
        return self

    def expected_peer_name(self, name: PeerName) -> Self:
        self._expected_peer_name = name
        return self

    def expected_peer_names(self, names: list[PeerName]) -> Self:
        self._expected_peer_names = names
        return self

    def build(self) -> Testcase:
        return Testcase(
            id=self._id,
            description=self._description,
            validation_kind=self._validation_kind,
            trusted_certs=self._trusted_certs,
            untrusted_intermediates=self._untrusted_intermediates,
            peer_certificate=self._peer_certificate,
            validation_time=self._validation_time,
            signature_algorithms=self._signature_algorithms,
            key_usage=self._key_usage,
            extended_key_usage=self._extended_key_usage,
            expected_result=self._expected_result,
            expected_peer_name=self._expected_peer_name,
        )


def _testcase(func: Callable) -> Callable:
    name = func.__name__.replace("_", "-")
    description = dedent(func.__doc__).strip() if func.__doc__ else name

    def wrapped() -> Testcase:
        builder = _TestcaseBuilder(id=name, description=description)

        func(builder)

        return builder.build()

    return wrapped


@_testcase
def ee_with_intermediate_pathlen_0(builder: _TestcaseBuilder) -> None:
    """
    Verifies an EE certificate with the following chains:

    ```
    EE -> intermediate (pathlen:0) -> root
    ```

    This is a "trivial" verification: the intermediate has a `pathlen:0`
    constraint, but the leaf is an end entity and is therefore allowed.
    """
    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(v3_root_ca())
        .untrusted_intermediates(intermediate_ca_pathlen_n(0))
        .peer_certificate(ee_cert_from_intermediate_pathlen_n(0))
        .succeeds()
    )

    builder.succeeds()


@_testcase
def ee_with_intermediate_pathlen_1(builder: _TestcaseBuilder) -> None:
    """
    Verifies an EE certificate with the following chains:

    ```
    EE -> intermediate (pathlen:1) -> root
    ```

    This is a "trivial" verification: the intermediate has a `pathlen:1`
    constraint, but the leaf is an end entity and is therefore allowed.
    """
    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(v3_root_ca())
        .untrusted_intermediates(intermediate_ca_pathlen_n(1))
        .peer_certificate(ee_cert_from_intermediate_pathlen_n(1))
        .succeeds()
    )

    builder.succeeds()


@_testcase
def ee_with_intermediate_pathlen_2(builder: _TestcaseBuilder) -> None:
    """
    Verifies an EE certificate with the following chains:

    ```
    EE -> intermediate (pathlen:2) -> root
    ```

    This is a "trivial" verification: the intermediate has a `pathlen:2`
    constraint, but the leaf is an end entity and is therefore allowed.
    """
    builder = builder.client_validation()
    builder = (
        builder.trusted_certs(v3_root_ca())
        .untrusted_intermediates(intermediate_ca_pathlen_n(2))
        .peer_certificate(ee_cert_from_intermediate_pathlen_n(2))
        .succeeds()
    )

    builder.succeeds()

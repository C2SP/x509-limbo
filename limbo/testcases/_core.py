from __future__ import annotations

from datetime import datetime
from textwrap import dedent
from typing import Callable, Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from limbo.assets import (
    _EPOCH,
    _ONE_THOUSAND_YEARS_OF_TORMENT,
    CertificatePair,
)
from limbo.models import OID, KeyUsage, KnownEKUs, PeerName, SignatureAlgorithm, Testcase


class Builder:
    # @cache
    def root_ca(
        self,
        *,
        issuer: x509.Name,
        subject: x509.Name | None = None,
        serial: int | None = None,
        not_before: datetime = _EPOCH,
        not_after: datetime = _ONE_THOUSAND_YEARS_OF_TORMENT,
        key: PrivateKeyTypes | None = None,
        aki: bool = False,
        ski: bool = True,
    ) -> CertificatePair:
        if subject is None:
            subject = issuer

        if serial is None:
            serial = x509.random_serial_number()

        if key is None:
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        builder = x509.CertificateBuilder(
            issuer_name=issuer,
            subject_name=subject,
            public_key=key.public_key(),  # type: ignore[arg-type]
            serial_number=serial,
            not_valid_before=not_before,
            not_valid_after=not_after,
        )

        builder = builder.add_extension(
            # TODO: Configurability here.
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )

        builder = builder.add_extension(
            # TODO: Configurability here.
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        )

        if aki:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    key.public_key()  # type: ignore[arg-type]
                ),
                critical=False,
            )
        if ski:
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    key.public_key()  # type: ignore[arg-type]
                ),
                critical=False,
            )

        cert = builder.sign(key, algorithm=hashes.SHA256())  # type: ignore[arg-type]

        return CertificatePair(cert, key)

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

    def trusted_certs(self, *certs: CertificatePair) -> Self:
        self._trusted_certs = [c.cert_pem for c in certs]
        return self

    def untrusted_intermediates(self, *certs: CertificatePair) -> Self:
        self._untrusted_intermediates = [c.cert_pem for c in certs]
        return self

    def peer_certificate(self, cert: CertificatePair) -> Self:
        self._peer_certificate = cert.cert_pem
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


registry: dict[str, Callable] = {}


def testcase(func: Callable) -> Callable:
    namespace = func.__module__.replace("_", "-")
    name = func.__name__.replace("_", "-")
    id = f"{namespace}::{name}"

    if id in registry:
        raise ValueError(f"duplicate testcase name: {id} is already registered")

    description = dedent(func.__doc__).strip() if func.__doc__ else name

    def wrapped() -> Testcase:
        builder = Builder(id=id, description=description)

        func(builder)

        return builder.build()

    registry[id] = wrapped
    return wrapped

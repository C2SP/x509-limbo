from __future__ import annotations

from datetime import datetime
from functools import cache
from textwrap import dedent
from typing import Callable, Literal, Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from limbo.assets import (
    _EPOCH,
    _ONE_THOUSAND_YEARS_OF_TORMENT,
    Certificate,
    CertificatePair,
    _Extension,
    ext,
)
from limbo.models import OID, Feature, KeyUsage, KnownEKUs, PeerName, SignatureAlgorithm, Testcase


class Builder:
    def _ca(
        self,
        issuer: x509.Name,
        subject: x509.Name | None,
        serial: int | None,
        not_before: datetime,
        not_after: datetime,
        key: PrivateKeyTypes | None,
        basic_constraints: _Extension[x509.BasicConstraints] | None,
        key_usage: _Extension[x509.KeyUsage] | None,
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None,
        ski: _Extension[x509.SubjectKeyIdentifier] | Literal[True] | None,
        extra_extension: _Extension[x509.UnrecognizedExtension] | None,
        parent: CertificatePair | None,
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

        if basic_constraints:
            builder = builder.add_extension(
                basic_constraints.ext,
                critical=basic_constraints.critical,
            )

        if key_usage:
            builder = builder.add_extension(key_usage.ext, critical=key_usage.critical)

        if isinstance(aki, _Extension):
            builder = builder.add_extension(aki.ext, critical=aki.critical)
        elif aki and parent:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    parent.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            )
        elif aki:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    key.public_key()  # type: ignore[arg-type]
                ),
                critical=False,
            )

        if isinstance(ski, _Extension):
            builder = builder.add_extension(ski.ext, critical=ski.critical)
        elif ski:
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    key.public_key()  # type: ignore[arg-type]
                ),
                critical=False,
            )

        if extra_extension:
            builder = builder.add_extension(extra_extension.ext, critical=extra_extension.critical)

        if parent:
            cert = builder.sign(parent.key, algorithm=hashes.SHA256())  # type: ignore[arg-type]
        else:
            cert = builder.sign(key, algorithm=hashes.SHA256())  # type: ignore[arg-type]

        return CertificatePair(cert, key)

    @cache
    def root_ca(
        self,
        *,
        issuer: x509.Name = x509.Name.from_rfc4514_string("CN=x509-limbo-root"),
        subject: x509.Name | None = None,
        serial: int | None = None,
        not_before: datetime = _EPOCH,
        not_after: datetime = _ONE_THOUSAND_YEARS_OF_TORMENT,
        key: PrivateKeyTypes | None = None,
        basic_constraints: _Extension[x509.BasicConstraints]
        | None = ext(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ),
        key_usage: _Extension[x509.KeyUsage]
        | None = ext(
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
        ),
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None = None,
        ski: _Extension[x509.SubjectKeyIdentifier] | Literal[True] | None = True,
        extra_extension: _Extension[x509.UnrecognizedExtension] | None = None,
    ) -> CertificatePair:
        return self._ca(
            issuer,
            subject,
            serial,
            not_before,
            not_after,
            key,
            basic_constraints,
            key_usage,
            aki,
            ski,
            extra_extension,
            None,
        )

    @cache
    def intermediate_ca(
        self,
        parent: CertificatePair,
        *,
        pathlen: int | None = None,
        issuer: x509.Name | None = None,
        subject: x509.Name | None = None,
        serial: int | None = None,
        not_before: datetime = _EPOCH,
        not_after: datetime = _ONE_THOUSAND_YEARS_OF_TORMENT,
        key: PrivateKeyTypes | None = None,
        key_usage: _Extension[x509.KeyUsage]
        | None = ext(
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
        ),
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None = True,
        ski: _Extension[x509.SubjectKeyIdentifier] | Literal[True] | None = True,
        extra_extension: _Extension[x509.UnrecognizedExtension] | None = None,
    ) -> CertificatePair:
        """
        An intermediate CA chained up to a root CA.

        The intermediate CA has a `pathlen:N` constraint, where `N` varies.

        These intermediates can be used to assert various behaviors, including:

        * That `pathlen:N` constraints are properly honored;
        * That certificates are correctly uniqued by both their key **and** their
          subject (as each intermediate generated here shares the same key)
        """
        if not issuer:
            issuer = parent.cert.subject

        if not subject:
            # NOTE: Stuff the parent cert's SN into the subject here to break accidental
            # self-issuing chains.
            subject = x509.Name.from_rfc4514_string(
                f"CN=x509-limbo-intermediate-pathlen-{pathlen},OU={parent.cert.serial_number}"
            )

        basic_constraints = ext(x509.BasicConstraints(True, path_length=pathlen), critical=True)

        return self._ca(
            issuer,
            subject,
            serial,
            not_before,
            not_after,
            key,
            basic_constraints,
            key_usage,
            aki,
            ski,
            extra_extension,
            parent,
        )

    def leaf_cert(
        self,
        parent: CertificatePair,
        *,
        issuer: x509.Name | None = None,
        subject: x509.Name = x509.Name.from_rfc4514_string("CN=x509-limbo-ee"),
        serial: int | None = None,
        not_before: datetime = _EPOCH,
        not_after: datetime = _ONE_THOUSAND_YEARS_OF_TORMENT,
        key: PrivateKeyTypes | None = None,
        key_usage: _Extension[x509.KeyUsage]
        | None = ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
        san: _Extension[x509.SubjectAlternativeName] | Literal[True] | None = None,
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None = True,
        extra_extension: _Extension[x509.UnrecognizedExtension] | None = None,
    ) -> CertificatePair:
        """
        Produces an end-entity (EE) certificate, signed by the given `parent`'s
        key.
        """
        if issuer is None:
            issuer = parent.cert.subject

        if serial is None:
            serial = x509.random_serial_number()

        if key is None:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        builder = builder.serial_number(serial)
        builder = builder.public_key(key.public_key())  # type: ignore[arg-type]
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),  # type: ignore[arg-type]
            critical=False,
        )

        if isinstance(aki, _Extension):
            builder = builder.add_extension(aki.ext, critical=aki.critical)
        elif aki:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    parent.key.public_key()  # type: ignore[arg-type]
                ),
                critical=False,
            )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=False,
        )

        if key_usage:
            builder = builder.add_extension(key_usage.ext, critical=key_usage.critical)

        if isinstance(san, _Extension):
            builder = builder.add_extension(san.ext, san.critical)
        elif san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False
            )

        if extra_extension is not None:
            builder = builder.add_extension(extra_extension.ext, extra_extension.critical)

        certificate = builder.sign(
            private_key=parent.key,  # type: ignore[arg-type]
            algorithm=hashes.SHA256(),
        )

        return CertificatePair(certificate, key)

    def __init__(self, id: str, description: str):
        self._id = id
        self._features: list[Feature] | None = None
        self._description = description
        self._validation_kind: str | None = None
        self._trusted_certs: list[str] = []
        self._untrusted_intermediates: list[str] = []
        self._peer_certificate: str | None = None
        self._validation_time: datetime | None = None
        self._signature_algorithms: list[SignatureAlgorithm] | None = None
        self._key_usage: list[KeyUsage] | None = None
        self._extended_key_usage: list[KnownEKUs | OID] | None = None

        self._expected_result: str | None = None
        self._expected_peer_name: PeerName | None = None
        self._expected_peer_names: list[PeerName] | None = None

    def features(self, feats: list[Feature]) -> Self:
        self._features = feats
        return self

    def client_validation(self) -> Self:
        self._validation_kind = "CLIENT"
        return self

    def server_validation(self) -> Self:
        self._validation_kind = "SERVER"
        return self

    def trusted_certs(self, *certs: Certificate) -> Self:
        self._trusted_certs = [c.cert_pem for c in certs]
        return self

    def untrusted_intermediates(self, *certs: Certificate) -> Self:
        self._untrusted_intermediates = [c.cert_pem for c in certs]
        return self

    def peer_certificate(self, cert: Certificate) -> Self:
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
            features=self._features,
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
    namespace = func.__module__.split(".")[-1].replace("_", "-")
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

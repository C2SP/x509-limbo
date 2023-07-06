"""
Models and definitions for generating certificate assets for Limbo testcases.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from functools import cache, cached_property
from typing import Generic, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import ExtensionType, NameOID

_EPOCH = datetime.datetime.fromtimestamp(0)
_ONE_THOUSAND_YEARS_OF_TORMENT = _EPOCH + datetime.timedelta(days=365 * 1000)
_ExtensionType = TypeVar("_ExtensionType", bound=ExtensionType)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CertificatePair:
    """
    An X.509 certificate and its associated private key.
    """

    cert: x509.Certificate
    key: PrivateKeyTypes

    @cached_property
    def key_pem(self) -> str:
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    @cached_property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode()


@dataclass(frozen=True)
class _Extension(Generic[_ExtensionType]):
    """
    An X.509 extension and its criticality.
    """

    ext: _ExtensionType
    critical: bool


def ext(extension: _ExtensionType, *, critical: bool) -> _Extension[_ExtensionType]:
    """
    Constructs a new _Extension to pass into certificate builder helpers.
    """
    return _Extension(extension, critical)


@cache
def intermediate_ca_pathlen_n(
    parent: CertificatePair, pathlen: int, *, extra_extension: _Extension | None = None
) -> CertificatePair:
    """
    An intermediate CA chained up to a root CA.

    The intermediate CA has a `pathlen:N` constraint, where `N` varies.

    These intermediates can be used to assert various behaviors, including:

    * That `pathlen:N` constraints are properly honored;
    * That certificates are correctly uniqued by both their key **and** their
      subject (as each intermediate generated here shares the same key)
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f"x509-limbo-intermediate-pathlen-{pathlen}"
                ),
            ]
        )
    )
    builder = builder.issuer_name(parent.cert.subject)
    builder = builder.not_valid_before(_EPOCH)
    builder = builder.not_valid_after(_ONE_THOUSAND_YEARS_OF_TORMENT)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            parent.key.public_key()  # type: ignore[arg-type]
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen),
        critical=True,
    )
    builder = builder.add_extension(
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
    if extra_extension:
        builder = builder.add_extension(extra_extension.ext, critical=extra_extension.critical)

    certificate = builder.sign(
        private_key=parent.key,  # type: ignore[arg-type]
        algorithm=hashes.SHA256(),
    )

    return CertificatePair(certificate, key)


@cache
def ee_cert(
    parent: CertificatePair, *, extra_extension: _Extension | None = None
) -> CertificatePair:
    """
    Produces an end-entity (EE) certificate, signed by the given `parent`'s
    key.
    """
    # NOTE: Throwaway keys, since we only care that they're distinct.
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "x509-limbo-ee"),
            ]
        )
    )
    builder = builder.issuer_name(parent.cert.subject)
    builder = builder.not_valid_before(_EPOCH)
    builder = builder.not_valid_after(_ONE_THOUSAND_YEARS_OF_TORMENT)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ee_key.public_key())
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key()),
        critical=False,
    )
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
    builder = builder.add_extension(
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
    )
    if extra_extension is not None:
        builder = builder.add_extension(extra_extension.ext, extra_extension.critical)

    certificate = builder.sign(
        private_key=parent.key,  # type: ignore[arg-type]
        algorithm=hashes.SHA256(),
    )

    return CertificatePair(certificate, ee_key)

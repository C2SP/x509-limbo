"""
Models and definitions for generating assets for Limbo testcases.
"""

from __future__ import annotations

import datetime
import functools
import logging
from dataclasses import dataclass
from functools import cache, cached_property
from textwrap import dedent
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import NameOID

_EPOCH = datetime.datetime.fromtimestamp(0)
_ONE_THOUSAND_YEARS_OF_TORMENT = _EPOCH + datetime.timedelta(days=365 * 1000)


logger = logging.getLogger(__name__)


@dataclass
class CertificatePair:
    """
    An X.509 certificate and its associated private key.
    """

    cert: x509.Certificate
    key: PrivateKeyTypes


_Builder = Callable[[], CertificatePair]


class Asset:
    """
    Represents a testcase asset, i.e. a `CertificatePair` with an name
    and a short description.
    """

    def __init__(self, name: str, description: str, builder: _Builder) -> None:
        self.name = name
        self.description = description
        self.cert_pair = builder()

    @cached_property
    def key(self) -> PrivateKeyTypes:
        return self.cert_pair.key

    @cached_property
    def key_pem(self) -> str:
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    @cached_property
    def cert(self) -> x509.Certificate:
        return self.cert_pair.cert

    @cached_property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode()


def _asset(func: Callable[..., CertificatePair]) -> Callable[..., Asset]:
    name = func.__name__.replace("_", "-")
    description = dedent(func.__doc__).strip() if func.__doc__ else name

    @cache
    def _wrapped(*args: list[Any]) -> Asset:
        return Asset(name, description, functools.partial(func, *args))

    return _wrapped


@_asset
def v3_root_ca() -> CertificatePair:
    """
    An X.509v3 root CA.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "x509-limbo-root"),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "x509-limbo-root"),
            ]
        )
    )
    builder = builder.not_valid_before(_EPOCH)
    builder = builder.not_valid_after(_ONE_THOUSAND_YEARS_OF_TORMENT)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
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
    certificate = builder.sign(
        private_key=key,
        algorithm=hashes.SHA256(),
    )

    return CertificatePair(certificate, key)


@_asset
def intermediate_ca_pathlen_n(pathlen: int) -> CertificatePair:
    """
    An intermediate CAs chained up to a root CA.

    The intermediate CA has a `pathlen:N` constraint, where `N` varies.

    These intermediates can be used to assert various behaviors, including:

    * That `pathlen:N` constraints are properly honored;
    * That certificates are correctly uniqued by both their key **and** their
      subject (as each intermediate generated here shares the same key)
    """
    subject_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key = v3_root_ca().key

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
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "x509-limbo-root"),
            ]
        )
    )
    builder = builder.not_valid_before(_EPOCH)
    builder = builder.not_valid_after(_ONE_THOUSAND_YEARS_OF_TORMENT)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(subject_key.public_key())
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
    certificate = builder.sign(
        private_key=signing_key,
        algorithm=hashes.SHA256(),
    )

    return CertificatePair(certificate, subject_key)


@_asset
def ee_cert_from_intermediate_pathlen_n(intermediate: int) -> CertificatePair:
    """
    An end-entity (EE) certificate chained through a particular
    `pathlen:N` constrained intermediate CA.

    Each of these EE certificates is valid but can be used to assert various
    behaviors, including:

    * That an intermediate's `pathlen:N` constraint doesn't incorrectly
      trigger on non-exact matches (e.g. `M: M <= N` passes)
    * That the correct intermediate path is built (e.g.
      `ee-from-intermediate-pathlen-0.pem` **must** build through
      `intermediate-ca-pathlen-0.pem` due to subject matching)
    """
    # NOTE: Throwaway keys, since we only care that they're distinct.
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key = intermediate_ca_pathlen_n(intermediate).key

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f"x509-limbo-ee-from-intermediate-pathlen-{intermediate}"
                ),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f"x509-limbo-intermediate-pathlen-{intermediate}"
                ),
            ]
        )
    )
    builder = builder.not_valid_before(_EPOCH)
    builder = builder.not_valid_after(_ONE_THOUSAND_YEARS_OF_TORMENT)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ee_key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
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
    certificate = builder.sign(
        private_key=signing_key,
        algorithm=hashes.SHA256(),
    )

    return CertificatePair(certificate, ee_key)

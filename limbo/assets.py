"""
Models and definitions for generating assets for Limbo testcases.
"""


import datetime
from functools import cache
from typing import Any, Callable, ParamSpec, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import NameOID

_EPOCH = datetime.datetime.fromtimestamp(0)
_ONE_THOUSAND_YEARS_OF_TORMENT = _EPOCH + datetime.timedelta(days=365 * 1000)


class Asset:
    def __init__(self, name: str, description: str, contents: bytes) -> None:
        self.name = name
        self.description = description
        self.contents = contents

    @cache
    def as_privkey(self) -> PrivateKeyTypes:
        return serialization.load_pem_private_key(self.contents, password=None)

    @cache
    def as_cert(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.contents)


_P = ParamSpec("_P")
_F = TypeVar("_F", bound=Callable[..., Any])


def _asset(name: str, description: str) -> Callable[[_F], Callable[_P, Asset]]:
    def wrapper(func: Callable[_P, bytes]) -> Callable[_P, Asset]:
        # NOTE: This caching decorator ensures consistency within
        # a given run -- without it, keys and other in-place generated
        # materials would change on each invocation.
        @cache
        def wrapped() -> Asset:
            result = func()
            return Asset(name, description, result)

        return wrapped  # type: ignore[return-value]

    return wrapper


@_asset("root.key", description="A 4096-bit RSA key for v3-root.pem")
def _root_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


@_asset("v3-root.pem", description="An x509v3 root CA")
def _v3_root_ca() -> bytes:
    key: rsa.RSAPrivateKey = _root_key().as_privkey()  # type: ignore[assignment]
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
    return certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    )


@_asset("intermediate.key", description="A 2048-bit RSA key for v3-intermediate.pem")
def _intermediate_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

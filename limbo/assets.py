"""
Models and definitions for generating assets for Limbo testcases.
"""


import datetime
from functools import cache

from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


_EPOCH = datetime.datetime.fromtimestamp(0)
_ONE_THOUSAND_YEARS_OF_TORMENT = _EPOCH + datetime.timedelta(days=365 * 1000)


class Asset:
    def __init__(self, name: str, contents: bytes) -> None:
        self.name = name
        self.contents = contents

    @cache
    def as_privkey(self) -> PrivateKeyTypes:
        return serialization.load_pem_private_key(self.contents, password=None)


def _asset(name: str):
    def wrapper(func):
        # NOTE: This caching decorator ensures consistency within
        # a given run -- without it, keys and other in-place generated
        # materials would change on each invocation.
        @cache
        def wrapped() -> Asset:
            result = func()
            return Asset(name, result)

        return wrapped

    return wrapper


@_asset("root.key")
def _root_key() -> Asset:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


@_asset("intermediate.key")
def _intermediate_key() -> Asset:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


@_asset("v3-root.pem")
def _v3_root_ca() -> Asset:
    key = _root_key().as_privkey()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "cryptography.io"),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "cryptography.io"),
            ]
        )
    )
    builder = builder.not_valid_before(_EPOCH)
    builder = builder.not_valid_after(_ONE_THOUSAND_YEARS_OF_TORMENT)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName("cryptography.io")]), critical=False
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    certificate = builder.sign(
        private_key=key,
        algorithm=hashes.SHA256(),
    )
    return certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    )

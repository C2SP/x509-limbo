"""
Models and definitions for generating assets for Limbo testcases.
"""

from __future__ import annotations

import datetime
import functools
import itertools
import logging
from functools import cache, cached_property
from pathlib import Path
from typing import Any, Callable, Iterable, ParamSpec, Self, Sequence, TypeVar, overload

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import NameOID

_EPOCH = datetime.datetime.fromtimestamp(0)
_ONE_THOUSAND_YEARS_OF_TORMENT = _EPOCH + datetime.timedelta(days=365 * 1000)

_ASSET_REGISTRY: dict[str, Asset] = {}


_Builder = Callable[[], bytes]


logger = logging.getLogger(__name__)


class Asset:
    """
    Represents a testcase asset.

    Conceptually, an asset is a collection of bytes (a key, a certificate, etc.),
    along with a name and a short human-readable description.
    Assets are either constructed from a "builder" or loaded from disk
    (by their name).

    In practice, testcases are frequently mutually interdependent,
    meaning that loading them from disk while also generating new ones
    must be done with care.
    """

    def __init__(self, name: str, description: str, builder: _Builder) -> None:
        self.name = name
        self.description = description
        self.builder = builder
        self.dir: Path | None = None

    def bind(self, dir: Path) -> Self:
        self.dir = dir
        return self

    @cache
    def load(self) -> bytes | None:
        if self.dir is None:
            raise ValueError("cannot load: asset not bound to a directory")

        path = self.dir / self.name
        return path.read_bytes() if path.exists() else None

    @cached_property
    def contents(self) -> bytes:
        # If this asset is bound to a directory, we can try loading from it.
        # Otherwise, fall back on building it.
        contents: bytes | None = None
        if self.dir:
            logger.debug(f"{self.name} is bound, attempting to load from file")
            contents = self.load()

        if contents is None:
            logger.debug(f"{self.name} is being constructed (either unbound or no file)")
            contents = self.builder()

        return contents

    @cache
    def as_privkey(self) -> PrivateKeyTypes:
        return serialization.load_pem_private_key(self.contents, password=None)

    @cache
    def as_cert(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.contents)


_P = ParamSpec("_P")
_F = TypeVar("_F", bound=Callable[..., Any])


@overload
def _asset(
    name: str,
    *,
    description: str,
    parametrize: Sequence[Any] | Sequence[Sequence[Any]],
) -> Callable[[_F], Callable[_P, list[Asset]]]:
    ...


@overload
def _asset(
    name: str,
    *,
    description: str,
) -> Callable[[_F], Callable[_P, Asset]]:
    ...


def _asset(
    name: str,
    *,
    description: str,
    parametrize: Sequence[Any] | Sequence[Sequence[Any]] | None = None,
) -> Callable[[_F], Callable[_P, Asset | list[Asset]]]:
    if parametrize and not isinstance(parametrize[0], Sequence):
        parametrize = [parametrize]

    def wrapper(func: Callable[_P, bytes]) -> Callable[_P, Asset | list[Asset]]:
        # NOTE: This caching decorator ensures consistency within
        # a given run -- without it, keys and other in-place generated
        # materials would change on each invocation.
        @cache
        def wrapped() -> Asset | list[Asset]:
            if parametrize:
                assets = []
                for args in itertools.product(*parametrize):
                    name_ = name.format(*args)
                    if name_ in _ASSET_REGISTRY:
                        raise ValueError(f"invalid asset: {name} already registered")

                    description_ = description.format(*args)
                    builder = functools.partial(func, *args)
                    asset = Asset(name_, description_, builder)

                    _ASSET_REGISTRY[name_] = asset
                    assets.append(asset)
                return assets
            else:
                if name in _ASSET_REGISTRY:
                    raise ValueError(f"invalid asset: {name} already registered")

                asset = Asset(name, description, func)
                _ASSET_REGISTRY[name] = asset
                return asset

        return wrapped  # type: ignore[return-value]

    return wrapper


# TODO: May be needed in the future, but not yet.
# def _get_asset(name: str) -> Asset:
#     """
#     Retrieve an asset by name.

#     Name lookups are done through an internal registry that gets populated
#     as each `Asset` is "concretized," meaning that a successful lookup
#     requires that the corresponding `Asset` has already been used at least
#     once.
#     """
#     return _ASSET_REGISTRY[name]


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


@_asset(
    "intermediate-ca-pathlen-{0}.pem",
    description="intermediate CA, pathlen:{0}, via v3-root.pem",
    parametrize=[0, 1, 2],  # different pathlen constraints
)
def _intermediate_ca_pathlen_n(pathlen: int) -> bytes:
    """
    Generates intermediate CAs chained up to a root CA.

    Each intermediate CA has a `pathlen:N` constraint, where `N` varies.

    These intermediates can be used to assert various behaviors, including:

    * That `pathlen:N` constraints are properly honored;
    * That certificates are correctly uniqued by both their key **and** their
      subject (as each intermediate generated here shares the same key)
    """
    subject_key: rsa.RSAPublicKey = (
        _intermediate_key().as_privkey().public_key()  # type: ignore[assignment]
    )
    signing_key: rsa.RSAPrivateKey = _root_key().as_privkey()  # type: ignore[assignment]

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
    builder = builder.public_key(subject_key)
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
    return certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    )


@_asset(
    "ee-from-intermediate-pathlen-{0}.pem",
    description="EE cert via intermediate-ca-pathlen-{0}.pem",
    parametrize=[0, 1, 2],
)
def _ee_cert_from_intermediate_pathlen_n(intermediate: int) -> bytes:
    """
    Generates end-entity (EE) certificates chained through a particular
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
    signing_key: rsa.RSAPrivateKey = _intermediate_key().as_privkey()  # type: ignore[assignment]

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
    return certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    )


def assets(load_from: Path) -> Iterable[Asset]:
    # TODO: Dedupe; This should be part of the decorator magic above.

    yield _root_key().bind(load_from)
    yield _v3_root_ca().bind(load_from)
    yield _intermediate_key().bind(load_from)
    yield from (a.bind(load_from) for a in _intermediate_ca_pathlen_n())
    yield from (a.bind(load_from) for a in _ee_cert_from_intermediate_pathlen_n())

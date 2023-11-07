"""
Models and definitions for generating certificate assets for Limbo testcases.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from functools import cached_property
from importlib import resources
from typing import Generic, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import ExtensionType

# NOTE: We judiciously start on the second *after* the Unix epoch, since
# some path validation libraries intentionally reject anything on or
# before the epoch.
EPOCH = datetime.datetime.utcfromtimestamp(1)
ONE_THOUSAND_YEARS_OF_TORMENT = EPOCH + datetime.timedelta(days=365 * 1000)
_ASSETS_PATH = resources.files("limbo._assets")
_ExtensionType = TypeVar("_ExtensionType", bound=ExtensionType)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Certificate:
    """
    An X.509 certificate.
    """

    cert: x509.Certificate

    @cached_property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode()


@dataclass(frozen=True)
class CertificatePair(Certificate):
    """
    An X.509 certificate and its associated private key.
    """

    key: PrivateKeyTypes

    @cached_property
    def key_pem(self) -> str:
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()


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

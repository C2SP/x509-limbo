"""
Test cases for structurally invalid certificates/chains.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding

from limbo.testcases._core import Builder, testcase


class MalformedRSAPrivateKey(rsa.RSAPrivateKey):
    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: asym_utils.Prehashed | hashes.HashAlgorithm,
    ) -> bytes:
        # SEQUENCE {}
        return b"\x30\x00"

    def public_key(self) -> MalformedRSAPublicKey:
        return MalformedRSAPublicKey()

    @property
    def key_size(self) -> int:
        raise NotImplementedError

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError


class MalformedRSAPublicKey(rsa.RSAPublicKey):
    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        assert encoding is serialization.Encoding.DER
        if format is serialization.PublicFormat.PKCS1:
            return b"\x300\x00"
        else:
            assert format is serialization.PublicFormat.SubjectPublicKeyInfo
            # SEQUENCE {
            #   SEQUENCE {
            #     # rsaEncryption
            #     OBJECT_IDENTIFIER { 1.2.840.113549.1.1.1 }
            #     NULL {}
            #   }
            #   BIT_STRING {
            #     `00`
            #     ``
            #   }
            # }
            return b"0\x120\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x01\x00"

    def __eq__(self, other: object) -> bool:
        raise NotImplementedError

    def encrypt(self, plaintext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError

    @property
    def key_size(self) -> int:
        raise NotImplementedError

    def public_numbers(self) -> rsa.RSAPublicNumbers:
        raise NotImplementedError

    def recover_data_from_signature(
        self,
        signature: bytes,
        padding: AsymmetricPadding,
        algorithm: hashes.HashAlgorithm | None,
    ) -> bytes:
        raise NotImplementedError

    def verify(
        self,
        signature: bytes,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: asym_utils.Prehashed | hashes.HashAlgorithm,
    ) -> None:
        raise NotImplementedError


@testcase
def invalid_issuer_key(builder: Builder) -> None:
    root1 = builder.root_ca()
    root2 = builder.root_ca()

    key = MalformedRSAPrivateKey()
    intermediate = builder.intermediate_ca(root2, key=key)

    leaf = builder.leaf_cert(intermediate)

    builder.server_validation().trusted_certs(root1).untrusted_intermediates(
        intermediate
    ).peer_certificate(leaf).fails()

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConstrainedStr, Field, StrictInt, StrictStr


class PeerName(BaseModel):
    kind: StrictStr  # TODO: ratchet
    value: StrictStr


class SignatureAlgorithm(str, Enum):
    """
    Valid X.509 signature algorithms.
    """

    # NOTE: We use the same names as cryptography's SignatureAlgorithmOID here,
    # so that we can just do a `getattr` to look each up.

    RSA_WITH_MD5 = "RSA_WITH_MD5"
    RSA_WITH_SHA1 = "RSA_WITH_SHA1"
    RSA_WITH_SHA224 = "RSA_WITH_SHA224"
    RSA_WITH_SHA256 = "RSA_WITH_SHA256"
    RSA_WITH_SHA384 = "RSA_WITH_SHA384"
    RSA_WITH_SHA512 = "RSA_WITH_SHA512"
    RSA_WITH_SHA3_224 = "RSA_WITH_SHA3_224"
    RSA_WITH_SHA3_256 = "RSA_WITH_SHA3_256"
    RSA_WITH_SHA3_384 = "RSA_WITH_SHA3_384"
    RSA_WITH_SHA3_512 = "RSA_WITH_SHA3_512"
    RSASSA_PSS = "RSASSA_PSS"
    ECDSA_WITH_SHA1 = "ECDSA_WITH_SHA1"
    ECDSA_WITH_SHA224 = "ECDSA_WITH_SHA224"
    ECDSA_WITH_SHA256 = "ECDSA_WITH_SHA256"
    ECDSA_WITH_SHA384 = "ECDSA_WITH_SHA384"
    ECDSA_WITH_SHA512 = "ECDSA_WITH_SHA512"
    ECDSA_WITH_SHA3_224 = "ECDSA_WITH_SHA3_224"
    ECDSA_WITH_SHA3_256 = "ECDSA_WITH_SHA3_256"
    ECDSA_WITH_SHA3_384 = "ECDSA_WITH_SHA3_384"
    ECDSA_WITH_SHA3_512 = "ECDSA_WITH_SHA3_512"
    DSA_WITH_SHA1 = "DSA_WITH_SHA1"
    DSA_WITH_SHA224 = "DSA_WITH_SHA224"
    DSA_WITH_SHA256 = "DSA_WITH_SHA256"
    DSA_WITH_SHA384 = "DSA_WITH_SHA384"
    DSA_WITH_SHA512 = "DSA_WITH_SHA512"
    ED25519 = "ED25519"
    ED448 = "ED448"
    GOSTR3411_94_WITH_3410_2001 = "GOSTR3411_94_WITH_3410_2001"
    GOSTR3410_2012_WITH_3411_2012_256 = "GOSTR3410_2012_WITH_3411_2012_256"
    GOSTR3410_2012_WITH_3411_2012_512 = "GOSTR3410_2012_WITH_3411_2012_512"


class KeyUsage(str, Enum):
    """
    X.509 key usages.

    See: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    """

    digital_signature = "digitalSignature"
    content_commitment = "contentCommitment"
    key_encipherment = "keyEncipherment"
    data_encipherment = "dataEncipherment"
    key_agreement = "keyAgreement"
    key_cert_sign = "keyCertSign"
    crl_sign = "cRLSign"
    encipher_only = "encipher_only"
    decipher_only = "decipher_only"


class KnownEKUs(str, Enum):
    """
    Well-known extended key usages, from RFC 5280.

    See: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
    """

    any = "anyExtendedKeyUsage"
    server_auth = "serverAuth"
    client_auth = "clientAuth"
    code_signing = "codeSigning"
    email_protection = "emailProtection"
    time_stamping = "timeStamping"
    ocsp_signing = "OCSPSigning"


class OID(ConstrainedStr):
    regex = r"^([0-2])((\.0)|(\.[1-9][0-9]*))*$"
    strict = True


class Testcase(BaseModel):
    """
    Represents an individual Limbo testcase.
    """

    description: StrictStr = Field(..., description="A short, human-readable description")
    validation_kind: Literal["CLIENT"] | Literal["SERVER"] = Field(
        ..., description="The kind of validation to perform"
    )

    expected_result: Literal["SUCCESS"] | Literal["ERROR"] = Field(
        ..., description="The expected validation result"
    )
    expected_peer_names: list[PeerName] = Field(..., description="The expected peer names")

    trusted_certs: list[StrictStr] = Field(
        ..., description="A list of CA certificates to consider trusted"
    )  # TODO: ratchet
    subject: StrictStr  # TODO: ratchet
    untrusted_intermediates: list[StrictStr] = Field(
        ..., description="A list of untrusted intermediates to use during path building"
    )  # TODO: ratchet
    peer_name: PeerName
    validation_time: StrictStr  # TODO: ratchet
    signature_algorithms: list[SignatureAlgorithm]
    key_usage: list[KeyUsage]
    extended_key_usage: list[KnownEKUs | OID] = Field(
        ...,
        description="A list of extended key usages, either in well-known form or as OIDs",
    )


class Limbo(BaseModel):
    """
    The top-level testcase container.
    """

    version: StrictInt
    testcases: list[Testcase] = Field(..., description="One or more testcases in this testsuite")

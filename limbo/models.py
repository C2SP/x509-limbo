from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConstrainedStr, Field, StrictStr, validator

PeerKind = Literal["RFC822"] | Literal["DNS"] | Literal["IP"]


class PeerName(BaseModel):
    """
    Represents a peer (i.e., end entity) certificate's name (Subject or SAN).
    """

    kind: PeerKind = Field(..., description="The kind of peer name")
    value: StrictStr = Field(..., description="The peer's name")


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
    """
    A "bare" OID, in dotted form.
    """

    regex = r"^([0-2])((\.0)|(\.[1-9][0-9]*))*$"
    strict = True


_ID_COMPONENT = r"[A-Za-z][A-Za-z0-9-.]+"
_NAMESPACE = rf"{_ID_COMPONENT}::"


class TestCaseID(ConstrainedStr):
    """
    Acceptable testcase IDs.

    Testcase IDs look like `namespace::id`, where `namespace::` is optional
    and only explicitly added when merging multiple testcase suites.
    """

    regex = rf"^({_NAMESPACE})*({_ID_COMPONENT})$"
    strict = True


class Testcase(BaseModel):
    """
    Represents an individual Limbo testcase.
    """

    id: TestCaseID = Field(..., description="A short, unique identifier for this testcase")

    description: StrictStr = Field(..., description="A short, Markdown-formatted description")

    validation_kind: Literal["CLIENT"] | Literal["SERVER"] = Field(
        ..., description="The kind of validation to perform"
    )

    trusted_certs: list[StrictStr] = Field(
        ..., description="A list of PEM-encoded CA certificates to consider trusted"
    )

    untrusted_intermediates: list[StrictStr] = Field(
        ..., description="A list of PEM-encoded untrusted intermediates to use during path building"
    )

    peer_certificate: StrictStr = Field(..., description="The PEM-encoded peer (EE) certificate")

    validation_time: datetime | None = Field(
        None, description="The time at which to perform the validation"
    )

    signature_algorithms: list[SignatureAlgorithm] | None = Field(
        None, description="A list of acceptable signature algorithms to constrain against"
    )

    key_usage: list[KeyUsage] | None = Field(None, description="A constraining list of key usages")

    extended_key_usage: list[KnownEKUs | OID] | None = Field(
        None,
        description=(
            "A constraining list of extended key usages, either in well-known form or as OIDs"
        ),
    )

    expected_result: Literal["SUCCESS"] | Literal["FAILURE"] = Field(
        ..., description="The expected validation result"
    )

    expected_peer_name: PeerName | None = Field(
        None, description="For client-side validation: the expected peer name, if any"
    )

    expected_peer_names: list[PeerName] | None = Field(
        None, description="For server-side validation: the expected peer names, if any"
    )


class Limbo(BaseModel):
    """
    The top-level testcase container.
    """

    version: Literal[1] = Field(
        ..., description="The limbo schema version; this must currently always be 1"
    )
    testcases: list[Testcase] = Field(..., description="One or more testcases in this testsuite")

    @validator("testcases")
    def validate_testcases_unique_ids(cls, v: list[Testcase]) -> list[Testcase]:
        ids = set()
        for case in v:
            if case.id in ids:
                raise ValueError(f"duplicated testcase id: {case.id}")
            ids.add(case.id)
        return v

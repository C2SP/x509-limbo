from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StrictStr, StringConstraints, field_validator


class ExpectedResult(str, Enum):
    """
    Represents an expected testcase evaluation result.
    """

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class ActualResult(str, Enum):
    """
    Represents the actual result of a testcase evaluation.
    """

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    SKIPPED = "SKIPPED"


class PeerKind(str, Enum):
    """
    Different types of peer subjects.
    """

    RFC822 = "RFC822"
    DNS = "DNS"
    IP = "IP"


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


OID = Annotated[str, StringConstraints(pattern=r"^([0-2])((\.0)|(\.[1-9][0-9]*))*$", strict=True)]
"""
A "bare" OID, in dotted form.
"""


_ID_COMPONENT = r"[A-Za-z][A-Za-z0-9-.]+"
_NAMESPACE = rf"{_ID_COMPONENT}::"


TestCaseID = Annotated[
    str, StringConstraints(pattern=rf"^({_NAMESPACE})*({_ID_COMPONENT})$", strict=True)
]
"""
Acceptable testcase IDs.

Testcase IDs look like `namespace::id`, where `namespace::` is optional
and only explicitly added when merging multiple testcase suites.
"""


class Feature(str, Enum):
    """
    Feature tags for testcases.
    """

    has_cert_policies = "has-cert-policies"
    """
    For implementations that explicitly support X.509 certificate policy extensions.
    """

    no_cert_policies = "no-cert-policies"
    """
    For implementations that explicitly do not support X.509 certificate policy extensions.
    """

    pedantic_public_suffix_wildcard = "pedantic-public-suffix-wildcard"
    """
    "Pedantic" public suffix wildcard SAN tests. Path validation is required to reject wildcards on
    public suffixes, however this isn't practical and most implementations make no attempt to
    comply with this.
    """

    name_constraint_dn = "name-constraint-dn"
    """
    For implementations that do not support name constraints for Distinguished Names (temporary).
    """

    pedantic_webpki = "pedantic-webpki"
    """
    Tests that exercise "pedantic" corners of the CABF profile.
    """

    pedantic_webpki_eku = "pedantic-webpki-eku"
    """
    Like `pedantic_webpkif`, but specifically for "pedantic" EKU handling under CABF.
    """

    pedantic_serial_number = "pedantic-serial-number"
    """
    Tests that exercise "pedantic" serial number handling.
    """

    max_chain_depth = "max-chain-depth"
    """
    Tests that restrict the chain-building depth. Not all implementations expose
    a configurable path length.
    """

    pedantic_rfc5280 = "pedantic-rfc5280"
    """
    Tests that exercise "pednatic" corners of the RFC 5280 certificate profile.
    """

    rfc5280_incompatible_with_webpki = "rfc5280-incompatible-with-webpki"
    """
    Tests where RFC 5280's prescription is stronger than the Web PKI's.
    """


class ValidationKind(str, Enum):
    """
    The kind of validation to perform.
    """

    CLIENT = "CLIENT"
    SERVER = "SERVER"


class Testcase(BaseModel):
    """
    Represents an individual Limbo testcase.
    """

    id: TestCaseID = Field(..., description="A short, unique identifier for this testcase")

    conflicts_with: list[TestCaseID] = Field(
        [], description="A list of testcase IDs that this testcase is mutually incompatible with"
    )

    features: list[Feature] | None = Field(
        None,
        description=(
            "One or more human-readable tags that describe OPTIONAL functionality described "
            "by this testcase. Implementers should use this to specify testcases for non-mandatory "
            "X.509 behavior (like certificate policy validation) or for 'pedantic' cases. "
            "Consumers that don't understand a given feature should skip tests that are "
            "marked with it."
        ),
    )

    description: StrictStr = Field(..., description="A short, Markdown-formatted description")

    validation_kind: ValidationKind = Field(..., description="The kind of validation to perform")

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

    expected_result: ExpectedResult = Field(..., description="The expected validation result")

    expected_peer_name: PeerName | None = Field(
        None, description="For client-side validation: the expected peer name, if any"
    )

    expected_peer_names: list[PeerName] | None = Field(
        None, description="For server-side validation: the expected peer names, if any"
    )

    max_chain_depth: int | None = Field(None, description="The maximum chain-building depth")


class Limbo(BaseModel):
    """
    The top-level testcase container.
    """

    version: Literal[1] = Field(
        ..., description="The limbo schema version; this must currently always be 1"
    )
    testcases: list[Testcase] = Field(..., description="One or more testcases in this testsuite")

    @field_validator("testcases")
    @classmethod
    def validate_testcases(cls, v: list[Testcase]) -> list[Testcase]:
        # Check that all IDs are unique.
        id_tc_map: dict[TestCaseID, Testcase] = {}
        for case in v:
            if case.id in id_tc_map:
                raise ValueError(f"duplicated testcase id: {case.id}")
            id_tc_map[case.id] = case

        # Check that all conflicts_with references are valid,
        # and bidirectional.
        for case in v:
            for cid in case.conflicts_with:
                # NOTE: https://github.com/python/mypy/issues/12998
                match _ := id_tc_map.get(cid):
                    case None:
                        raise ValueError(f"{case.id} marks conflict with nonexistent case: {cid}")
                    case conflicting_case:
                        if case.id not in conflicting_case.conflicts_with:
                            raise ValueError(f"{case.id} -> {cid} conflict is not bidirectional")

        return v


class TestcaseResult(BaseModel):
    """
    Represents the outcome of evaluating a testcase.
    """

    id: TestCaseID = Field(..., description="A short, unique identifier for the testcase")

    actual_result: ActualResult = Field(
        ...,
        description=(
            "The result of evaluating the testcase; this should be compared to "
            "`Testcase.expected_result`"
        ),
    )

    context: StrictStr | None = Field(
        ..., description="Any context for FAILURE or SKIPPED results; can be multiple lines"
    )


class LimboResult(BaseModel):
    """
    The top-level testcase result container.
    """

    version: Literal[1] = Field(
        ..., description="The limbo-result schema version; this must currently always be 1"
    )

    harness: StrictStr = Field(
        ..., description="A short, unique identifier for the harness that produced these results"
    )

    results: list[TestcaseResult] = Field(
        ..., description="One or more results for testcase evaluations"
    )

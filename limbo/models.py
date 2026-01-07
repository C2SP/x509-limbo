from __future__ import annotations

from datetime import datetime
from enum import Enum
from functools import cached_property
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    Field,
    FieldSerializationInfo,
    StrictStr,
    StringConstraints,
    field_serializer,
    field_validator,
)


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
    encipher_only = "encipherOnly"
    decipher_only = "decipherOnly"


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

    has_policy_constraints = "has-policy-constraints"
    """
    For implementations that explicitly support policy constraints and policy mapping.
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

    pedantic_webpki_subscriber_key = "pedantic-webpki-subscriber-key"
    """
    Tests that exercise "pedantic" handling of subscriber key types under CABF.

    Many CABF validators don't enforce the key requirements on subscriber (i.e. leaf, EE)
    certificates. However, the language in CABF 7.1.2.7 implies that subscriber certificates
    obey the same `subjectPublicKeyInfo` rules as CAs, as defined in CABF 7.1.3.1.
    """

    pedantic_webpki_eku = "pedantic-webpki-eku"
    """
    Tests that exercise "pedantic" EKU handling under CABF.
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

    denial_of_service = "denial-of-service"
    """
    Tests that exercise DoS resiliency.
    """

    has_crl = "has-crl"
    """
    Tests that use Certificate Revocation Lists (CRLs).
    """


class Importance(str, Enum):
    """
    A subjective ranking of a testcase's importance.
    """

    UNDETERMINED = "undetermined"
    """
    Not yet determined.
    """

    LOW = "low"
    """
    Low importance, e.g. due to a pedantic reading of the specifications
    or being commonly ignored by other implementations.
    """

    MEDIUM = "medium"
    """
    Medium importance; implementations should address these but are unlikely
    to encounter issues with real-world chains due to them.
    """

    HIGH = "high"
    """
    High importance; implementations should address these due to expected issues
    with real-world chains.
    """

    CRITICAL = "critical"
    """
    Critical importance; failure to handle this indicates a potentially
    exploitable vulnerability in the implementation under test.
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

    features: list[Feature] = Field(
        [],
        description=(
            "Zero or more human-readable tags that describe OPTIONAL functionality described "
            "by this testcase. Implementers should use this to specify testcases for non-mandatory "
            "X.509 behavior (like certificate policy validation) or for 'pedantic' cases. "
            "Consumers that don't understand a given feature should skip tests that are "
            "marked with it."
        ),
    )

    importance: Importance = Field(Importance.UNDETERMINED, description="The testcase's importance")

    description: StrictStr = Field(..., description="A short, Markdown-formatted description")

    validation_kind: ValidationKind = Field(..., description="The kind of validation to perform")

    trusted_certs: list[StrictStr] = Field(
        ..., description="A list of PEM-encoded CA certificates to consider trusted"
    )

    untrusted_intermediates: list[StrictStr] = Field(
        ..., description="A list of PEM-encoded untrusted intermediates to use during path building"
    )

    peer_certificate: StrictStr = Field(..., description="The PEM-encoded peer (EE) certificate")

    peer_certificate_key: StrictStr | None = Field(
        None,
        description="The PEM-encoded private key for the peer certificate, if present",
    )

    validation_time: datetime | None = Field(
        None, description="The time at which to perform the validation"
    )

    signature_algorithms: list[SignatureAlgorithm] = Field(
        ..., description="A list of acceptable signature algorithms to constrain against"
    )

    key_usage: list[KeyUsage] = Field(..., description="A constraining list of key usages")

    extended_key_usage: list[KnownEKUs] = Field(
        ...,
        description=(
            "A constraining list of extended key usages, either in well-known form or as OIDs"
        ),
    )

    expected_result: ExpectedResult = Field(..., description="The expected validation result")

    expected_peer_name: PeerName | None = Field(
        None, description="For server (i.e. client-side) validation: the expected peer name, if any"
    )

    expected_peer_names: list[PeerName] = Field(
        ..., description="For client (i.e. server-side) validation: the expected peer names"
    )

    max_chain_depth: int | None = Field(None, description="The maximum chain-building depth")

    crls: list[StrictStr] = Field(
        [], description="A list of PEM-encoded Certificate Revocation Lists (CRLs)", title="CRLs"
    )

    @field_validator("validation_time")
    @classmethod
    def validate_validation_time(cls, v: datetime | None) -> datetime | None:
        if v is not None:
            # Times must be in UTC.
            assert v.tzname() == "UTC"

        return v

    @field_serializer("validation_time")
    def serialize_validation_time(
        self, validation_time: datetime | None, _info: FieldSerializationInfo
    ) -> str | None:
        if validation_time is None:
            return validation_time
        # NOTE(ww): Explicitly serialize with `isoformat`, which expresses UTC
        # with `+00:00`` instead of `Z`. This is needed for Python consumers below 3.11,
        # which don't support `Z` in `fromisoformat()`.
        if validation_time.microsecond != 0:
            # Only render millis if they're present.
            return validation_time.isoformat(timespec="milliseconds")
        else:
            return validation_time.isoformat(timespec="seconds")


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

    @cached_property
    def by_id(self) -> dict[TestCaseID, Testcase]:
        """
        Returns a cached mapping of every testcase, keyed by its ID.
        """
        return {tc.id: tc for tc in self.testcases}


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

    @cached_property
    def by_id(self) -> dict[TestCaseID, TestcaseResult]:
        """
        Returns a cached mapping of every testcase result, keyed by its ID.
        """
        return {r.id: r for r in self.results}


class RegressionEntry(BaseModel):
    """Represents a single regression (changed test result)."""

    testcase_id: str = Field(..., description="The testcase ID that regressed")
    previous_result: str = Field(..., description="The previous result value")
    current_result: str = Field(..., description="The current result value")


class NewTestcaseEntry(BaseModel):
    """Represents a new testcase not in the previous results."""

    testcase_id: str = Field(..., description="The new testcase ID")
    expected_result: str = Field(..., description="The expected result")
    actual_result: str = Field(..., description="The actual result from the harness")
    context: str | None = Field(None, description="Additional context if available")


class RegressionData(BaseModel):
    """Data structure for passing regression detection results between workflows."""

    regressions: dict[str, list[RegressionEntry]] = Field(
        default_factory=dict,
        description="Map of harness name to list of regressions",
    )
    new_testcases: dict[str, list[NewTestcaseEntry]] = Field(
        default_factory=dict,
        description="Map of harness name to list of new testcases",
    )
    workflow_url: str = Field(..., description="GitHub Actions workflow URL")
    pr_number: int | None = Field(None, description="Pull request number")

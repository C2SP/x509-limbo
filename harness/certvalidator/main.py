import sys
from cgi import test
from concurrent.futures import ThreadPoolExecutor

from certvalidator import CertificateValidator, ValidationContext
from certvalidator import __version__ as version
from certvalidator.validate import validate_usage

from limbo.models import (
    ActualResult,
    KeyUsage,
    KnownEKUs,
    Limbo,
    LimboResult,
    Testcase,
    TestcaseResult,
    ValidationKind,
)

LIMBO_UNSUPPORTED_FEATURES = set()

LIMBO_SKIP_TESTCASES = set()


def _skip(tc: Testcase, msg: str) -> TestcaseResult:
    return TestcaseResult(id=tc.id, actual_result=ActualResult.SKIPPED, context=msg)


def evaluate_testcase(testcase: Testcase) -> TestcaseResult:
    if testcase.id in LIMBO_SKIP_TESTCASES:
        return _skip(testcase, "testcase skipped (explicitly unsupported case)")

    if LIMBO_UNSUPPORTED_FEATURES.intersection(testcase.features):
        return _skip(testcase, "testcase skipped (explicit unsupported feature)")

    if testcase.validation_kind != ValidationKind.SERVER:
        return _skip(testcase, "non-SERVER cases not supported yet")

    if testcase.signature_algorithms != []:
        return _skip(testcase, "signature algorithm customization not supported yet")

    context = ValidationContext(
        trust_roots=[c.encode() for c in testcase.trusted_certs],
        moment=testcase.validation_time,
        allow_fetching=False,
        weak_hash_algos={"md2", "md5", "sha1"},
    )

    validator = CertificateValidator(
        end_entity_cert=testcase.peer_certificate.encode(),
        intermediate_certs=[c.encode() for c in testcase.untrusted_intermediates],
        validation_context=context,
    )

    try:
        path = validator.validate_tls(hostname=testcase.expected_peer_name.value)
        leaf = list(path)[-1]

        key_usage = {ku.name for ku in testcase.key_usage}
        extended_key_usage = {eku.name for eku in testcase.extended_key_usage}
        validate_usage(
            context,
            leaf,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
            # EKU is required if EKUs are explicitly specified.
            extended_optional=bool(extended_key_usage),
        )
        return TestcaseResult(id=testcase.id, actual_result=ActualResult.SUCCESS, context=None)
    except Exception as e:  # noqa
        # NOTE: Ideally we'd catch only certvalidator errors here, but lots of others
        # leak through (e.g. ValueError and errors from oscrypto).
        return TestcaseResult(id=testcase.id, actual_result=ActualResult.FAILURE, context=str(e))


def main():
    limbo = Limbo.model_validate_json(sys.stdin.read())

    results: list[TestcaseResult] = []
    for testcase in limbo.testcases:
        # NOTE: This is not for true parallelism, just a way to give us cancellation.
        with ThreadPoolExecutor(max_workers=1) as executor:
            fut = executor.submit(evaluate_testcase, testcase)
            try:
                # Certificate validation should, extremely conservatively,
                # absolutely never take more than 5 seconds.
                result = fut.result(timeout=5)
            except TimeoutError:
                # NOTE: We need a better result type here.
                result = TestcaseResult(
                    id=testcase.id, actual_result=ActualResult.SKIPPED, context="testcase timed out"
                )
        results.append(result)

    print(
        LimboResult(version=1, harness=f"certvalidator-{version}", results=results).model_dump_json(
            indent=2
        )
    )


if __name__ == "__main__":
    main()

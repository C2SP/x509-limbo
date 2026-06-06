import multiprocessing as mp
import sys

from certvalidator import CertificateValidator, ValidationContext
from certvalidator import __version__ as version
from certvalidator.validate import validate_usage

from limbo.models import (
    ActualResult,
    Feature,
    Limbo,
    LimboResult,
    Testcase,
    TestcaseResult,
    ValidationKind,
)

LIMBO_UNSUPPORTED_FEATURES = {"has-crl"}

LIMBO_SKIP_TESTCASES = set()

# Certificate validation should, extremely conservatively, absolutely never take
# more than this many seconds. Anything slower is treated as a hang.
TIMEOUT_SECONDS = 5


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


def _worker(testcase_json: str, conn) -> None:
    result = evaluate_testcase(Testcase.model_validate_json(testcase_json))
    conn.send(result.model_dump_json())
    conn.close()


def _evaluate_with_cancellation(testcase: Testcase) -> TestcaseResult:
    ctx = mp.get_context()
    recv_conn, send_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_worker, args=(testcase.model_dump_json(), send_conn), daemon=True)
    proc.start()
    send_conn.close()  # the parent only reads; closing our copy lets us see EOF

    try:
        if recv_conn.poll(TIMEOUT_SECONDS):
            try:
                return TestcaseResult.model_validate_json(recv_conn.recv())
            except EOFError:
                # The worker died without sending a result (e.g. a crash).
                # Report it rather than hanging or raising.
                proc.join()
                print(f"CRASH: {testcase.id} (exit code {proc.exitcode})", file=sys.stderr)
                return TestcaseResult(
                    id=testcase.id,
                    actual_result=ActualResult.FAILURE,
                    context=f"worker crashed without a result (exit code {proc.exitcode})",
                )
        # Nothing within the timeout and the worker is still alive: a true hang.
        print(f"HANG: {testcase.id}", file=sys.stderr)
        return TestcaseResult(
            id=testcase.id, actual_result=ActualResult.HANG, context="testcase timed out"
        )
    finally:
        if proc.is_alive():
            proc.terminate()
        proc.join()
        recv_conn.close()


def main():
    limbo = Limbo.model_validate_json(sys.stdin.read())

    results: list[TestcaseResult] = []
    for testcase in limbo.testcases:
        # Only denial-of-service testcases can plausibly hang, and the
        # out-of-process timeout machinery costs a subprocess spawn per case. So
        # gate it on that feature and run everything else inline, avoiding that
        # overhead across the full suite.
        if Feature.denial_of_service in testcase.features:
            result = _evaluate_with_cancellation(testcase)
        else:
            result = evaluate_testcase(testcase)
        results.append(result)

    print(
        LimboResult(version=1, harness=f"certvalidator-{version}", results=results).model_dump_json(
            indent=2
        )
    )


if __name__ == "__main__":
    main()

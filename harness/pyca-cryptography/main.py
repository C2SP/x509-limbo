import ipaddress
import multiprocessing as mp
import sys

from cryptography import __version__ as pyca_version
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from limbo.models import (
    ActualResult,
    Feature,
    KnownEKUs,
    Limbo,
    LimboResult,
    PeerKind,
    PeerName,
    Testcase,
    TestcaseResult,
    ValidationKind,
)

# Certificate validation should, extremely conservatively, absolutely never take
# more than this many seconds. Anything slower is treated as a hang.
TIMEOUT_SECONDS = 5

LIMBO_UNSUPPORTED_FEATURES = {
    # NOTE: Path validation is required to reject wildcards on public suffixes,
    # however this isn't practical and most implementations make no attempt to
    # comply with this.
    Feature.pedantic_public_suffix_wildcard,
    # TODO: We don't support Distinguished Name Constraints yet.
    Feature.name_constraint_dn,
    # Our support for custom EKUs is limited, and we (like most impls.) don't
    # handle all EKU conditions under CABF.
    Feature.pedantic_webpki_eku,
    # Most CABF validators do not enforce the CABF key requirements on
    # subscriber keys (i.e., in the leaf certificate).
    Feature.pedantic_webpki_subscriber_key,
    # Tests that fail based on a strict reading of RFC 5280
    # but are widely ignored by validators.
    Feature.pedantic_rfc5280,
    # In rare circumstances, CABF relaxes RFC 5280's prescriptions in
    # incompatible ways. Our validator always tries (by default) to comply
    # closer to CABF, so we skip these.
    Feature.rfc5280_incompatible_with_webpki,
    # We do not support policy constraints.
    Feature.has_policy_constraints,
    # We do not support CRLs
    Feature.has_crl,
}

LIMBO_SKIP_TESTCASES = {
    # We unconditionally count intermediate certificates for pathlen and max
    # depth constraint purposes, even when self-issued.
    # This is a violation of RFC 5280, but is consistent with Go's crypto/x509
    # and Rust's webpki crate do.
    "pathlen::self-issued-certs-pathlen",
    "pathlen::max-chain-depth-1-self-issued",
    # We allow certificates with serial numbers of zero. This is
    # invalid under RFC 5280 but is widely violated by certs in common
    # trust stores.
    "rfc5280::serial::zero",
    # We allow CAs that don't have AKIs, which is forbidden under
    # RFC 5280. This is consistent with what Go's crypto/x509 and Rust's
    # webpki crate do.
    "rfc5280::ski::root-missing-ski",
    "rfc5280::ski::intermediate-missing-ski",
    # We currently allow intermediate CAs that don't have AKIs, which
    # is technically forbidden under CABF. This is consistent with what
    # Go's crypto/x509 and Rust's webpki crate do.
    "rfc5280::aki::intermediate-missing-aki",
    # We allow root CAs where the AKI and SKI mismatch, which is technically
    # forbidden under CABF. This is consistent with what
    # Go's crypto/x509 and Rust's webpki crate do.
    "webpki::aki::root-with-aki-ski-mismatch",
    # We allow RSA keys that aren't divisible by 8, which is technically
    # forbidden under CABF. No other implementation checks this either.
    "webpki::forbidden-rsa-not-divisable-by-8-in-root",
    # We disallow CAs in the leaf position, which is explicitly forbidden
    # by CABF (but implicitly permitted under RFC 5280). This is consistent
    # with what webpki and rustls do, but inconsistent with Go and OpenSSL.
    "rfc5280::ca-as-leaf",
    "pathlen::validation-ignores-pathlen-in-leaf",
    # Not fixed upstream yet.
    "pathological::pathological-chain-same-subject-same-key",
}


def _get_limbo_peer(expected_peer: PeerName):
    match expected_peer.kind:
        case PeerKind.DNS:
            return x509.DNSName(expected_peer.value)
        case PeerKind.IP:
            return x509.IPAddress(ipaddress.ip_address(expected_peer.value))
        case _:
            raise ValueError(f"unexpected peer kind: {expected_peer.kind}")


def _skip(tc: Testcase, msg: str) -> TestcaseResult:
    return TestcaseResult(id=tc.id, actual_result=ActualResult.SKIPPED, context=msg)


def evaluate_testcase(testcase: Testcase) -> TestcaseResult:
    print(f"Evaluating: {testcase.id}", file=sys.stderr)

    if testcase.id in LIMBO_SKIP_TESTCASES:
        return _skip(testcase, "testcase skipped (explicitly unsupported case)")

    if LIMBO_UNSUPPORTED_FEATURES.intersection(testcase.features):
        return _skip(testcase, "testcase skipped (explicit unsupported feature)")

    if testcase.validation_kind != ValidationKind.SERVER:
        return _skip(testcase, "non-SERVER cases not supported yet")

    if testcase.signature_algorithms != []:
        return _skip(testcase, "signature algorithm customization not supported yet")

    if testcase.extended_key_usage not in ([], [KnownEKUs.server_auth]):
        return _skip(testcase, "non-serverAuth EKUs not supported yet")

    trusted_certs = [load_pem_x509_certificate(cert.encode()) for cert in testcase.trusted_certs]
    untrusted_intermediates = [
        load_pem_x509_certificate(cert.encode()) for cert in testcase.untrusted_intermediates
    ]

    peer_certificate = load_pem_x509_certificate(testcase.peer_certificate.encode())
    peer_name = _get_limbo_peer(testcase.expected_peer_name)

    builder = PolicyBuilder().store(Store(trusted_certs))
    if validation_time := testcase.validation_time:
        builder = builder.time(validation_time)

    if testcase.max_chain_depth is not None:
        builder = builder.max_chain_depth(testcase.max_chain_depth)

    # This can fail if the peer name is invalid.
    try:
        verifier = builder.build_server_verifier(peer_name)
    except ValueError as e:
        return TestcaseResult(id=testcase.id, actual_result=ActualResult.FAILURE, context=str(e))

    try:
        verifier.verify(peer_certificate, untrusted_intermediates)
        return TestcaseResult(
            id=testcase.id, actual_result=ActualResult.SUCCESS, context="chain built successfully"
        )
    except VerificationError as e:
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
                # The worker died without sending a result (e.g. a crash in the
                # native core). Report it rather than hanging or raising.
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
        LimboResult(
            version=1, harness=f"pyca-cryptography-{pyca_version}", results=results
        ).model_dump_json(indent=2)
    )


if __name__ == "__main__":
    main()

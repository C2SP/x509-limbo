use chrono::{DateTime, Utc};
use limbo_harness_support::load_limbo;
use limbo_harness_support::models::{
    Feature, LimboResult, Testcase, TestcaseResult, ValidationKind,
};
use pki_types::pem::PemObject;
use pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use webpki::{
    anchor_from_trusted_cert, EndEntityCert, ExpirationPolicy, KeyUsage, OwnedCertRevocationList,
    RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy, ALL_VERIFICATION_ALGS,
};

fn main() {
    let limbo = load_limbo();

    let mut results = vec![];
    for testcase in limbo.testcases {
        results.push(evaluate_testcase(&testcase));
    }

    let result = LimboResult {
        version: 1,
        harness: "rustls-webpki".into(),
        results,
    };

    serde_json::to_writer_pretty(std::io::stdout(), &result).unwrap();
}

fn evaluate_testcase(tc: &Testcase) -> TestcaseResult {
    // Check for skipped features first
    if tc.features.contains(&Feature::MaxChainDepth) {
        return TestcaseResult::skip(
            tc,
            "max-chain-depth testcases are not supported by this API",
        );
    }

    if !matches!(tc.validation_kind, ValidationKind::Server) {
        return TestcaseResult::skip(tc, "non-SERVER testcases not supported yet");
    }

    if !tc.signature_algorithms.is_empty() {
        return TestcaseResult::skip(tc, "signature_algorithms not supported yet");
    }

    if !tc.key_usage.is_empty() {
        return TestcaseResult::skip(tc, "key_usage not supported yet");
    }

    match run_validation(tc) {
        Ok(()) => TestcaseResult::success(tc),
        Err(err) => TestcaseResult::fail(tc, &err),
    }
}

/// Run validation and return Ok(()) on success, or an error message on failure
fn run_validation(tc: &Testcase) -> Result<(), String> {
    let trust_anchor_ders = tc
        .trusted_certs
        .iter()
        .map(|ta| cert_der_from_pem(ta))
        .collect::<Vec<_>>();

    let trust_anchors = trust_anchor_ders
        .iter()
        .filter_map(|der| anchor_from_trusted_cert(der).ok())
        .collect::<Vec<_>>();

    if trust_anchors.is_empty() && !trust_anchor_ders.is_empty() {
        return Err("trust anchor extraction failed".into());
    }

    let intermediates = tc
        .untrusted_intermediates
        .iter()
        .map(|ic| cert_der_from_pem(ic))
        .collect::<Vec<_>>();

    let crls = tc
        .crls
        .iter()
        .map(|pem| {
            let der = CertificateRevocationListDer::from_pem_slice(pem.as_bytes())
                .map_err(|e| format!("CRL PEM parse failed: {e}"))?;

            OwnedCertRevocationList::from_der(der.as_ref())
                .map(Into::into)
                .map_err(|e| format!("CRL DER parse failed: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let crls = crls.iter().collect::<Vec<_>>();

    let revocation_options = (!crls.is_empty()).then(|| {
        RevocationOptionsBuilder::new(crls.as_slice())
            .unwrap()
            .with_depth(RevocationCheckDepth::Chain)
            .with_status_policy(UnknownStatusPolicy::Deny)
            .with_expiration_policy(ExpirationPolicy::Enforce)
            .build()
    });

    let leaf_der = cert_der_from_pem(&tc.peer_certificate);
    let leaf =
        EndEntityCert::try_from(&leaf_der).map_err(|e| format!("leaf cert parse failed: {e}"))?;

    let validation_time = UnixTime::since_unix_epoch(
        (tc.validation_time.unwrap_or_else(Utc::now) - DateTime::UNIX_EPOCH)
            .to_std()
            .expect("invalid validation time!"),
    );

    leaf.verify_for_usage(
        ALL_VERIFICATION_ALGS,
        &trust_anchors,
        &intermediates[..],
        validation_time,
        KeyUsage::server_auth(),
        revocation_options,
        None,
    )
    .map_err(|e| e.to_string())?;

    // Verify subject name if expected
    if let Some(peer_name) = tc.expected_peer_name.as_ref() {
        let subject_name = ServerName::try_from(peer_name.value.as_str())
            .map_err(|_| format!("invalid expected peer name: {:?}", peer_name))?;

        leaf.verify_is_valid_for_subject_name(&subject_name)
            .map_err(|_| "subject name validation failed")?;
    }

    Ok(())
}

fn cert_der_from_pem<B: AsRef<[u8]>>(bytes: B) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(bytes.as_ref())
        .expect("cert PEM parse failed")
        .into_owned()
}

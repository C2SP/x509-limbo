use chrono::{DateTime, Utc};
use limbo_harness_support::{
    load_limbo,
    models::{Feature, LimboResult, Testcase, TestcaseResult, ValidationKind},
};
use webpki::ring;

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

fn cert_der_from_pem<B: AsRef<[u8]>>(bytes: B) -> rustls_pki_types::CertificateDer<'static> {
    let pem = pem::parse(bytes).expect("cert: PEM parse failed");
    rustls_pki_types::CertificateDer::from(pem.contents()).into_owned()
}

fn crl_der_from_pem<B: AsRef<[u8]>>(
    bytes: B,
) -> rustls_pki_types::CertificateRevocationListDer<'static> {
    let pem = pem::parse(bytes).expect("crl: PEM parse failed");
    rustls_pki_types::CertificateRevocationListDer::from(pem.into_contents())
}

fn evaluate_testcase(tc: &Testcase) -> TestcaseResult {
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

    let leaf_der = cert_der_from_pem(&tc.peer_certificate);
    let Ok(leaf) = webpki::EndEntityCert::try_from(&leaf_der) else {
        return TestcaseResult::fail(tc, "leaf cert: X.509 parse failed");
    };

    let intermediates = tc
        .untrusted_intermediates
        .iter()
        .map(|ic| cert_der_from_pem(ic))
        .collect::<Vec<_>>();

    let trust_anchor_ders = tc
        .trusted_certs
        .iter()
        .map(|ta| cert_der_from_pem(ta))
        .collect::<Vec<_>>();

    let Ok(trust_anchors) = trust_anchor_ders
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
    else {
        return TestcaseResult::fail(tc, "trusted certs: trust anchor extraction failed");
    };

    let validation_time = rustls_pki_types::UnixTime::since_unix_epoch(
        (tc.validation_time.unwrap_or(Utc::now()) - DateTime::UNIX_EPOCH)
            .to_std()
            .expect("invalid validation time!"),
    );

    let sig_algs = &[
        ring::ECDSA_P256_SHA256,
        ring::ECDSA_P384_SHA384,
        ring::RSA_PKCS1_2048_8192_SHA256,
        ring::RSA_PKCS1_2048_8192_SHA384,
        ring::RSA_PKCS1_2048_8192_SHA512,
        ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ];

    let crls = tc
        .crls
        .iter()
        .map(|pem| {
            webpki::OwnedCertRevocationList::from_der(crl_der_from_pem(pem).as_ref())
                .unwrap_or_else(|e| panic!("crl: tc {} DER parse failed: {e}", tc.id.to_string()))
                .into()
        })
        .collect::<Vec<_>>();
    let crls = crls.iter().collect::<Vec<_>>();

    let revocation_options = if !crls.is_empty() {
        let opts = webpki::RevocationOptionsBuilder::new(crls.as_slice()).unwrap();
        opts.with_depth(webpki::RevocationCheckDepth::Chain);
        opts.with_status_policy(webpki::UnknownStatusPolicy::Deny);
        opts.with_expiration_policy(webpki::ExpirationPolicy::Enforce);
        Some(opts.build())
    } else {
        None
    };

    if let Err(e) = leaf.verify_for_usage(
        sig_algs,
        &trust_anchors,
        &intermediates[..],
        validation_time,
        webpki::KeyUsage::server_auth(),
        revocation_options,
        None,
    ) {
        return TestcaseResult::fail(tc, &e.to_string());
    }

    let Some(peer_name) = tc.expected_peer_name.as_ref() else {
        return TestcaseResult::skip(tc, "implementation requires peer names");
    };

    let subject_name = rustls_pki_types::ServerName::try_from(peer_name.value.as_str())
        .unwrap_or_else(|_| panic!("invalid expected peer name: {peer_name:?}"));

    if leaf
        .verify_is_valid_for_subject_name(&subject_name)
        .is_err()
    {
        TestcaseResult::fail(tc, "subject name validation failed")
    } else {
        TestcaseResult::success(tc)
    }
}

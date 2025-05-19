use std::time::SystemTime;

use chrono::Utc;
use limbo_harness_support::{
    load_limbo,
    models::{Feature, LimboResult, PeerKind, Testcase, TestcaseResult, ValidationKind},
};

fn main() {
    let limbo = load_limbo();

    let mut results = vec![];
    for testcase in limbo.testcases {
        results.push(evaluate_testcase(&testcase));
    }

    let result = LimboResult {
        version: 1,
        harness: "rust-webpki".into(),
        results,
    };

    serde_json::to_writer_pretty(std::io::stdout(), &result).unwrap();
}

fn render_err(e: &webpki::ErrorExt) -> String {
    match e {
        webpki::ErrorExt::Error(e) => e.to_string(),
        webpki::ErrorExt::MaximumPathBuildCallsExceeded => {
            "maximum path build calls exceeded".into()
        }
        webpki::ErrorExt::MaximumSignatureChecksExceeded => {
            "maximum signature checks exceeded".into()
        }
        _ => "unknown error".into(),
    }
}

fn evaluate_testcase(tc: &Testcase) -> TestcaseResult {
    if tc.features.contains(&Feature::MaxChainDepth) {
        return TestcaseResult::skip(
            tc,
            "max-chain-depth testcases are not supported by this API",
        );
    }
    
    if tc.features.contains(&Feature::HasCrl) {
        return TestcaseResult::skip(
            tc,
            "CRLs are not supported by this API",
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

    let leaf_der = pem::parse(&tc.peer_certificate).expect("leaf cert: PEM parse failed");
    let Ok(leaf) = webpki::EndEntityCert::try_from(leaf_der.contents()) else {
        return TestcaseResult::fail(tc, "leaf cert: X.509 parse failed");
    };

    let intermediates = tc
        .untrusted_intermediates
        .iter()
        .map(|ic| pem::parse(ic).unwrap())
        .collect::<Vec<_>>();

    let trust_anchor_ders = tc
        .trusted_certs
        .iter()
        .map(|ta| pem::parse(ta).unwrap())
        .collect::<Vec<_>>();

    let Ok(trust_anchors) = trust_anchor_ders
        .iter()
        .map(|ta| webpki::TrustAnchor::try_from_cert_der(ta.contents()))
        .collect::<Result<Vec<_>, _>>()
    else {
        return TestcaseResult::fail(tc, "trusted certs: trust anchor extraction failed");
    };

    let validation_time = webpki::Time::try_from(SystemTime::from(
        tc.validation_time.unwrap_or(Utc::now().into()),
    ))
    .expect("SystemTime to webpki::Time conversion failed");

    let sig_algs = &[
        &webpki::ECDSA_P256_SHA256,
        &webpki::ECDSA_P384_SHA384,
        &webpki::RSA_PKCS1_2048_8192_SHA256,
        &webpki::RSA_PKCS1_2048_8192_SHA384,
        &webpki::RSA_PKCS1_2048_8192_SHA512,
        &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ];

    if let Err(e) = leaf.verify_is_valid_tls_server_cert_ext(
        sig_algs,
        &webpki::TlsServerTrustAnchors(&trust_anchors),
        &intermediates
            .iter()
            .map(|ic| ic.contents())
            .collect::<Vec<_>>(),
        validation_time,
    ) {
        return TestcaseResult::fail(tc, &render_err(&e));
    }

    let dns_name = match &tc.expected_peer_name {
        None => return TestcaseResult::skip(tc, "implementation requires peer names"),
        Some(pn) => match pn.kind {
            PeerKind::Dns => webpki::DnsNameRef::try_from_ascii_str(&pn.value)
                .expect(&format!("invalid expected DNS name: {}", &pn.value)),
            _ => return TestcaseResult::skip(tc, "implementation requires DNS peer names"),
        },
    };

    if let Err(_) = leaf.verify_is_valid_for_dns_name(dns_name) {
        TestcaseResult::fail(tc, "DNS name validation failed")
    } else {
        TestcaseResult::success(tc)
    }

    // We're not actually initiating a TLS connection, so we don't
    // perform `EndEntityCert.verify_signature`.
}

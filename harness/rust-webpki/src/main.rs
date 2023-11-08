use std::time::SystemTime;

use chrono::{DateTime, Utc};
use models::{Feature, Limbo, PeerKind, Testcase, ValidationKind};
use serde::Serialize;

pub(crate) mod models;

// `cargo run` runs from the workspace root, so these are relative to
// the root.
const LIMBO_JSON: &str = "limbo.json";
const LIMBO_RESULTS_OUT: &str = "./harness/rust-webpki/results.json";

fn main() {
    let limbo =
        serde_json::from_str::<Limbo>(&std::fs::read_to_string(LIMBO_JSON).unwrap()).unwrap();

    let mut results = vec![];
    for testcase in limbo.testcases {
        results.push(evaluate_testcase(&testcase));
    }

    let result = LimboResult {
        version: 1,
        harness: "rust-webpki".into(),
        results,
    };

    std::fs::write(
        LIMBO_RESULTS_OUT,
        serde_json::to_string_pretty(&result).unwrap(),
    )
    .unwrap()
}

#[derive(Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum ActualResult {
    Success,
    Failure,
    Skipped,
}

#[derive(Serialize)]
struct TestcaseResult {
    id: String,
    actual_result: ActualResult,
    context: Option<String>,
}

impl TestcaseResult {
    fn fail(tc: &Testcase, reason: &str) -> Self {
        TestcaseResult {
            id: tc.id.clone(),
            actual_result: ActualResult::Failure,
            context: Some(reason.into()),
        }
    }

    fn success(tc: &Testcase) -> Self {
        TestcaseResult {
            id: tc.id.clone(),
            actual_result: ActualResult::Success,
            context: None,
        }
    }

    fn skip(tc: &Testcase, reason: &str) -> Self {
        TestcaseResult {
            id: tc.id.clone(),
            actual_result: ActualResult::Skipped,
            context: Some(reason.into()),
        }
    }
}

#[derive(Serialize)]
struct LimboResult {
    version: u8,
    harness: String,
    results: Vec<TestcaseResult>,
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
    if tc
        .features
        .as_ref()
        .map_or(false, |features| features.contains(&Feature::MaxChainDepth))
    {
        return TestcaseResult::skip(
            tc,
            "max-chain-depth testcases are not supported by this API",
        );
    }

    if !matches!(tc.validation_kind, ValidationKind::Server) {
        return TestcaseResult::skip(tc, "non-SERVER testcases not supported yet");
    }

    if !matches!(tc.signature_algorithms, None) {
        return TestcaseResult::skip(tc, "signature_algorithms not supported yet");
    }

    if !matches!(tc.key_usage, None) {
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
        tc.validation_time.as_ref().map_or(Utc::now().into(), |s| {
            DateTime::parse_from_rfc3339(&s).expect("RFC 3339 parse failed")
        }),
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
                .expect("invalid expected DNS name"),
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

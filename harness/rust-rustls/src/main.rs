use std::{net::IpAddr, time::SystemTime};

use chrono::{DateTime, Utc};
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
        harness: "rustls-webpki".into(),
        results,
    };

    serde_json::to_writer_pretty(std::io::stdout(), &result).unwrap();
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

    if let Err(e) = leaf.verify_for_usage(
        sig_algs,
        &trust_anchors,
        &intermediates
            .iter()
            .map(|ic| ic.contents())
            .collect::<Vec<_>>(),
        validation_time,
        webpki::KeyUsage::server_auth(),
        &[],
    ) {
        return TestcaseResult::fail(tc, &e.to_string());
    }

    let subject_name = match &tc.expected_peer_name {
        None => return TestcaseResult::skip(tc, "implementation requires peer names"),
        Some(pn) => match pn.kind {
            PeerKind::Dns => webpki::SubjectNameRef::DnsName(
                webpki::DnsNameRef::try_from_ascii_str(&pn.value)
                    .expect(&format!("invalid expected DNS name: {}", &pn.value)),
            ),
            PeerKind::Ip => {
                // Very dumb: rustls-webpki doesn't allow compressed IPv6 string representations,
                // so we need to round-trip through `std::net::IpAddr`. This in turn requires
                // us to round-trip through `webpki::IpAddr` and perform a leak, since
                // we have no outliving reference to borrow against.
                let addr = pn.value.parse::<IpAddr>().unwrap();
                let addr_leaked: &'static webpki::IpAddr = Box::leak(Box::new(addr.into()));

                let addr_ref = webpki::IpAddrRef::from(addr_leaked);

                webpki::SubjectNameRef::IpAddress(addr_ref)
            }
            _ => return TestcaseResult::skip(tc, "implementation requires DNS or IP peer names"),
        },
    };

    if let Err(_) = leaf.verify_is_valid_for_subject_name(subject_name) {
        TestcaseResult::fail(tc, "subject name validation failed")
    } else {
        TestcaseResult::success(tc)
    }
}

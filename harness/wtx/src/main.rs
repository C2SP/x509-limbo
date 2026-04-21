use core::{fmt::Debug, mem, ops::Range, slice};
use limbo_harness_support::{
    load_limbo,
    models::{ExpectedResult, Feature, KeyUsage, KnownEkUs, LimboResult, Testcase, TestcaseResult},
};
use wtx::{
    asn1::{parse_der_from_pem_range, parse_der_from_pem_range_many, Asn1Error},
    calendar::{DateTime, Instant},
    codec::{Decode, DecodeWrapper},
    collection::Vector,
    misc::Pem,
    x509::{
        extensions::ExtendedKeyUsage, Certificate, Crl, CvCertificate, CvCrl, CvEvaluationDepth,
        CvPolicy, CvPolicyMode, CvTrustAnchor, ServerName, X509CvError, X509Error,
    },
};

fn main() {
    let limbo = load_limbo();

    let mut bytes_certs = Vector::new();
    let mut crls = Vector::new();
    let mut pems = Vector::new();
    let mut trusted_certs = Vector::new();
    let mut untrusted_intermediates = Vector::new();
    let mut results = Vector::new();

    for testcase in &limbo.testcases {
        let mut local_crls = crls;
        let mut local_trusted_certs = trusted_certs;
        let mut local_untrusted_intermediates = untrusted_intermediates;
        bytes_certs.clear();
        pems.clear();
        let result = evaluate_test_case(
            &mut bytes_certs,
            &mut local_crls,
            &mut pems,
            testcase,
            &mut local_trusted_certs,
            &mut local_untrusted_intermediates,
        );
        results.push(result).unwrap();
        crls = clear_and_recycle(local_crls);
        trusted_certs = clear_and_recycle(local_trusted_certs);
        untrusted_intermediates = clear_and_recycle(local_untrusted_intermediates);
    }

    let result = LimboResult {
        version: 1,
        harness: "wtx".into(),
        results: results.into_vec(),
    };
    serde_json::to_writer_pretty(std::io::stdout(), &result).unwrap();
}

fn clear_and_recycle<T, U>(mut vector: Vector<T>) -> Vector<U> {
    vector.clear();
    assert!(size_of::<T>() == size_of::<U>());
    assert!(align_of::<T>() == align_of::<U>());
    let cap = vector.capacity();
    let ptr = vector.as_mut_ptr().cast();
    mem::forget(vector);
    // SAFETY: storage comes from the non-dropped vector
    Vector::from_vec(unsafe { Vec::from_raw_parts(ptr, 0, cap) })
}

fn evaluate_test_case<'bytes>(
    bytes_certs: &'bytes mut Vector<u8>,
    crls: &mut Vector<CvCrl<'_, 'bytes>>,
    pems: &mut Vector<Pem<Range<usize>, 1>>,
    testcase: &Testcase,
    trusted_certs: &mut Vector<CvTrustAnchor<'_, 'bytes>>,
    untrusted_intermediates: &mut Vector<CvCertificate<'_, 'bytes, false>>,
) -> TestcaseResult {
    let leaf_pem = {
        let mut dw = DecodeWrapper::new(testcase.peer_certificate.as_bytes(), &mut *bytes_certs);
        Pem::decode(&mut dw).unwrap()
    };

    for elem in &testcase.crls {
        let mut dw = DecodeWrapper::new(elem.as_bytes(), &mut *bytes_certs);
        pems.push(Pem::decode(&mut dw).unwrap()).unwrap();
    }

    let idx0 = pems.len();
    for elem in &testcase.trusted_certs {
        let mut dw = DecodeWrapper::new(elem.as_bytes(), &mut *bytes_certs);
        pems.push(Pem::decode(&mut dw).unwrap()).unwrap();
    }

    let idx1 = pems.len();
    for elem in &testcase.untrusted_intermediates {
        let mut dw = DecodeWrapper::new(elem.as_bytes(), &mut *bytes_certs);
        pems.push(Pem::decode(&mut dw).unwrap()).unwrap();
    }

    let leaf = match eval_eager_checks(
        parse_der_from_pem_range::<Certificate<'_>>(&*bytes_certs, &leaf_pem)
            .and_then(CvCertificate::<'_, '_>::try_from),
        testcase,
    ) {
        Err(Some(err)) => return TestcaseResult::fail(testcase, &err.to_string()),
        Err(None) => return TestcaseResult::success(testcase),
        Ok(elem) => elem,
    };

    match eval_eager_checks(
        parse_der_from_pem_range_many(&*bytes_certs, crls, &pems[..idx0], |el: Crl<'_>| {
            el.try_into()
        }),
        testcase,
    ) {
        Err(Some(err)) => return TestcaseResult::fail(testcase, &err.to_string()),
        Err(None) => return TestcaseResult::success(testcase),
        Ok(elem) => elem,
    };

    match eval_eager_checks(
        parse_der_from_pem_range_many(
            &*bytes_certs,
            trusted_certs,
            &pems[idx0..idx1],
            |el: Certificate<'_>| el.try_into(),
        ),
        testcase,
    ) {
        Err(Some(err)) => return TestcaseResult::fail(testcase, &err.to_string()),
        Err(None) => return TestcaseResult::success(testcase),
        Ok(elem) => elem,
    };

    match eval_eager_checks(
        parse_der_from_pem_range_many(
            &*bytes_certs,
            untrusted_intermediates,
            &pems[idx1..],
            |el: Certificate<'_>| el.try_into(),
        ),
        testcase,
    ) {
        Err(Some(err)) => return TestcaseResult::fail(testcase, &err.to_string()),
        Err(None) => return TestcaseResult::success(testcase),
        Ok(elem) => elem,
    };

    let mut cvp = CvPolicy::from_crls(crls).unwrap();
    let mut eku = ExtendedKeyUsage::default();
    fill_cvp(&mut cvp, &mut eku, testcase);

    let rslt_chain = leaf.validate_chain(untrusted_intermediates, &cvp, trusted_certs);
    let peer_names = if let Some(peer_name) = testcase.expected_peer_name.as_ref() {
        slice::from_ref(peer_name)
    } else if !testcase.expected_peer_names.is_empty() {
        testcase.expected_peer_names.as_slice()
    } else {
        &[]
    };
    let rslt_sn = leaf.validate_subject_name(
        peer_names
            .iter()
            .map(|el| ServerName::from_ascii(el.value.as_bytes()).unwrap()),
    );

    let rslt = rslt_chain.and(rslt_sn);
    match testcase.expected_result {
        ExpectedResult::Success => {
            if let Err(err) = rslt {
                return TestcaseResult::fail(testcase, &err.to_string());
            }
        }
        ExpectedResult::Failure => {
            if rslt.is_ok() {
                return TestcaseResult::fail(testcase, "Test should fail but is actually passing");
            }
        }
    }

    TestcaseResult::success(testcase)
}

// These errors are thrown when the certificates are instantiated.
fn eval_eager_checks<T>(rslt: wtx::Result<T>, testcase: &Testcase) -> Result<T, Option<wtx::Error>>
where
    T: Debug,
{
    match rslt {
        Ok(elem) => Ok(elem),
        Err(wtx::Error::Asn1Error(Asn1Error::LargeData))
        | Err(wtx::Error::X509Error(X509Error::InvalidCertificateVersion))
        | Err(wtx::Error::X509Error(X509Error::InvalidExtendedKeyUsage))
        | Err(wtx::Error::X509Error(X509Error::InvalidExtensionKeyUsage))
        | Err(wtx::Error::X509Error(X509Error::InvalidExtensionNameConstraints))
        | Err(wtx::Error::X509Error(X509Error::InvalidSan))
        | Err(wtx::Error::X509Error(X509Error::InvalidSerialNumberBytes))
        | Err(wtx::Error::X509CvError(X509CvError::AuthorityKeyIdentifierMustNotBeCritical))
        | Err(wtx::Error::X509CvError(X509CvError::CertCanNotHaveDuplicateExtensions))
        | Err(wtx::Error::X509CvError(X509CvError::CertificateAlgorithmMismatch))
        | Err(wtx::Error::X509CvError(X509CvError::CertsMustNotHaveCriticalUnknownExtensions))
        | Err(wtx::Error::X509CvError(X509CvError::HasIncompatibleKeyUsage))
        | Err(wtx::Error::X509CvError(X509CvError::InvalidNameConstraints))
        | Err(wtx::Error::X509CvError(X509CvError::CrlNumberMustNotBeCritical))
        | Err(wtx::Error::X509CvError(X509CvError::IcasMustHaveASubjectSequence))
        | Err(wtx::Error::X509CvError(X509CvError::IcasMustHaveCriticalBasicConstraints))
        | Err(wtx::Error::X509CvError(X509CvError::IcasMustHaveSki))
        | Err(wtx::Error::X509CvError(X509CvError::InvalidAuthorityKeyIdentifier))
        | Err(wtx::Error::X509CvError(X509CvError::MissingCrlNumber))
        | Err(wtx::Error::X509CvError(X509CvError::NameConstraintsMustBeCritical))
        | Err(wtx::Error::X509CvError(X509CvError::NameConstraintsOverflow))
        | Err(wtx::Error::X509CvError(X509CvError::PolicyConstraintMustBeCritical))
        | Err(wtx::Error::X509CvError(X509CvError::RootCasMustHaveKeyIdentifiers))
        | Err(wtx::Error::X509CvError(X509CvError::RootCasMustHaveMatchingAkiAndSki))
        | Err(wtx::Error::X509CvError(X509CvError::SubjectKeyIdentifierMustNotBeCritical)) => {
            match testcase.expected_result {
                ExpectedResult::Success => Err(Some(rslt.unwrap_err())),
                ExpectedResult::Failure => Err(None),
            }
        }
        Err(err) => Err(Some(err)),
    }
}

fn fill_cvp<'any>(
    cvp: &mut CvPolicy<'any, '_>,
    eku: &'any mut ExtendedKeyUsage,
    testcase: &Testcase,
) {
    for elem in &testcase.extended_key_usage {
        match elem {
            KnownEkUs::AnyExtendedKeyUsage => {
                *eku.any_mut() = true;
            }
            KnownEkUs::ServerAuth => {
                *eku.server_auth_mut() = true;
            }
            KnownEkUs::ClientAuth => {
                *eku.client_auth_mut() = true;
            }
            KnownEkUs::CodeSigning => {
                *eku.code_signing_mut() = true;
            }
            KnownEkUs::EmailProtection => {
                *eku.email_protection_mut() = true;
            }
            KnownEkUs::TimeStamping => {
                *eku.time_stamping_mut() = true;
            }
            KnownEkUs::OcspSigning => {
                *eku.ocsp_signing_mut() = true;
            }
        }
    }

    let mut ku: wtx::x509::extensions::KeyUsage = wtx::x509::extensions::KeyUsage::default();
    for elem in &testcase.key_usage {
        match elem {
            KeyUsage::DigitalSignature => {
                ku.set_digital_signature(true);
            }
            KeyUsage::ContentCommitment => {
                ku.set_non_repudiation(true);
            }
            KeyUsage::KeyEncipherment => {
                ku.set_key_encipherment(true);
            }
            KeyUsage::DataEncipherment => {
                ku.set_data_encipherment(true);
            }
            KeyUsage::KeyAgreement => {
                ku.set_key_agreement(true);
            }
            KeyUsage::KeyCertSign => {
                ku.set_key_cert_sign(true);
            }
            KeyUsage::CRlSign => {
                ku.set_crl_sign(true);
            }
            KeyUsage::EncipherOnly => {
                ku.set_encipher_only(true);
            }
            KeyUsage::DecipherOnly => {
                ku.set_decipher_only(true);
            }
        }
    }

    let mut is_pedantic = false;
    for elem in &testcase.features {
        is_pedantic = matches!(
            elem,
            Feature::PedanticPublicSuffixWildcard
                | Feature::PedanticWebpkiSubscriberKey
                | Feature::PedanticWebpkiEku
                | Feature::PedanticSerialNumber
                | Feature::PedanticRfc5280
        );
        if is_pedantic {
            break;
        }
    }

    *cvp.mode_mut() = if is_pedantic {
        CvPolicyMode::Strict
    } else {
        // The vast majority don't have AKI, even some `webpki` tests don't have AKI.
        if [
            "webpki::aki::root-with-aki-missing-keyidentifier",
            "webpki::aki::root-with-aki-ski-mismatch",
        ]
        .contains(&testcase.id.as_str())
        {
            CvPolicyMode::Strict
        } else {
            CvPolicyMode::Lenient
        }
    };

    if let Some(elem) = testcase.max_chain_depth {
        *cvp.evaluation_depth_mut() = CvEvaluationDepth::Chain(elem.try_into().unwrap());
    }

    *cvp.key_usage_mut() = ku;
    *cvp.extended_key_usage_mut() = eku;
    let validation_time = if let Some(elem) = testcase.validation_time {
        DateTime::from_timestamp_secs(elem.timestamp()).unwrap()
    } else {
        Instant::now_date_time(0).unwrap()
    };
    cvp.set_validation_time(validation_time);
}

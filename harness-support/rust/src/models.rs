use serde::{Deserialize, Serialize};
use typify::import_types;

import_types!(schema = "../../limbo-schema.json");

#[derive(Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ActualResult {
    Success,
    Failure,
    Skipped,
}

#[derive(Serialize)]
pub struct TestcaseResult {
    pub id: String,
    pub actual_result: ActualResult,
    pub context: Option<String>,
}

impl TestcaseResult {
    pub fn fail(tc: &Testcase, reason: &str) -> Self {
        TestcaseResult {
            id: tc.id.to_string(),
            actual_result: ActualResult::Failure,
            context: Some(reason.into()),
        }
    }

    pub fn success(tc: &Testcase) -> Self {
        TestcaseResult {
            id: tc.id.to_string(),
            actual_result: ActualResult::Success,
            context: None,
        }
    }

    pub fn skip(tc: &Testcase, reason: &str) -> Self {
        TestcaseResult {
            id: tc.id.to_string(),
            actual_result: ActualResult::Skipped,
            context: Some(reason.into()),
        }
    }
}

#[derive(Serialize)]
pub struct LimboResult {
    pub version: u8,
    pub harness: String,
    pub results: Vec<TestcaseResult>,
}

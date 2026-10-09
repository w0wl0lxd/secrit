//! The rows of a `doctor` run. `cmd::doctor` prints them, and each backend
//! adds its own, so neither module depends on the other for these types.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Status {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Info => "info",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub check: String,
    pub status: Status,
    pub detail: String,
}

/// The rows of one `doctor` run, in order.
#[derive(Debug, Default)]
pub struct Report(Vec<Row>);

impl Report {
    pub fn add(&mut self, check: impl Into<String>, status: Status, detail: impl Into<String>) {
        self.0.push(Row {
            check: check.into(),
            status,
            detail: detail.into(),
        });
    }

    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.0
    }
}

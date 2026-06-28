//! Decision logging — structured, timestamped log of every policy evaluation.
//!
//! Logs to `<data_dir>/prodagent/decisions.log` using JSON-lines format.
//! Failures are silently ignored (logging must never block the hook).

use std::fs::{self, OpenOptions};
use std::io::Write;

use camino::Utf8PathBuf;
use prodagent_policy::PolicyDecision;
use serde::Serialize;
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;

/// A single decision log entry.
#[derive(Serialize)]
struct LogEntry<'a> {
    timestamp: String,
    tool_name: &'a str,
    command: &'a str,
    decision: PolicyDecision,
    reason: &'a str,
}

/// Log a policy decision to the decisions log file.
///
/// Best-effort — errors are silently swallowed. The hook must never fail
/// because logging failed.
pub fn log_decision(tool_name: &str, command: &str, decision: PolicyDecision, reason: &str) {
    let _ = try_log(tool_name, command, decision, reason);
}

fn try_log(tool_name: &str, command: &str, decision: PolicyDecision, reason: &str) -> Option<()> {
    let log_path = log_file_path()?;

    // Ensure parent directory exists
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).ok()?;
    }

    let entry = LogEntry {
        timestamp: iso8601_now(),
        tool_name,
        command,
        decision,
        reason,
    };

    let mut line = serde_json::to_string(&entry).ok()?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path.as_std_path())
        .ok()?;

    file.write_all(line.as_bytes()).ok()
}

/// Resolve the log file path: `<data_dir>/prodagent/decisions.log`.
fn log_file_path() -> Option<Utf8PathBuf> {
    let data_dir = dirs::data_dir()?;
    let data_dir = Utf8PathBuf::try_from(data_dir).ok()?;
    Some(data_dir.join("prodagent").join("decisions.log"))
}

/// Format the current time as ISO 8601 (UTC).
fn iso8601_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_format_is_valid() {
        let ts = iso8601_now();
        // Should start with a 4-digit year and contain 'T'
        assert!(ts.len() >= 20, "timestamp too short: {ts}");
        assert!(ts.contains('T'), "missing T separator: {ts}");
    }

    #[test]
    fn log_file_path_uses_data_dir() {
        // Just ensure it doesn't panic — the actual path varies by platform
        let path = log_file_path();
        if let Some(p) = path {
            assert!(p.as_str().contains("prodagent"));
            assert!(p.as_str().ends_with("decisions.log"));
        }
    }
}

//! Decision logging — structured, timestamped log of every policy evaluation.
//!
//! Logs to `<data_dir>/prodagent/decisions.log` using JSON-lines format.
//! Failures are silently ignored (logging must never block the hook).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::SystemTime;

use agent_policy::PolicyDecision;
use camino::Utf8PathBuf;
use serde::Serialize;

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
    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Manual UTC decomposition — avoids pulling in chrono/time for a single format call.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from days since epoch (algorithm from Howard Hinnant)
    let (year, month, day) = civil_from_days(days as i64);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
///
/// Algorithm by Howard Hinnant, public domain.
/// <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_epoch() {
        // Sanity: the algorithm should produce 1970-01-01 for epoch
        let (y, m, d) = civil_from_days(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn iso8601_known_date() {
        // 2024-01-01 00:00:00 UTC = 19723 days since epoch
        let (y, m, d) = civil_from_days(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
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

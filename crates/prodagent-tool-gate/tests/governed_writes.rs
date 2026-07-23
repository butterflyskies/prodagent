use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn run_hook(root: &std::path::Path, command: &str) -> Value {
    let config_home = root.join("config");
    let data_home = root.join("data");
    let incidents = root.join("incidents");
    fs::create_dir_all(config_home.join("prodagent")).unwrap();
    fs::create_dir_all(&incidents).unwrap();
    fs::write(
        config_home.join("prodagent/config.toml"),
        format!(
            r#"
[[governed_writes]]
directory = "{}"
guide = "Use incident-submit and include an owner."
template = "https://example.test/incident-template"

[policy.commands]
incident-submit = "allow"
"#,
            incidents.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_prodagent-tool-gate"))
        .current_dir(root)
        .env("XDG_CONFIG_HOME", config_home)
        .env("XDG_DATA_HOME", data_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(
        child.stdin.as_mut().unwrap(),
        &json!({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": root.to_str().unwrap(),
        }),
    )
    .unwrap();
    child.stdin.take().unwrap().flush().unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn governed_append_is_refused_without_file_change_and_corrected_retry_is_allowed() {
    let root = tempfile::tempdir().unwrap();
    let report = root.path().join("incidents/report.md");
    fs::create_dir_all(report.parent().unwrap()).unwrap();
    fs::write(&report, "original\n").unwrap();

    let denied = run_hook(root.path(), "cd incidents && echo attempted >> report.md");
    let output = &denied["hookSpecificOutput"];
    assert_eq!(output["permissionDecision"], "deny");
    let reason = output["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("Use incident-submit and include an owner."));
    assert!(reason.contains("https://example.test/incident-template"));
    assert!(reason.contains("retry with a corrected command"));
    assert_eq!(fs::read_to_string(&report).unwrap(), "original\n");

    let corrected = run_hook(
        root.path(),
        "incident-submit incidents/report.md --owner platform",
    );
    let corrected_output = &corrected["hookSpecificOutput"];
    assert_eq!(corrected_output["permissionDecision"], "allow");
    assert!(!corrected_output["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("Contribution guidance"));
}

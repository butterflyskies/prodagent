use super::*;
use agent_shell_parser::parse::Word;

// --- resolve_path ---

#[test]
fn resolve_absolute() {
    assert_eq!(resolve_path("/abs/path", "/base"), "/abs/path");
}

#[test]
fn resolve_relative() {
    assert_eq!(resolve_path("subdir", "/base"), "/base/subdir");
}

#[test]
fn resolve_tilde_alone() {
    let home = std::env::var("HOME").unwrap_or_default();
    assert_eq!(resolve_path("~", "/base"), home);
}

#[test]
fn resolve_tilde_subdir() {
    let home = std::env::var("HOME").unwrap_or_default();
    let result = resolve_path("~/docs", "/base");
    assert_eq!(result, format!("{home}/docs"));
}

// --- extract_cd_target ---

#[test]
fn cd_target_normal() {
    let words: Vec<Word> = ["cd", "/foo"].iter().map(|s| Word::from(*s)).collect();
    assert_eq!(extract_cd_target(&words), Some(&Word::from("/foo")));
}

#[test]
fn cd_target_with_flags() {
    let words: Vec<Word> = ["cd", "-L", "/foo"]
        .iter()
        .map(|s| Word::from(*s))
        .collect();
    assert_eq!(extract_cd_target(&words), Some(&Word::from("/foo")));
}

#[test]
fn cd_target_no_args() {
    let words: Vec<Word> = ["cd"].iter().map(|s| Word::from(*s)).collect();
    assert_eq!(extract_cd_target(&words), None);
}

// --- extract_git_c_path ---

#[test]
fn git_c_path_present() {
    let words: Vec<Word> = ["git", "-C", "/repo", "status"]
        .iter()
        .map(|s| Word::from(*s))
        .collect();
    assert_eq!(extract_git_c_path(&words), Some(&Word::from("/repo")));
}

#[test]
fn git_c_path_absent() {
    let words: Vec<Word> = ["git", "status"].iter().map(|s| Word::from(*s)).collect();
    assert_eq!(extract_git_c_path(&words), None);
}

#[test]
fn git_c_path_multiple_flags() {
    let words: Vec<Word> = ["git", "--no-pager", "-C", "/repo", "log"]
        .iter()
        .map(|s| Word::from(*s))
        .collect();
    assert_eq!(extract_git_c_path(&words), Some(&Word::from("/repo")));
}

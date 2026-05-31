use agent_shell_parser::parse::types::Word;

use crate::lookup::classify;
use crate::types::*;

fn words(args: &[&str]) -> Vec<Word> {
    args.iter().map(|s| Word::from(*s)).collect()
}

fn git_knowledge() -> KnowledgeBase {
    let mut kb = KnowledgeBase::default();

    let mut git_subs = SubcommandMap::new();
    for cmd in &["status", "log", "diff", "show", "branch", "blame"] {
        git_subs.insert(*cmd, SubcommandEntry::with_effect(Effect::ReadOnly));
    }
    for cmd in &["push", "commit", "add", "pull", "fetch", "rebase"] {
        git_subs.insert(*cmd, SubcommandEntry::with_effect(Effect::Mutating));
    }

    kb.commands.insert(
        "git".to_string(),
        CommandKnowledge {
            name: "git".to_string(),
            effect: Effect::Unknown,
            subcommands: git_subs,
            flags: FlagSchema {
                skip_arg: vec!["-C".into(), "-c".into(), "--git-dir".into()],
                skip_solo: vec!["--bare".into(), "--no-pager".into()],
                escalation: vec!["--force".into(), "-f".into(), "--force-with-lease".into()],
                path: vec!["-C".into()],
            },
            env_gates: vec![],
            paths: PathSpec::default(),
            properties: CommandProperties {
                version_flag: Some("--version".into()),
            },
        },
    );
    kb
}

fn gh_knowledge() -> KnowledgeBase {
    let mut kb = KnowledgeBase::default();

    let mut gh_subs = SubcommandMap::new();
    for pattern in &["pr list", "pr view", "pr diff", "issue list", "issue view"] {
        gh_subs.insert(*pattern, SubcommandEntry::with_effect(Effect::ReadOnly));
    }
    for pattern in &["pr create", "pr merge", "issue create", "issue close"] {
        gh_subs.insert(*pattern, SubcommandEntry::with_effect(Effect::Mutating));
    }
    for pattern in &["repo delete"] {
        gh_subs.insert(*pattern, SubcommandEntry::with_effect(Effect::Destructive));
    }

    let mut gh = CommandKnowledge::simple("gh", Effect::Unknown);
    gh.subcommands = gh_subs;
    kb.commands.insert("gh".to_string(), gh);
    kb
}

fn rm_knowledge() -> KnowledgeBase {
    let mut kb = KnowledgeBase::default();
    let mut rm = CommandKnowledge::simple("rm", Effect::Destructive);
    rm.paths = PathSpec {
        positionals: PathPositionals::All,
        flags: vec![],
    };
    kb.commands.insert("rm".to_string(), rm);
    kb
}

// --- git tests ---

#[test]
fn git_status_is_read_only() {
    let kb = git_knowledge();
    let info = classify(&Word::from("git"), &words(&["git", "status"]), &kb);
    assert_eq!(info.effect, Effect::ReadOnly);
    assert_eq!(info.subcommand.as_deref(), Some("status"));
}

#[test]
fn git_push_is_mutating() {
    let kb = git_knowledge();
    let info = classify(
        &Word::from("git"),
        &words(&["git", "push", "origin", "main"]),
        &kb,
    );
    assert_eq!(info.effect, Effect::Mutating);
    assert_eq!(info.subcommand.as_deref(), Some("push"));
}

#[test]
fn git_push_force_has_escalation() {
    let kb = git_knowledge();
    let info = classify(&Word::from("git"), &words(&["git", "push", "--force"]), &kb);
    assert_eq!(info.effect, Effect::Mutating);
    assert!(info.has_escalation_flags);
}

#[test]
fn git_push_force_short_flag() {
    let kb = git_knowledge();
    let info = classify(&Word::from("git"), &words(&["git", "push", "-f"]), &kb);
    assert!(info.has_escalation_flags);
}

#[test]
fn git_unknown_subcommand_inherits_parent() {
    let kb = git_knowledge();
    let info = classify(&Word::from("git"), &words(&["git", "frobnicate"]), &kb);
    assert_eq!(info.effect, Effect::Unknown);
    assert!(info.subcommand.is_none());
}

#[test]
fn git_global_flag_skipping() {
    let kb = git_knowledge();
    let info = classify(
        &Word::from("git"),
        &words(&["git", "--no-pager", "log"]),
        &kb,
    );
    assert_eq!(info.effect, Effect::ReadOnly);
    assert_eq!(info.subcommand.as_deref(), Some("log"));
}

#[test]
fn git_c_flag_skipping_with_value() {
    let kb = git_knowledge();
    let info = classify(
        &Word::from("git"),
        &words(&["git", "-C", "/tmp", "status"]),
        &kb,
    );
    assert_eq!(info.effect, Effect::ReadOnly);
    assert_eq!(info.subcommand.as_deref(), Some("status"));
}

#[test]
fn git_c_flag_extracts_path() {
    let kb = git_knowledge();
    let info = classify(
        &Word::from("git"),
        &words(&["git", "-C", "/tmp/repo", "push"]),
        &kb,
    );
    assert!(info.affected_paths.contains(&Word::from("/tmp/repo")));
}

// --- gh tests ---

#[test]
fn gh_pr_list_is_read_only() {
    let kb = gh_knowledge();
    let info = classify(&Word::from("gh"), &words(&["gh", "pr", "list"]), &kb);
    assert_eq!(info.effect, Effect::ReadOnly);
    assert_eq!(info.subcommand.as_deref(), Some("pr list"));
}

#[test]
fn gh_pr_create_is_mutating() {
    let kb = gh_knowledge();
    let info = classify(
        &Word::from("gh"),
        &words(&["gh", "pr", "create", "--draft"]),
        &kb,
    );
    assert_eq!(info.effect, Effect::Mutating);
    assert_eq!(info.subcommand.as_deref(), Some("pr create"));
}

#[test]
fn gh_repo_delete_is_destructive() {
    let kb = gh_knowledge();
    let info = classify(
        &Word::from("gh"),
        &words(&["gh", "repo", "delete", "myrepo"]),
        &kb,
    );
    assert_eq!(info.effect, Effect::Destructive);
    assert_eq!(info.subcommand.as_deref(), Some("repo delete"));
}

#[test]
fn gh_unknown_subcommand() {
    let kb = gh_knowledge();
    let info = classify(&Word::from("gh"), &words(&["gh", "unknown"]), &kb);
    assert_eq!(info.effect, Effect::Unknown);
}

// --- rm tests (path extraction) ---

#[test]
fn rm_extracts_all_paths() {
    let kb = rm_knowledge();
    let info = classify(&Word::from("rm"), &words(&["rm", "-rf", "foo", "bar"]), &kb);
    assert_eq!(info.effect, Effect::Destructive);
    assert!(info.affected_paths.contains(&Word::from("foo")));
    assert!(info.affected_paths.contains(&Word::from("bar")));
}

// --- unknown command ---

#[test]
fn unknown_command_returns_unknown() {
    let kb = KnowledgeBase::default();
    let info = classify(
        &Word::from("frobnicate"),
        &words(&["frobnicate", "arg"]),
        &kb,
    );
    assert_eq!(info.effect, Effect::Unknown);
    assert!(info.subcommand.is_none());
}

// --- wrapper ---

#[test]
fn wrapper_returns_wrapper_info() {
    let mut kb = KnowledgeBase::default();
    kb.wrappers.insert(
        "sudo".to_string(),
        WrapperKnowledge {
            name: "sudo".to_string(),
            floor_effect: Effect::Mutating,
            clears_env: false,
            escalates_privilege: true,
        },
    );

    let info = classify(
        &Word::from("sudo"),
        &words(&["sudo", "rm", "-rf", "/"]),
        &kb,
    );
    let wrapper = info.wrapper.unwrap();
    assert_eq!(wrapper.name, "sudo");
    assert_eq!(wrapper.floor_effect, Effect::Mutating);
    assert!(!wrapper.clears_env);
    assert!(wrapper.escalates_privilege);
}

// --- env gates ---

#[test]
fn env_gates_from_command() {
    let mut kb = KnowledgeBase::default();
    let mut git = CommandKnowledge::simple("git", Effect::Unknown);
    git.env_gates = vec![EnvGate::Grant {
        var: "GIT_CONFIG_GLOBAL".into(),
        value: "~/.gitconfig.ai".into(),
        unlocks: Effect::ReadOnly,
    }];
    kb.commands.insert("git".to_string(), git);

    let info = classify(&Word::from("git"), &words(&["git", "push"]), &kb);
    assert_eq!(info.env_gates.len(), 1);
}

// --- P1 fix: subcommand words excluded from path positionals ---

#[test]
fn git_add_paths_exclude_subcommand_word() {
    let mut kb = git_knowledge();
    let git = kb.commands.get_mut("git").unwrap();
    let mut add_entry = SubcommandEntry::with_effect(Effect::Mutating);
    add_entry.paths = PathSpec {
        positionals: PathPositionals::All,
        flags: vec![],
    };
    git.subcommands.insert("add", add_entry);

    let info = classify(
        &Word::from("git"),
        &words(&["git", "add", "src/main.rs", "README.md"]),
        &kb,
    );
    assert_eq!(info.effect, Effect::Mutating);
    assert!(info.affected_paths.contains(&Word::from("src/main.rs")));
    assert!(info.affected_paths.contains(&Word::from("README.md")));
    assert!(
        !info.affected_paths.contains(&Word::from("add")),
        "subcommand 'add' should not be in affected paths"
    );
}

// --- P2 fix: escalation flags with =value ---

#[test]
fn git_force_with_lease_equals_value() {
    let kb = git_knowledge();
    let info = classify(
        &Word::from("git"),
        &words(&["git", "push", "--force-with-lease=main"]),
        &kb,
    );
    assert!(info.has_escalation_flags);
}

// --- nested subcommands ---

#[test]
fn nested_subcommand_resolution() {
    let mut kb = KnowledgeBase::default();

    let mut push_subs = SubcommandMap::new();
    push_subs.insert("push", SubcommandEntry::with_effect(Effect::Mutating));

    let mut git_entry = SubcommandEntry::with_effect(Effect::Unknown);
    git_entry.subcommands = push_subs;

    let mut git_subs = SubcommandMap::new();
    git_subs.insert("git", git_entry);

    let mut jj = CommandKnowledge::simple("jj", Effect::Unknown);
    jj.subcommands = git_subs;
    kb.commands.insert("jj".to_string(), jj);

    let info = classify(&Word::from("jj"), &words(&["jj", "git", "push"]), &kb);
    assert_eq!(info.effect, Effect::Mutating);
    assert_eq!(info.subcommand.as_deref(), Some("git push"));
}

// --- PathPositionals::Tail ---

#[test]
fn chmod_tail_skips_mode() {
    let mut kb = KnowledgeBase::default();
    let mut chmod = CommandKnowledge::simple("chmod", Effect::Mutating);
    chmod.paths = PathSpec {
        positionals: PathPositionals::Tail(1),
        flags: vec![],
    };
    kb.commands.insert("chmod".to_string(), chmod);

    let info = classify(
        &Word::from("chmod"),
        &words(&["chmod", "755", "script.sh", "other.sh"]),
        &kb,
    );
    assert!(info.affected_paths.contains(&Word::from("script.sh")));
    assert!(info.affected_paths.contains(&Word::from("other.sh")));
    assert!(!info.affected_paths.contains(&Word::from("755")));
}

// --- PathPositionals::Last ---

#[test]
fn cp_last_gets_destination() {
    let mut kb = KnowledgeBase::default();
    let mut cp = CommandKnowledge::simple("cp", Effect::Mutating);
    cp.paths = PathSpec {
        positionals: PathPositionals::Last,
        flags: vec![],
    };
    kb.commands.insert("cp".to_string(), cp);

    let info = classify(
        &Word::from("cp"),
        &words(&["cp", "source.txt", "dest.txt"]),
        &kb,
    );
    assert_eq!(info.affected_paths, vec![Word::from("dest.txt")]);
}

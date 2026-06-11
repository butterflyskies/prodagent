use super::*;
use crate::lookup::classify;
use crate::types::{Effect, KnowledgeBase};
use prodagent_types::Word;

fn words(args: &[&str]) -> Vec<Word> {
    args.iter().map(|s| Word::from(*s)).collect()
}

// ── TOML parses ───────────────────────────────────────────────────────────

#[test]
fn embedded_toml_parses_successfully() {
    let kb = default_knowledge_base();
    assert!(
        !kb.commands.is_empty(),
        "knowledge base should have commands"
    );
    assert!(
        !kb.wrappers.is_empty(),
        "knowledge base should have wrappers"
    );
}

// ── round-trip serde ──────────────────────────────────────────────────────

#[test]
fn knowledge_base_round_trips_through_toml() {
    let kb = default_knowledge_base();
    let serialized = toml::to_string(kb).expect("KB should serialize to TOML");
    let _: KnowledgeBase = toml::from_str(&serialized).expect("re-parsed KB should deserialize");
}

// ── COMMAND_EFFECTS: base command effect table ────────────────────────────

#[test]
fn command_effects() {
    #[rustfmt::skip]
    let cases: &[(&str, Effect)] = &[
        // read-only
        ("ls",        Effect::ReadOnly),
        ("tree",      Effect::ReadOnly),
        ("cat",       Effect::ReadOnly),
        ("head",      Effect::ReadOnly),
        ("tail",      Effect::ReadOnly),
        ("grep",      Effect::ReadOnly),
        ("find",      Effect::ReadOnly),
        ("stat",      Effect::ReadOnly),
        ("diff",      Effect::ReadOnly),
        ("wc",        Effect::ReadOnly),
        ("sort",      Effect::ReadOnly),
        ("uniq",      Effect::ReadOnly),
        ("echo",      Effect::ReadOnly),
        ("printf",    Effect::ReadOnly),
        ("date",      Effect::ReadOnly),
        ("pwd",       Effect::ReadOnly),
        ("which",     Effect::ReadOnly),
        ("ps",        Effect::ReadOnly),
        ("uname",     Effect::ReadOnly),
        ("hostname",  Effect::ReadOnly),
        ("id",        Effect::ReadOnly),
        ("whoami",    Effect::ReadOnly),
        ("df",        Effect::ReadOnly),
        ("du",        Effect::ReadOnly),
        ("free",      Effect::ReadOnly),
        ("uptime",    Effect::ReadOnly),
        ("printenv",  Effect::ReadOnly),
        ("rg",        Effect::ReadOnly),
        ("fd",        Effect::ReadOnly),
        ("bat",       Effect::ReadOnly),
        ("eza",       Effect::ReadOnly),
        ("tokei",     Effect::ReadOnly),
        ("hyperfine", Effect::ReadOnly),
        ("jq",        Effect::ReadOnly),
        // mutating
        ("mkdir",  Effect::Mutating),
        ("touch",  Effect::Mutating),
        ("mv",     Effect::Mutating),
        ("cp",     Effect::Mutating),
        ("ln",     Effect::Mutating),
        ("chmod",  Effect::Mutating),
        ("chown",  Effect::Mutating),
        ("tee",    Effect::Mutating),
        ("curl",   Effect::Mutating),
        ("wget",   Effect::Mutating),
        // mutating (formerly destructive)
        ("rm",       Effect::Mutating),
        ("rmdir",    Effect::Mutating),
        ("shred",    Effect::Mutating),
        ("dd",       Effect::Mutating),
        ("mkfs",     Effect::Mutating),
        ("fdisk",    Effect::Mutating),
        ("parted",   Effect::Mutating),
        ("shutdown", Effect::Mutating),
        ("reboot",   Effect::Mutating),
        ("halt",     Effect::Mutating),
        ("poweroff", Effect::Mutating),
        // unknown (subcommand-dispatch commands)
        ("git",     Effect::Unknown),
        ("cargo",   Effect::Unknown),
        ("gh",      Effect::Unknown),
        ("kubectl", Effect::Unknown),
    ];

    let kb = default_knowledge_base();
    for (cmd, expected) in cases {
        let entry = kb
            .commands
            .get(*cmd)
            .unwrap_or_else(|| panic!("'{cmd}' should be in the KB"));
        assert_eq!(
            entry.effect, *expected,
            "'{cmd}' effect: expected {expected:?}, got {:?}",
            entry.effect
        );
    }
}

// ── SUBCOMMAND_EFFECTS: (command, subcommand, expected_effect) ────────────

#[test]
fn subcommand_effects() {
    #[rustfmt::skip]
    let cases: &[(&str, &str, Effect)] = &[
        // ── git read-only ──────────────────────────────────────────────
        ("git", "status",       Effect::ReadOnly),
        ("git", "log",          Effect::ReadOnly),
        ("git", "diff",         Effect::ReadOnly),
        ("git", "show",         Effect::ReadOnly),
        ("git", "branch",       Effect::ReadOnly),
        ("git", "tag",          Effect::ReadOnly),
        ("git", "remote",       Effect::ReadOnly),
        ("git", "rev-parse",    Effect::ReadOnly),
        ("git", "ls-files",     Effect::ReadOnly),
        ("git", "ls-tree",      Effect::ReadOnly),
        ("git", "shortlog",     Effect::ReadOnly),
        ("git", "blame",        Effect::ReadOnly),
        ("git", "describe",     Effect::ReadOnly),
        ("git", "stash",        Effect::ReadOnly),
        ("git", "cat-file",     Effect::ReadOnly),
        ("git", "for-each-ref", Effect::ReadOnly),
        // ── git mutating ───────────────────────────────────────────────
        ("git", "push",        Effect::Mutating),
        ("git", "pull",        Effect::Mutating),
        ("git", "fetch",       Effect::Mutating),
        ("git", "commit",      Effect::Mutating),
        ("git", "add",         Effect::Mutating),
        ("git", "rebase",      Effect::Mutating),
        ("git", "merge",       Effect::Mutating),
        ("git", "checkout",    Effect::Mutating),
        ("git", "switch",      Effect::Mutating),
        ("git", "restore",     Effect::Mutating),
        ("git", "init",        Effect::Mutating),
        ("git", "clone",       Effect::Mutating),
        ("git", "config",      Effect::Mutating),
        ("git", "cherry-pick", Effect::Mutating),
        ("git", "revert",      Effect::Mutating),
        ("git", "am",          Effect::Mutating),
        ("git", "apply",       Effect::Mutating),
        ("git", "submodule",   Effect::Mutating),
        // ── git mutating (formerly destructive) ────────────────────────
        ("git", "reset",        Effect::Mutating),
        ("git", "clean",        Effect::Mutating),
        ("git", "rm",           Effect::Mutating),
        ("git", "update-ref",   Effect::Mutating),
        ("git", "update-index", Effect::Mutating),
        // ── cargo read-only ────────────────────────────────────────────
        ("cargo", "build",            Effect::ReadOnly),
        ("cargo", "check",            Effect::ReadOnly),
        ("cargo", "test",             Effect::ReadOnly),
        ("cargo", "bench",            Effect::ReadOnly),
        ("cargo", "run",              Effect::ReadOnly),
        ("cargo", "clippy",           Effect::ReadOnly),
        ("cargo", "fmt",              Effect::ReadOnly),
        ("cargo", "doc",              Effect::ReadOnly),
        ("cargo", "clean",            Effect::ReadOnly),
        ("cargo", "update",           Effect::ReadOnly),
        ("cargo", "fetch",            Effect::ReadOnly),
        ("cargo", "tree",             Effect::ReadOnly),
        ("cargo", "metadata",         Effect::ReadOnly),
        ("cargo", "version",          Effect::ReadOnly),
        ("cargo", "verify-project",   Effect::ReadOnly),
        ("cargo", "search",           Effect::ReadOnly),
        ("cargo", "generate-lockfile", Effect::ReadOnly),
        ("cargo", "nextest",          Effect::ReadOnly),
        ("cargo", "deny",             Effect::ReadOnly),
        ("cargo", "audit",            Effect::ReadOnly),
        ("cargo", "outdated",         Effect::ReadOnly),
        ("cargo", "package",          Effect::ReadOnly),
        ("cargo", "semver-checks",    Effect::ReadOnly),
        ("cargo", "expand",           Effect::ReadOnly),
        ("cargo", "insta",            Effect::ReadOnly),
        // ── cargo mutating ─────────────────────────────────────────────
        ("cargo", "install",   Effect::Mutating),
        ("cargo", "uninstall", Effect::Mutating),
        ("cargo", "publish",   Effect::Mutating),
        ("cargo", "add",       Effect::Mutating),
        ("cargo", "remove",    Effect::Mutating),
        ("cargo", "init",      Effect::Mutating),
        ("cargo", "new",       Effect::Mutating),
        // ── gh read-only ───────────────────────────────────────────────
        ("gh", "status",          Effect::ReadOnly),
        ("gh", "repo view",       Effect::ReadOnly),
        ("gh", "repo list",       Effect::ReadOnly),
        ("gh", "repo clone",      Effect::ReadOnly),
        ("gh", "pr list",         Effect::ReadOnly),
        ("gh", "pr view",         Effect::ReadOnly),
        ("gh", "pr diff",         Effect::ReadOnly),
        ("gh", "pr checks",       Effect::ReadOnly),
        ("gh", "pr status",       Effect::ReadOnly),
        ("gh", "issue list",      Effect::ReadOnly),
        ("gh", "issue view",      Effect::ReadOnly),
        ("gh", "issue status",    Effect::ReadOnly),
        ("gh", "run list",        Effect::ReadOnly),
        ("gh", "run view",        Effect::ReadOnly),
        ("gh", "run watch",       Effect::ReadOnly),
        ("gh", "workflow list",   Effect::ReadOnly),
        ("gh", "workflow view",   Effect::ReadOnly),
        ("gh", "release list",    Effect::ReadOnly),
        ("gh", "release view",    Effect::ReadOnly),
        ("gh", "search",          Effect::ReadOnly),
        ("gh", "browse",          Effect::ReadOnly),
        ("gh", "api",             Effect::ReadOnly),
        ("gh", "auth status",     Effect::ReadOnly),
        ("gh", "auth token",      Effect::ReadOnly),
        ("gh", "extension list",  Effect::ReadOnly),
        ("gh", "label list",      Effect::ReadOnly),
        ("gh", "cache list",      Effect::ReadOnly),
        ("gh", "variable list",   Effect::ReadOnly),
        ("gh", "variable get",    Effect::ReadOnly),
        ("gh", "secret list",     Effect::ReadOnly),
        // ── gh mutating ────────────────────────────────────────────────
        ("gh", "repo create",       Effect::Mutating),
        ("gh", "repo edit",         Effect::Mutating),
        ("gh", "repo fork",         Effect::Mutating),
        ("gh", "repo rename",       Effect::Mutating),
        ("gh", "repo archive",      Effect::Mutating),
        ("gh", "pr create",         Effect::Mutating),
        ("gh", "pr merge",          Effect::Mutating),
        ("gh", "pr close",          Effect::Mutating),
        ("gh", "pr reopen",         Effect::Mutating),
        ("gh", "pr comment",        Effect::Mutating),
        ("gh", "pr review",         Effect::Mutating),
        ("gh", "pr edit",           Effect::Mutating),
        ("gh", "issue create",      Effect::Mutating),
        ("gh", "issue close",       Effect::Mutating),
        ("gh", "issue reopen",      Effect::Mutating),
        ("gh", "issue comment",     Effect::Mutating),
        ("gh", "issue edit",        Effect::Mutating),
        ("gh", "issue pin",         Effect::Mutating),
        ("gh", "issue unpin",       Effect::Mutating),
        ("gh", "run rerun",         Effect::Mutating),
        ("gh", "run cancel",        Effect::Mutating),
        ("gh", "run delete",        Effect::Mutating),
        ("gh", "workflow enable",   Effect::Mutating),
        ("gh", "workflow disable",  Effect::Mutating),
        ("gh", "workflow run",      Effect::Mutating),
        ("gh", "release create",    Effect::Mutating),
        ("gh", "release edit",      Effect::Mutating),
        ("gh", "auth login",        Effect::Mutating),
        ("gh", "auth logout",       Effect::Mutating),
        ("gh", "auth refresh",      Effect::Mutating),
        ("gh", "extension install", Effect::Mutating),
        ("gh", "extension remove",  Effect::Mutating),
        ("gh", "extension upgrade", Effect::Mutating),
        ("gh", "label create",      Effect::Mutating),
        ("gh", "label edit",        Effect::Mutating),
        ("gh", "variable set",      Effect::Mutating),
        ("gh", "variable delete",   Effect::Mutating),
        ("gh", "secret set",        Effect::Mutating),
        ("gh", "secret delete",     Effect::Mutating),
        ("gh", "config set",        Effect::Mutating),
        // ── gh mutating (formerly destructive) ─────────────────────────
        ("gh", "repo delete",    Effect::Mutating),
        ("gh", "issue delete",   Effect::Mutating),
        ("gh", "issue transfer", Effect::Mutating),
        ("gh", "release delete", Effect::Mutating),
        ("gh", "label delete",   Effect::Mutating),
        ("gh", "cache delete",   Effect::Mutating),
        // ── kubectl read-only ──────────────────────────────────────────
        ("kubectl", "get",           Effect::ReadOnly),
        ("kubectl", "describe",      Effect::ReadOnly),
        ("kubectl", "logs",          Effect::ReadOnly),
        ("kubectl", "top",           Effect::ReadOnly),
        ("kubectl", "explain",       Effect::ReadOnly),
        ("kubectl", "api-resources", Effect::ReadOnly),
        ("kubectl", "api-versions",  Effect::ReadOnly),
        ("kubectl", "version",       Effect::ReadOnly),
        ("kubectl", "cluster-info",  Effect::ReadOnly),
        // ── kubectl mutating ───────────────────────────────────────────
        ("kubectl", "apply",        Effect::Mutating),
        ("kubectl", "delete",       Effect::Mutating),
        ("kubectl", "rollout",      Effect::Mutating),
        ("kubectl", "scale",        Effect::Mutating),
        ("kubectl", "autoscale",    Effect::Mutating),
        ("kubectl", "patch",        Effect::Mutating),
        ("kubectl", "replace",      Effect::Mutating),
        ("kubectl", "create",       Effect::Mutating),
        ("kubectl", "edit",         Effect::Mutating),
        ("kubectl", "drain",        Effect::Mutating),
        ("kubectl", "cordon",       Effect::Mutating),
        ("kubectl", "uncordon",     Effect::Mutating),
        ("kubectl", "taint",        Effect::Mutating),
        ("kubectl", "exec",         Effect::Mutating),
        ("kubectl", "run",          Effect::Mutating),
        ("kubectl", "port-forward", Effect::Mutating),
        ("kubectl", "cp",           Effect::Mutating),
    ];

    let kb = default_knowledge_base();
    for (cmd, subcmd, expected) in cases {
        let command = kb
            .commands
            .get(*cmd)
            .unwrap_or_else(|| panic!("'{cmd}' should be in the KB"));
        let entry = command
            .subcommands
            .get(subcmd)
            .unwrap_or_else(|| panic!("'{cmd} {subcmd}' should be in the KB"));
        assert_eq!(
            entry.effect, *expected,
            "'{cmd} {subcmd}' effect: expected {expected:?}, got {:?}",
            entry.effect
        );
    }
}

// ── CLASSIFY_INTEGRATION: classify() end-to-end table ────────────────────

#[test]
fn classify_integration() {
    // (argv, expected_effect, expected_subcommand)
    let cases: &[(&[&str], Effect, Option<&str>)] = &[
        (&["git", "status"], Effect::ReadOnly, Some("status")),
        (&["git", "log"], Effect::ReadOnly, Some("log")),
        (&["git", "diff"], Effect::ReadOnly, Some("diff")),
        (&["git", "push"], Effect::Mutating, Some("push")),
        (&["git", "reset"], Effect::Mutating, Some("reset")),
        (&["gh", "pr", "list"], Effect::ReadOnly, Some("pr list")),
        (&["gh", "pr", "create"], Effect::Mutating, Some("pr create")),
        (
            &["gh", "repo", "delete"],
            Effect::Mutating,
            Some("repo delete"),
        ),
        (&["cargo", "test"], Effect::ReadOnly, Some("test")),
        (&["cargo", "publish"], Effect::Mutating, Some("publish")),
        (&["kubectl", "get"], Effect::ReadOnly, Some("get")),
        (&["kubectl", "apply"], Effect::Mutating, Some("apply")),
        (&["frobnicate", "arg"], Effect::Unknown, None),
    ];

    let kb = default_knowledge_base();
    for (argv, expected_effect, expected_subcmd) in cases {
        let cmd_word = Word::from(argv[0]);
        let word_vec = words(argv);
        let info = classify(&cmd_word, &word_vec, kb);
        let label = argv.join(" ");
        assert_eq!(
            info.effect, *expected_effect,
            "classify({label:?}) effect: expected {expected_effect:?}, got {:?}",
            info.effect
        );
        assert_eq!(
            info.subcommand.as_deref(),
            *expected_subcmd,
            "classify({label:?}) subcommand: expected {expected_subcmd:?}, got {:?}",
            info.subcommand
        );
    }
}

// ── classify: escalation flag passthrough ─────────────────────────────────

#[test]
fn classify_git_push_force_has_escalation_flag() {
    let kb = default_knowledge_base();
    let info = classify(&Word::from("git"), &words(&["git", "push", "--force"]), kb);
    assert_eq!(info.effect, Effect::Mutating);
    assert!(
        info.has_escalation_flags,
        "git push --force should set has_escalation_flags"
    );
}

// ── classify: sudo wrapper ────────────────────────────────────────────────

#[test]
fn classify_sudo_wrapper() {
    let kb = default_knowledge_base();
    let info = classify(&Word::from("sudo"), &words(&["sudo", "rm", "-rf", "/"]), kb);
    let wrapper = info.wrapper.expect("sudo should return wrapper info");
    assert_eq!(wrapper.name, "sudo");
    assert!(wrapper.escalates_privilege);
}

// ── deny-list ─────────────────────────────────────────────────────────────

#[test]
fn deny_list_commands_are_mutating() {
    let kb = default_knowledge_base();
    for cmd in &["shred", "dd", "shutdown", "reboot"] {
        let entry = kb
            .commands
            .get(*cmd)
            .unwrap_or_else(|| panic!("{cmd} should be in the KB"));
        assert_eq!(entry.effect, Effect::Mutating, "{cmd} should be Mutating");
    }
}

// ── flag tests ────────────────────────────────────────────────────────────

// ── flag schema tests ─────────────────────────────────────────────────────

#[test]
fn git_flag_schema() {
    let kb = default_knowledge_base();
    let git = &kb.commands["git"];
    for flag in &["--force", "-f", "--force-with-lease"] {
        assert!(
            git.flags.escalation.contains(&flag.to_string()),
            "git missing escalation flag {flag}"
        );
    }
    for flag in &["-C", "--git-dir"] {
        assert!(
            git.flags.skip_arg.contains(&flag.to_string()),
            "git missing skip_arg flag {flag}"
        );
    }
}

// ── wrapper tests (table-driven) ─────────────────────────────────────────

const WRAPPER_FIELDS: &[(&str, Effect, bool, bool)] = &[
    // (name, floor_effect, clears_env, escalates_privilege)
    ("sudo", Effect::Mutating, false, true),
    ("su", Effect::Mutating, true, true),
    ("doas", Effect::Mutating, false, true),
    ("pkexec", Effect::Mutating, true, true),
    ("env", Effect::ReadOnly, false, false),
    ("xargs", Effect::ReadOnly, false, false),
    ("nohup", Effect::ReadOnly, false, false),
    ("nice", Effect::ReadOnly, false, false),
    ("timeout", Effect::ReadOnly, false, false),
    ("time", Effect::ReadOnly, false, false),
    ("watch", Effect::ReadOnly, false, false),
    ("strace", Effect::ReadOnly, false, false),
    ("ltrace", Effect::ReadOnly, false, false),
    ("parallel", Effect::ReadOnly, false, false),
];

#[test]
fn wrapper_fields() {
    let kb = default_knowledge_base();
    for (name, floor, clears, escalates) in WRAPPER_FIELDS {
        let w = kb
            .wrappers
            .get(*name)
            .unwrap_or_else(|| panic!("{name} should be in wrappers"));
        assert_eq!(w.floor_effect, *floor, "{name} floor_effect");
        assert_eq!(w.clears_env, *clears, "{name} clears_env");
        assert_eq!(
            w.escalates_privilege, *escalates,
            "{name} escalates_privilege"
        );
    }
}

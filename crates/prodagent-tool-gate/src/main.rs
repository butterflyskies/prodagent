//! `prodagent-tool-gate` — PreToolUse hook binary for Claude Code.
//!
//! Reads Claude Code hook JSON from stdin, evaluates the command through
//! prodagent's policy engine, and emits a `hookSpecificOutput` JSON response
//! to stdout with a `permissionDecision` of `allow`, `ask`, or `deny`.
//!
//! Exit code is always 0 for normal operation (the decision is communicated
//! via JSON, not exit code). Exit code 1 indicates a fatal error.

use clap::Parser;

mod decision_log;
mod hook;

#[derive(Parser)]
#[command(
    version,
    about = "PreToolUse hook — gates Bash commands via prodagent's policy engine"
)]
struct Cli {
    /// Turn all Deny decisions into Ask — escape hatch for debugging.
    #[arg(long)]
    escalate_deny: bool,

    /// Print the merged configuration (all three tiers) and exit.
    #[arg(long)]
    dump_config: bool,

    /// Parse a command and print its shell AST, then exit.
    #[arg(long, value_name = "COMMAND")]
    dump_ast: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if cli.dump_config {
        if let Err(e) = dump_config() {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        return;
    }

    if let Some(ref command) = cli.dump_ast {
        dump_ast(command);
        return;
    }

    if let Err(e) = hook::run(cli.escalate_deny) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Print the merged three-tier configuration and exit.
fn dump_config() -> anyhow::Result<()> {
    let loader = prodagent_config::ConfigLoader::from_environment();
    let config = loader.load()?;

    println!("{}", serde_json::to_string_pretty(&config.policy)?);
    Ok(())
}

/// Parse a command string and print its AST.
fn dump_ast(command: &str) {
    match agent_shell_parser::parse::parse_with_substitutions(command) {
        Ok(pipeline) => {
            println!("{pipeline:#?}");
        }
        Err(e) => {
            eprintln!("parse error: {e}");
            std::process::exit(1);
        }
    }
}

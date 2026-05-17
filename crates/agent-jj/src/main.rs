use clap::{Parser, Subcommand};

mod cleanup;
mod guard;
mod policy;
mod workspace;

#[derive(Parser)]
#[command(version, about = "Agent productivity hooks for jj-colocated repos")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// PreToolUse hook — blocks git commands in jj-colocated repos with jj alternatives
    Guard,
    /// WorktreeCreate hook — creates jj workspaces for agent worktree isolation
    Workspace,
    /// WorktreeRemove hook — forgets jj workspaces and removes directories on teardown
    Cleanup,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Guard => guard::run(),
        Command::Workspace => workspace::run(),
        Command::Cleanup => cleanup::run(),
    }
}

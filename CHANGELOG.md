# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-05-14

### Added
- `agent-jj-guard`: PreToolUse hook that blocks git commands in jj-colocated repos with per-command jj equivalents (25 commands covered)
- `agent-jj-workspace`: WorktreeCreate hook for creating jj workspaces under `.claude/worktrees/`
- `agent-jj-cleanup`: WorktreeRemove hook for cleaning up jj workspaces
- `agent-shell-parser`: Shared library for JSON input parsing, jj detection, shell tokenization, and guard rules

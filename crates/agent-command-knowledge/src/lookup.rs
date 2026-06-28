use camino::Utf8PathBuf;
use prodagent_types::Word;

use crate::types::{
    CommandInfo, Effect, FlagSchema, KnowledgeBase, PathPositionals, PathSpec, SubcommandEntry,
    WrapperInfo,
};

/// Classify a command using the knowledge base.
///
/// Takes the base command name and the full word list (including the command
/// itself). Returns a `CommandInfo` describing the command's effect,
/// subcommand, escalation flags, affected paths, and env gates.
#[must_use = "classification result contains the effect, subcommand, and paths — ignoring it skips policy evaluation"]
pub fn classify(base_command: &Word, words: &[Word], kb: &KnowledgeBase) -> CommandInfo {
    let Some(knowledge) = kb.commands.get(base_command.as_str()) else {
        return check_wrapper(base_command, kb);
    };

    let suffix = format!("/{base_command}");
    let cmd_idx = words
        .iter()
        .position(|w| w == base_command || w.ends_with(suffix.as_str()))
        .map(|i| i + 1)
        .unwrap_or(0);

    let remaining: Vec<&Word> = skip_flags(&words[cmd_idx..], &knowledge.flags);

    let (effect, subcommand, sub_depth, sub_flags, sub_env_gates, sub_paths) =
        match knowledge.subcommands.longest_match(&remaining) {
            Some((entry, depth)) => {
                let sub_pattern: String = remaining[..depth]
                    .iter()
                    .map(|w| w.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let (e, s, d, f, g, p) =
                    resolve_subcommand(entry, &remaining[depth..], &sub_pattern, depth, &[]);
                (e, s, d, f, g, p)
            }
            None => (
                knowledge.effect,
                None,
                0,
                &knowledge.flags,
                vec![],
                &knowledge.paths,
            ),
        };

    let merged_flags = merge_flag_schemas(&knowledge.flags, sub_flags);
    let has_escalation_flags = check_escalation_flags(words, &merged_flags);
    let positionals_after_sub: Vec<&Word> = remaining.iter().skip(sub_depth).copied().collect();
    let affected_paths = extract_paths(words, &positionals_after_sub, sub_paths, &merged_flags);

    let env_gates = {
        let mut gates = knowledge.env_gates.clone();
        if subcommand.is_some() {
            gates.extend(sub_env_gates);
        }
        gates
    };

    CommandInfo {
        effect,
        subcommand,
        has_escalation_flags,
        affected_paths,
        env_gates,
        wrapper: None,
    }
}

fn resolve_subcommand<'a>(
    entry: &'a SubcommandEntry,
    remaining: &[&Word],
    pattern: &str,
    accumulated_depth: usize,
    accumulated_gates: &[crate::types::EnvGate],
) -> (
    Effect,
    Option<String>,
    usize,
    &'a FlagSchema,
    Vec<crate::types::EnvGate>,
    &'a PathSpec,
) {
    // Merge gates from this level into the accumulator.
    let mut gates_so_far: Vec<crate::types::EnvGate> = accumulated_gates.to_vec();
    gates_so_far.extend(entry.env_gates.iter().cloned());

    if !entry.subcommands.is_empty() {
        let remaining_owned: Vec<Word> = remaining.iter().map(|w| Word::from(w.as_str())).collect();
        let inner_remaining: Vec<&Word> = skip_flags(&remaining_owned, &entry.flags);
        if let Some((inner_entry, inner_depth)) = entry.subcommands.longest_match(&inner_remaining)
        {
            let inner_pattern: String = inner_remaining[..inner_depth]
                .iter()
                .map(|w| w.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let full_pattern = format!("{} {}", pattern, inner_pattern);
            let total_depth = accumulated_depth + inner_depth;
            return resolve_subcommand(
                inner_entry,
                &inner_remaining[inner_depth..],
                &full_pattern,
                total_depth,
                &gates_so_far,
            );
        }
    }

    (
        entry.effect,
        Some(pattern.to_string()),
        accumulated_depth,
        &entry.flags,
        gates_so_far,
        &entry.paths,
    )
}

fn check_wrapper(base_command: &Word, kb: &KnowledgeBase) -> CommandInfo {
    if let Some(wrapper) = kb.wrappers.get(base_command.as_str()) {
        CommandInfo {
            effect: Effect::Unknown,
            subcommand: None,
            has_escalation_flags: false,
            affected_paths: vec![],
            env_gates: vec![],
            wrapper: Some(WrapperInfo {
                name: wrapper.name.clone(),
                floor_effect: wrapper.floor_effect,
                clears_env: wrapper.clears_env,
                escalates_privilege: wrapper.escalates_privilege,
            }),
        }
    } else {
        CommandInfo::unknown()
    }
}

/// Skip past flags in a word list to find subcommand words.
fn skip_flags<'a>(words: &'a [Word], schema: &FlagSchema) -> Vec<&'a Word> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let w = &words[i];
        if schema.skip_arg.iter().any(|f| w == f) {
            i += 2;
            continue;
        }
        if w.starts_with('-') && w.contains('=') {
            if let Some((flag_part, _)) = w.split_once('=') {
                if schema.skip_arg.iter().any(|f| f == flag_part) {
                    i += 1;
                    continue;
                }
            }
        }
        if w.as_str() == "--" {
            result.extend(words[i + 1..].iter());
            break;
        }
        if schema.skip_solo.iter().any(|f| w == f) {
            i += 1;
            continue;
        }
        if w.starts_with('-') {
            i += 1;
            continue;
        }
        result.push(w);
        i += 1;
    }
    result
}

fn check_escalation_flags(words: &[Word], schema: &FlagSchema) -> bool {
    words.iter().any(|w| {
        schema.escalation.iter().any(|f| {
            w == f
                || w.split_once('=')
                    .is_some_and(|(prefix, _)| prefix == f.as_str())
        })
    })
}

fn merge_flag_schemas(parent: &FlagSchema, child: &FlagSchema) -> FlagSchema {
    FlagSchema {
        skip_arg: parent
            .skip_arg
            .iter()
            .chain(child.skip_arg.iter())
            .cloned()
            .collect(),
        skip_solo: parent
            .skip_solo
            .iter()
            .chain(child.skip_solo.iter())
            .cloned()
            .collect(),
        escalation: parent
            .escalation
            .iter()
            .chain(child.escalation.iter())
            .cloned()
            .collect(),
        path: parent
            .path
            .iter()
            .chain(child.path.iter())
            .cloned()
            .collect(),
    }
}

/// Extract affected paths from a command invocation.
///
/// `positionals` is the flag-skipped word list after subcommand consumption —
/// the same view that `longest_match` operated on, minus the subcommand words.
/// This ensures positional path extraction agrees with subcommand resolution
/// about which words are arguments vs flag values.
///
/// Shell words are validated as UTF-8 paths at this boundary. Since `Word`
/// wraps `String` (already UTF-8), the conversion to `Utf8PathBuf` is
/// infallible. This gives downstream consumers proper path semantics (joining,
/// prefix matching, canonicalization) without re-parsing.
fn extract_paths(
    words: &[Word],
    positionals: &[&Word],
    path_spec: &PathSpec,
    flag_schema: &FlagSchema,
) -> Vec<Utf8PathBuf> {
    let mut paths = Vec::new();

    for flag in &flag_schema.path {
        let prefix = format!("{flag}=");
        let mut i = 0;
        while i < words.len() {
            if words[i] == flag.as_str() && i + 1 < words.len() {
                paths.push(Utf8PathBuf::from(words[i + 1].as_str()));
                i += 2;
                continue;
            }
            if let Some(value) = words[i].strip_prefix(prefix.as_str()) {
                paths.push(Utf8PathBuf::from(value));
            }
            i += 1;
        }
    }

    match &path_spec.positionals {
        PathPositionals::None => {}
        PathPositionals::All => {
            paths.extend(positionals.iter().map(|p| Utf8PathBuf::from(p.as_str())));
        }
        PathPositionals::Tail(skip) => {
            paths.extend(
                positionals
                    .iter()
                    .skip(*skip)
                    .map(|p| Utf8PathBuf::from(p.as_str())),
            );
        }
        PathPositionals::Last => {
            if let Some(last) = positionals.last() {
                paths.push(Utf8PathBuf::from(last.as_str()));
            }
        }
    }

    paths
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod lookup_tests;

#[cfg(test)]
#[path = "classify_proptest.rs"]
mod classify_proptest;

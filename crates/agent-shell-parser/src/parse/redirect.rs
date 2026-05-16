use super::types::Redirection;
use tree_sitter::Node;

/// Inspect a `file_redirect` node for output redirection.
///
/// Safe (returns `None`): `<`, `<<`, `<<-`, `<<<`, `<&`, anything to
/// `/dev/null`, fd duplication to 0/1/2, fd closing (`>&-`).
///
/// Flagged (returns `Some`): `>`, `>>`, `>|`, `&>`, `&>>` to non-devnull,
/// `<>` (read-write), `>&N` where N >= 3, `N>` to non-devnull.
fn check_file_redirect(node: Node, source: &[u8]) -> Option<Redirection> {
    let mut fd: Option<String> = None;
    let mut operator = "";
    let mut dest = String::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "file_descriptor" {
            fd = child.utf8_text(source).ok().map(str::to_string);
        } else if child.is_named() {
            dest = child.utf8_text(source).unwrap_or("").to_string();
        } else {
            let k = child.kind();
            if matches!(
                k,
                ">" | ">>"
                    | ">|"
                    | "&>"
                    | "&>>"
                    | ">&"
                    | "<"
                    | "<>"
                    | "<<<"
                    | "<<"
                    | "<<-"
                    | "<&"
                    | ">&-"
                    | "<&-"
            ) {
                operator = k;
            }
        }
    }

    // Explicit <> token (if a future tree-sitter-bash version adds it).
    if operator == "<>" {
        return Some(Redirection {
            description: "output redirection (<> read-write)".into(),
        });
    }

    if matches!(
        operator,
        "" | "<" | "<<<" | "<<" | "<<-" | "<&" | ">&-" | "<&-"
    ) {
        // tree-sitter-bash 0.25 parses `<>` as `<` + ERROR(`>`).
        // Detect this by scanning the node text as a fallback.
        if operator == "<" {
            let text = node.utf8_text(source).unwrap_or("");
            if text.contains("<>") {
                return Some(Redirection {
                    description: "output redirection (<> read-write)".into(),
                });
            }
        }
        return None;
    }

    if matches!(operator, "&>" | "&>>") {
        if dest == "/dev/null" {
            return None;
        }
        return Some(Redirection {
            description: format!("output redirection ({operator})"),
        });
    }

    if operator == ">&" {
        if let Some(ref f) = fd {
            if matches!(dest.as_str(), "0" | "1" | "2") {
                return None;
            }
            return Some(Redirection {
                description: format!("output redirection ({f}>&{dest}, custom fd target)"),
            });
        }
        if matches!(dest.as_str(), "0" | "1" | "2") {
            return None;
        }
        return Some(Redirection {
            description: format!("output redirection (>&{dest}, custom fd target)"),
        });
    }

    if matches!(operator, ">" | ">>" | ">|") {
        if dest == "/dev/null" {
            return None;
        }
        if let Some(ref f) = fd {
            return Some(Redirection {
                description: format!("output redirection ({f}{operator})"),
            });
        }
        return Some(Redirection {
            description: format!("output redirection ({operator})"),
        });
    }

    None
}

/// Recursively search for `file_redirect` descendants, skipping `heredoc_body`.
pub(super) fn detect_redirections(node: Node, source: &[u8]) -> Option<Redirection> {
    if node.kind() == "file_redirect" {
        return check_file_redirect(node, source);
    }
    if node.kind() == "heredoc_body" {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(r) = detect_redirections(child, source) {
            return Some(r);
        }
    }
    None
}

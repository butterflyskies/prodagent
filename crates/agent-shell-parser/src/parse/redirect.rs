use super::types::Redirection;
use tree_sitter::Node;

fn parse_fd(s: &str) -> Option<u32> {
    s.parse().ok()
}

/// Inspect a `file_redirect` node for output redirection.
///
/// Safe (returns `None`): `<`, `<<`, `<<-`, `<<<`, `<&`, anything to
/// `/dev/null`, fd duplication to 0/1/2, fd closing (`>&-`).
///
/// Flagged (returns `Some`): `>`, `>>`, `>|`, `&>`, `&>>` to non-devnull,
/// `<>` (read-write), `>&N` where N >= 3, `N>` to non-devnull.
fn check_file_redirect(node: Node, source: &[u8]) -> Option<Redirection> {
    let mut fd_text: Option<String> = None;
    let mut operator = "";
    let mut dest = String::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "file_descriptor" {
            fd_text = child.utf8_text(source).ok().map(str::to_string);
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

    let fd = fd_text.as_deref().and_then(parse_fd);

    if operator == "<>" {
        return Some(Redirection {
            operator: "<>",
            fd,
            target: dest,
        });
    }

    if matches!(
        operator,
        "" | "<" | "<<<" | "<<" | "<<-" | "<&" | ">&-" | "<&-"
    ) {
        // Workaround: tree-sitter-bash does not include `<>` in its grammar
        // (missing from the `file_redirect` choice list as of 0.25.1), so the
        // parser sees `<` + ERROR(`>`).  This string check recovers the correct
        // operator from the raw source text.
        // Remove when tree-sitter-bash adds `<>` to its redirect operators.
        if operator == "<" {
            let text = node.utf8_text(source).unwrap_or("");
            if text.contains("<>") {
                return Some(Redirection {
                    operator: "<>",
                    fd,
                    target: dest,
                });
            }
        }
        return None;
    }

    if matches!(operator, "&>" | "&>>") {
        if dest == "/dev/null" {
            return None;
        }
        let op: &'static str = if operator == "&>" { "&>" } else { "&>>" };
        return Some(Redirection {
            operator: op,
            fd,
            target: dest,
        });
    }

    if operator == ">&" {
        if matches!(dest.as_str(), "0" | "1" | "2") && fd_text.is_none() {
            return None;
        }
        if fd_text.is_some() && matches!(dest.as_str(), "0" | "1" | "2") {
            return None;
        }
        return Some(Redirection {
            operator: ">&",
            fd,
            target: dest,
        });
    }

    if matches!(operator, ">" | ">>" | ">|") {
        if dest == "/dev/null" {
            return None;
        }
        let op: &'static str = match operator {
            ">>" => ">>",
            ">|" => ">|",
            _ => ">",
        };
        return Some(Redirection {
            operator: op,
            fd,
            target: dest,
        });
    }

    None
}

/// Recursively collect `file_redirect` descendants, skipping `heredoc_body`.
fn collect_redirections_inner(node: Node, source: &[u8], found: &mut Vec<Redirection>) {
    if node.kind() == "file_redirect" {
        if let Some(redirection) = check_file_redirect(node, source) {
            found.push(redirection);
        }
        return;
    }
    if node.kind() == "heredoc_body" {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_redirections_inner(child, source, found);
    }
}

pub(super) fn collect_redirections(node: Node, source: &[u8]) -> Vec<Redirection> {
    let mut found = Vec::new();
    collect_redirections_inner(node, source, &mut found);
    found
}

/// Recursively find the first `file_redirect` descendant.
///
/// Kept for compatibility with callers that need only the aggregate
/// redirection signal. Consumers enforcing per-destination policy should use
/// [`collect_redirections`] instead.
pub(super) fn detect_redirections(node: Node, source: &[u8]) -> Option<Redirection> {
    collect_redirections(node, source).into_iter().next()
}

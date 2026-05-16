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
        // tree-sitter-bash 0.25 parses `<>` as `<` + ERROR(`>`).
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

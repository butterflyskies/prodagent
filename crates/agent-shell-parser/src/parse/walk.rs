use super::redirect::detect_redirections;
use super::types::{Operator, Redirection};
use tree_sitter::Node;

pub(super) struct WalkResult {
    pub(super) segments: Vec<SegmentInfo>,
    pub(super) operators: Vec<Operator>,
}

pub(super) struct SegmentInfo {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) redirection: Option<Redirection>,
}

impl WalkResult {
    pub(super) fn empty() -> Self {
        Self {
            segments: vec![],
            operators: vec![],
        }
    }

    pub(super) fn single(start: usize, end: usize, redir: Option<Redirection>) -> Self {
        Self {
            segments: vec![SegmentInfo {
                start,
                end,
                redirection: redir,
            }],
            operators: vec![],
        }
    }

    pub(super) fn append(&mut self, other: WalkResult, join_op: Option<Operator>) {
        if other.segments.is_empty() {
            return;
        }
        if !self.segments.is_empty() {
            if let Some(op) = join_op {
                self.operators.push(op);
            }
        }
        self.segments.extend(other.segments);
        self.operators.extend(other.operators);
    }
}

/// For `list`/`pipeline`, only the last segment gets the redirect.
/// For control-flow bodies, every segment gets it.
fn propagate_redirect(result: &mut WalkResult, node_kind: &str, redir: &Redirection) {
    if node_kind == "list" || node_kind == "pipeline" {
        if let Some(last) = result.segments.last_mut() {
            if last.redirection.is_none() {
                last.redirection = Some(redir.clone());
            }
        }
    } else {
        for seg in &mut result.segments {
            if seg.redirection.is_none() {
                seg.redirection = Some(redir.clone());
            }
        }
    }
}

pub(super) fn walk_ast(node: Node, source: &[u8]) -> WalkResult {
    match node.kind() {
        "program" => walk_program(node, source),
        "list" => walk_list(node, source),
        "pipeline" => walk_pipeline(node, source),
        "command" | "declaration_command" | "test_command" | "unset_command" => {
            let redir = detect_redirections(node, source);
            WalkResult::single(node.start_byte(), node.end_byte(), redir)
        }
        "variable_assignment" | "variable_assignments" => {
            WalkResult::single(node.start_byte(), node.end_byte(), None)
        }
        "redirected_statement" => walk_redirected(node, source),
        "for_statement" | "while_statement" | "until_statement" | "c_style_for_statement" => {
            walk_loop(node, source)
        }
        "if_statement" => walk_if(node, source),
        "case_statement" => walk_case(node, source),
        "subshell" | "compound_statement" | "do_group" | "else_clause" | "elif_clause" => {
            walk_block(node, source)
        }
        "case_item" => walk_case_item(node, source),
        "negated_command" => walk_negated(node, source),
        "function_definition" => walk_function(node, source),
        "comment" | "heredoc_body" => WalkResult::empty(),
        _ if node.is_named() => WalkResult::single(node.start_byte(), node.end_byte(), None),
        _ => WalkResult::empty(),
    }
}

/// Top-level `program` node. Detects `&` (background) between children.
fn walk_program(node: Node, source: &[u8]) -> WalkResult {
    let mut result = WalkResult::empty();
    let mut cursor = node.walk();
    let all: Vec<Node> = node.children(&mut cursor).collect();

    for (i, child) in all.iter().enumerate() {
        if !child.is_named() {
            continue;
        }
        let join_op = if result.segments.is_empty() {
            None
        } else {
            let bg = (0..i)
                .rev()
                .take_while(|&j| !all[j].is_named())
                .any(|j| all[j].kind() == "&");
            Some(if bg {
                Operator::Background
            } else {
                Operator::Semi
            })
        };
        result.append(walk_ast(*child, source), join_op);
    }
    result
}

/// `list` — left-recursive binary: `a && b || c` → `list(list(a,&&,b),||,c)`.
///
/// Iterative left-descent to avoid stack overflow on deeply nested chains
/// (e.g. 20,000+ `&&`-chained commands).
fn walk_list(node: Node, source: &[u8]) -> WalkResult {
    // Collect (right_child, operator) pairs by iteratively descending into
    // the left-recursive spine of `list` nodes.
    let mut parts: Vec<(Node, Operator)> = Vec::new();
    let mut current = node;

    loop {
        let mut cursor = current.walk();
        let named: Vec<Node> = current.named_children(&mut cursor).collect();

        if named.len() < 2 {
            // Degenerate list node (0 or 1 children) — treat current as the
            // leftmost base and stop descending.
            break;
        }

        let op = list_operator(current);
        // Save the right child and the operator joining left to right.
        parts.push((named[1], op));

        if named[0].kind() == "list" {
            // Left child is another list — descend iteratively.
            current = named[0];
        } else {
            // Left child is not a list — it is the leftmost base node.
            current = named[0];
            break;
        }
    }

    // `current` is now the leftmost non-list node (or a degenerate list).
    // Walk it to produce the initial result.
    let mut result = walk_ast(current, source);

    // Replay the collected right-hand sides from left to right (they were
    // pushed in right-to-left order during descent).
    for (right_node, op) in parts.into_iter().rev() {
        result.append(walk_ast(right_node, source), Some(op));
    }

    result
}

/// tree-sitter-bash `list` nodes only contain `&&` or `||`.
/// The background `&` operator appears at the `program` level instead.
fn list_operator(node: Node) -> Operator {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            match child.kind() {
                "&&" => return Operator::And,
                "||" => return Operator::Or,
                _ => {}
            }
        }
    }
    Operator::Semi
}

fn walk_pipeline(node: Node, source: &[u8]) -> WalkResult {
    let mut result = WalkResult::empty();
    let mut pending_op: Option<Operator> = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            result.append(walk_ast(child, source), pending_op.take());
        } else {
            match child.kind() {
                "|" => pending_op = Some(Operator::Pipe),
                "|&" => pending_op = Some(Operator::PipeErr),
                _ => {}
            }
        }
    }
    result
}

fn walk_redirected(node: Node, source: &[u8]) -> WalkResult {
    let redir = detect_redirections(node, source);

    // First pass: heredoc_redirect with same-line commands.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "heredoc_redirect" {
            let inner = walk_heredoc_redirect(child, source);
            if !inner.segments.is_empty() {
                let mut full = WalkResult::empty();
                let mut c2 = node.walk();
                for sib in node.named_children(&mut c2) {
                    if sib.kind() == "heredoc_redirect" {
                        break;
                    }
                    if matches!(sib.kind(), "file_redirect" | "herestring_redirect") {
                        continue;
                    }
                    if is_leaf_command(sib) {
                        let end = effective_end(node).min(child.start_byte());
                        full.append(
                            WalkResult::single(sib.start_byte(), end, redir.clone()),
                            None,
                        );
                    } else {
                        let mut body = walk_ast(sib, source);
                        if let Some(ref r) = redir {
                            propagate_redirect(&mut body, sib.kind(), r);
                        }
                        full.append(body, None);
                    }
                    break;
                }
                let join_op = heredoc_join_operator(child);
                full.append(inner, Some(join_op));
                return full;
            }
        }
    }

    // Second pass: normal body.
    let mut cursor2 = node.walk();
    for child in node.named_children(&mut cursor2) {
        if matches!(
            child.kind(),
            "file_redirect" | "herestring_redirect" | "heredoc_redirect"
        ) {
            continue;
        }
        if is_leaf_command(child) {
            let end = effective_end(node);
            return WalkResult::single(node.start_byte(), end, redir);
        }
        let mut result = walk_ast(child, source);
        if let Some(ref r) = redir {
            propagate_redirect(&mut result, child.kind(), r);
        }
        return result;
    }

    let end = effective_end(node);
    WalkResult::single(node.start_byte(), end, redir)
}

fn walk_heredoc_redirect(node: Node, source: &[u8]) -> WalkResult {
    let mut result = WalkResult::empty();
    let mut cursor = node.walk();
    let mut loose_words_start: Option<usize> = None;
    let mut loose_words_end: usize = 0;

    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "pipeline" | "list" | "command" | "redirected_statement" => {
                if let Some(start) = loose_words_start.take() {
                    result.append(
                        WalkResult::single(start, loose_words_end, None),
                        Some(Operator::Semi),
                    );
                }
                let op = heredoc_operator_before(node, child);
                result.append(walk_ast(child, source), Some(op));
            }
            "word" => {
                if loose_words_start.is_none() {
                    loose_words_start = Some(child.start_byte());
                }
                loose_words_end = child.end_byte();
            }
            _ => {}
        }
    }

    if let Some(start) = loose_words_start {
        result.append(
            WalkResult::single(start, loose_words_end, None),
            Some(Operator::Semi),
        );
    }

    result
}

fn heredoc_operator_before(heredoc_node: Node, child: Node) -> Operator {
    let mut cursor = heredoc_node.walk();
    let mut last_op = None;
    for sib in heredoc_node.children(&mut cursor) {
        if sib.start_byte() >= child.start_byte() {
            break;
        }
        if !sib.is_named() {
            match sib.kind() {
                "&&" => last_op = Some(Operator::And),
                "||" => last_op = Some(Operator::Or),
                "|&" => last_op = Some(Operator::PipeErr),
                "|" => last_op = Some(Operator::Pipe),
                _ => {}
            }
        }
    }
    last_op.unwrap_or(Operator::Pipe)
}

fn heredoc_join_operator(heredoc_node: Node) -> Operator {
    let mut cursor = heredoc_node.walk();
    for child in heredoc_node.children(&mut cursor) {
        if !child.is_named() {
            match child.kind() {
                "&&" => return Operator::And,
                "||" => return Operator::Or,
                "|&" => return Operator::PipeErr,
                _ => {}
            }
        } else {
            match child.kind() {
                "pipeline" => return Operator::Pipe,
                "command" | "list" | "redirected_statement" => break,
                _ => {}
            }
        }
    }
    Operator::Pipe
}

/// Loop statements: `for`, `while`, `until`, `c_style_for`.
///
/// For `while`/`until`, the condition is a command — walked alongside the body.
/// For `for`/`c_style_for`, only the `do_group` body is walked; iteration
/// values are not commands (substitutions there become structural).
fn walk_loop(node: Node, source: &[u8]) -> WalkResult {
    let mut result = WalkResult::empty();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "do_group" => result.append(walk_block(child, source), Some(Operator::Semi)),
            _ if node.kind() == "while_statement" || node.kind() == "until_statement" => {
                result.append(walk_ast(child, source), Some(Operator::Semi));
            }
            _ => {}
        }
    }
    result
}

fn walk_if(node: Node, source: &[u8]) -> WalkResult {
    let mut result = WalkResult::empty();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "command"
            | "declaration_command"
            | "test_command"
            | "pipeline"
            | "list"
            | "redirected_statement"
            | "compound_statement"
            | "subshell"
            | "negated_command" => {
                result.append(walk_ast(child, source), Some(Operator::Semi));
            }
            "else_clause" | "elif_clause" => {
                result.append(walk_ast(child, source), Some(Operator::Semi));
            }
            _ => {}
        }
    }
    result
}

fn walk_case(node: Node, source: &[u8]) -> WalkResult {
    let mut result = WalkResult::empty();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "case_item" {
            result.append(walk_case_item(child, source), Some(Operator::Semi));
        }
    }
    result
}

fn walk_case_item(node: Node, source: &[u8]) -> WalkResult {
    let mut result = WalkResult::empty();
    let mut past_paren = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() && child.kind() == ")" {
            past_paren = true;
            continue;
        }
        if past_paren && child.is_named() {
            result.append(walk_ast(child, source), Some(Operator::Semi));
        }
    }
    result
}

fn walk_block(node: Node, source: &[u8]) -> WalkResult {
    let mut result = WalkResult::empty();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        result.append(walk_ast(child, source), Some(Operator::Semi));
    }
    result
}

fn walk_negated(node: Node, source: &[u8]) -> WalkResult {
    let mut cursor = node.walk();
    if let Some(child) = node.named_children(&mut cursor).next() {
        return walk_ast(child, source);
    }
    WalkResult::empty()
}

fn walk_function(node: Node, source: &[u8]) -> WalkResult {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "word" {
            continue;
        }
        return walk_ast(child, source);
    }
    WalkResult::empty()
}

fn is_leaf_command(node: Node) -> bool {
    matches!(
        node.kind(),
        "command"
            | "declaration_command"
            | "test_command"
            | "unset_command"
            | "variable_assignment"
    )
}

fn effective_end(node: Node) -> usize {
    let mut end = node.end_byte();
    trim_at_heredoc_body(node, &mut end);
    end
}

fn trim_at_heredoc_body(node: Node, end: &mut usize) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "heredoc_body" {
            *end = (*end).min(child.start_byte());
            return;
        }
        trim_at_heredoc_body(child, end);
    }
}

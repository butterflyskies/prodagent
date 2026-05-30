use super::redirect::detect_redirections;
use super::tokenize::shlex_or_whitespace_words;
use super::types::{Operator, Redirection, Word};
use tree_sitter::Node;

/// Strip the outermost matching quote pair from a word.
///
/// Handles single quotes, double quotes, and `$'...'` ANSI-C quotes.
/// Unmatched or absent quotes leave the word unchanged. Escape sequences
/// inside `$'...'` are left as-is (they are source text, not interpreted).
fn strip_quotes(word: &str) -> Word {
    // $'...' ANSI-C quotes
    if let Some(inner) = word.strip_prefix("$'") {
        if let Some(inner) = inner.strip_suffix('\'') {
            return Word::from(inner);
        }
        return Word::from(word);
    }
    // Single quotes
    if let Some(inner) = word.strip_prefix('\'') {
        if let Some(inner) = inner.strip_suffix('\'') {
            return Word::from(inner);
        }
        return Word::from(word);
    }
    // Double quotes
    if let Some(inner) = word.strip_prefix('"') {
        if let Some(inner) = inner.strip_suffix('"') {
            return Word::from(inner);
        }
        return Word::from(word);
    }
    Word::from(word)
}

pub(super) struct WalkResult {
    pub(super) segments: Vec<SegmentInfo>,
    pub(super) operators: Vec<Operator>,
}

pub(super) struct SegmentInfo {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) redirection: Option<Redirection>,
    /// Pre-tokenized words for this segment.
    ///
    /// Always populated — either via tree-sitter word extraction (for known
    /// node types like `command`, `declaration_command`, `test_command`) or
    /// via explicit shlex tokenization at the call site (for unknown node
    /// types and heredoc loose words). There is no implicit fallback.
    pub(super) words: Vec<Word>,
}

impl WalkResult {
    pub(super) fn empty() -> Self {
        Self {
            segments: vec![],
            operators: vec![],
        }
    }

    pub(super) fn single_with_words(
        start: usize,
        end: usize,
        redir: Option<Redirection>,
        words: Vec<Word>,
    ) -> Self {
        Self {
            segments: vec![SegmentInfo {
                start,
                end,
                redirection: redir,
                words,
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

/// Extract word-level tokens from a `command` node's named children.
///
/// Each named child of a tree-sitter `command` node represents one shell
/// word: `command_name`, `word`, `raw_string`, `string`,
/// `command_substitution`, `process_substitution`, `variable_assignment`
/// (for leading `KEY=VALUE`), `concatenation`, etc.
///
/// The full source text of each child is used, preserving quotes and
/// substitution delimiters. This matches shell semantics: `$(echo test)`
/// is one word, `'hello world'` is one word.
fn extract_command_words(node: Node, source: &[u8]) -> Vec<Word> {
    let mut words = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        // Skip redirect-related nodes — they are not command words.
        if matches!(
            child.kind(),
            "file_redirect" | "herestring_redirect" | "heredoc_redirect" | "heredoc_body"
        ) {
            continue;
        }
        if let Ok(text) = child.utf8_text(source) {
            words.push(strip_quotes(text));
        }
    }
    words
}

/// Extract word-level tokens from a `declaration_command` node.
///
/// Declaration commands (`export`, `declare`, `local`, `readonly`, `typeset`)
/// have the keyword as an anonymous child and `variable_assignment` or
/// `word` nodes as named children. We include the keyword as the first word.
fn extract_declaration_words(node: Node, source: &[u8]) -> Vec<Word> {
    let mut words = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // Anonymous keyword nodes: export, declare, local, readonly, typeset
            "export" | "declare" | "local" | "readonly" | "typeset" => {
                if let Ok(text) = child.utf8_text(source) {
                    words.push(strip_quotes(text));
                }
            }
            _ if child.is_named() => {
                // Skip redirect-related nodes.
                if matches!(
                    child.kind(),
                    "file_redirect" | "herestring_redirect" | "heredoc_redirect" | "heredoc_body"
                ) {
                    continue;
                }
                if let Ok(text) = child.utf8_text(source) {
                    words.push(strip_quotes(text));
                }
            }
            _ => {}
        }
    }
    words
}

/// Extract word-level tokens from a `variable_assignments` (plural) node.
///
/// This node wraps multiple `variable_assignment` children. Each child
/// becomes one word (e.g. `FOO=bar BAZ=qux` -> `["FOO=bar", "BAZ=qux"]`).
fn extract_variable_assignments_words(node: Node, source: &[u8]) -> Vec<Word> {
    let mut words = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Ok(text) = child.utf8_text(source) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                words.push(strip_quotes(trimmed));
            }
        }
    }
    words
}

/// Extract word-level tokens from an `unset_command` node.
///
/// Structure: `unset` (anonymous) followed by `variable_name` children.
fn extract_unset_words(node: Node, source: &[u8]) -> Vec<Word> {
    let mut words = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "unset" | "unsetenv" => {
                if let Ok(text) = child.utf8_text(source) {
                    words.push(strip_quotes(text));
                }
            }
            _ if child.is_named() => {
                if let Ok(text) = child.utf8_text(source) {
                    words.push(strip_quotes(text));
                }
            }
            _ => {}
        }
    }
    words
}

/// Extract word-level tokens from a `test_command` node.
///
/// tree-sitter-bash parses `[[ -f "foo bar" ]]` into structured children:
/// `[[` (anonymous), `test_operator`, string/word, `]]` (anonymous).
/// This function walks those children (including nested `binary_expression`
/// and `unary_expression`) and collects words, stripping quotes. The
/// bracket delimiters (`[[`, `]]`, `[`, `]`) are included as words.
fn extract_test_words(node: Node, source: &[u8]) -> Vec<Word> {
    let mut words = Vec::new();
    extract_test_words_recursive(node, source, &mut words);
    words
}

fn extract_test_words_recursive(node: Node, source: &[u8], words: &mut Vec<Word>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // Bracket delimiters — include as words
            "[[" | "]]" | "[" | "]" => {
                if let Ok(text) = child.utf8_text(source) {
                    words.push(Word::from(text));
                }
            }
            // Compound test expressions — recurse into them
            "binary_expression" | "unary_expression" => {
                extract_test_words_recursive(child, source, words);
            }
            // Operators and leaf tokens — extract text
            "test_operator" => {
                if let Ok(text) = child.utf8_text(source) {
                    words.push(Word::from(text));
                }
            }
            // Named nodes (string, word, variable, etc.) — extract and strip quotes
            _ if child.is_named() => {
                if let Ok(text) = child.utf8_text(source) {
                    words.push(strip_quotes(text));
                }
            }
            // Anonymous operators like ==, !=, =~, -eq, &&, ||, etc.
            _ => {
                let text = child.utf8_text(source).unwrap_or("");
                if !text.is_empty() && text != "(" && text != ")" {
                    // Skip parentheses used for grouping, keep operators
                    if text.starts_with('-')
                        || text.contains('=')
                        || text == "!"
                        || text == ">"
                        || text == "<"
                        || text == "&&"
                        || text == "||"
                    {
                        words.push(Word::from(text));
                    }
                }
            }
        }
    }
}

pub(super) fn walk_ast(node: Node, source: &[u8]) -> WalkResult {
    match node.kind() {
        "program" => walk_program(node, source),
        "list" => walk_list(node, source),
        "pipeline" => walk_pipeline(node, source),
        "command" => {
            let redir = detect_redirections(node, source);
            let words = extract_command_words(node, source);
            WalkResult::single_with_words(node.start_byte(), node.end_byte(), redir, words)
        }
        "declaration_command" => {
            let redir = detect_redirections(node, source);
            let words = extract_declaration_words(node, source);
            WalkResult::single_with_words(node.start_byte(), node.end_byte(), redir, words)
        }
        "unset_command" => {
            let redir = detect_redirections(node, source);
            let words = extract_unset_words(node, source);
            WalkResult::single_with_words(node.start_byte(), node.end_byte(), redir, words)
        }
        "test_command" => {
            let redir = detect_redirections(node, source);
            let words = extract_test_words(node, source);
            WalkResult::single_with_words(node.start_byte(), node.end_byte(), redir, words)
        }
        "variable_assignment" => {
            // Bare variable assignment (no command). The whole text is
            // effectively one "word". Use full text as a single-element list.
            let text = node.utf8_text(source).unwrap_or("").trim();
            let words: Vec<Word> = if text.is_empty() {
                vec![]
            } else {
                vec![strip_quotes(text)]
            };
            WalkResult::single_with_words(node.start_byte(), node.end_byte(), None, words)
        }
        "variable_assignments" => {
            // Multiple bare variable assignments (e.g. `FOO=bar BAZ=qux`).
            // Iterate named children to produce one word per assignment.
            let words = extract_variable_assignments_words(node, source);
            WalkResult::single_with_words(node.start_byte(), node.end_byte(), None, words)
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
        _ if node.is_named() => {
            // Unknown node type — shlex fallback, explicit and auditable.
            let text = node.utf8_text(source).unwrap_or("");
            let words = shlex_or_whitespace_words(text);
            WalkResult::single_with_words(node.start_byte(), node.end_byte(), None, words)
        }
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
                        let words = extract_leaf_words(sib, source);
                        let wr = WalkResult::single_with_words(
                            sib.start_byte(),
                            end,
                            redir.clone(),
                            words,
                        );
                        full.append(wr, None);
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
            let words = extract_leaf_words(child, source);
            return WalkResult::single_with_words(node.start_byte(), end, redir, words);
        }
        let mut result = walk_ast(child, source);
        if let Some(ref r) = redir {
            propagate_redirect(&mut result, child.kind(), r);
        }
        return result;
    }

    let end = effective_end(node);
    // Redirected statement with no recognized body — shlex the visible text.
    let text = source
        .get(node.start_byte()..end)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("");
    let words = shlex_or_whitespace_words(text);
    WalkResult::single_with_words(node.start_byte(), end, redir, words)
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
                    // Heredoc loose words — no tree-sitter structure, use shlex.
                    let text = source
                        .get(start..loose_words_end)
                        .and_then(|b| std::str::from_utf8(b).ok())
                        .unwrap_or("");
                    let words = shlex_or_whitespace_words(text);
                    result.append(
                        WalkResult::single_with_words(start, loose_words_end, None, words),
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
        // Heredoc trailing loose words — no tree-sitter structure, use shlex.
        let text = source
            .get(start..loose_words_end)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        let words = shlex_or_whitespace_words(text);
        result.append(
            WalkResult::single_with_words(start, loose_words_end, None, words),
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
            | "variable_assignments"
    )
}

/// Extract tree-sitter words from a leaf command node.
///
/// All leaf command node types have word-level extraction.
fn extract_leaf_words(node: Node, source: &[u8]) -> Vec<Word> {
    match node.kind() {
        "command" => extract_command_words(node, source),
        "declaration_command" => extract_declaration_words(node, source),
        "unset_command" => extract_unset_words(node, source),
        "test_command" => extract_test_words(node, source),
        "variable_assignment" => {
            let text = node.utf8_text(source).unwrap_or("").trim();
            if text.is_empty() {
                vec![]
            } else {
                vec![strip_quotes(text)]
            }
        }
        "variable_assignments" => extract_variable_assignments_words(node, source),
        _ => {
            // Unknown leaf type — shlex fallback, explicit and auditable.
            let text = node.utf8_text(source).unwrap_or("");
            shlex_or_whitespace_words(text)
        }
    }
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

#[cfg(test)]
mod walk_tests {
    use super::strip_quotes;

    #[test]
    fn strip_quotes_empty_string() {
        assert_eq!(strip_quotes(""), "");
    }

    #[test]
    fn strip_quotes_empty_single_quotes() {
        let w = strip_quotes("''");
        assert_eq!(w, "");
    }

    #[test]
    fn strip_quotes_empty_double_quotes() {
        let w = strip_quotes("\"\"");
        assert_eq!(w, "");
    }

    #[test]
    fn strip_quotes_ansi_c_quotes() {
        let w = strip_quotes("$'hello'");
        assert_eq!(w, "hello");
    }

    #[test]
    fn strip_quotes_unclosed_double_quote() {
        let w = strip_quotes("\"unclosed");
        assert_eq!(w, "\"unclosed");
    }

    #[test]
    fn strip_quotes_unmatched_single_quote() {
        let w = strip_quotes("'unmatched");
        assert_eq!(w, "'unmatched");
    }
}

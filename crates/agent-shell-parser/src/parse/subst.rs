use super::types::{ParseError, ParsedPipeline, Redirection, SubstitutionSpan};
use super::walk::{SegmentInfo, WalkResult};
use tree_sitter::Node;

pub(super) struct RawSubstSpan {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) inner: String,
}

pub(super) struct BuiltSegment {
    pub(super) source_start: usize,
    pub(super) source_end: usize,
    pub(super) trim_offset: usize,
    pub(super) command: String,
    pub(super) redirection: Option<Redirection>,
}

const MAX_SUBSTITUTION_DEPTH: usize = 32;

/// Collect outermost `command_substitution` and `process_substitution`
/// nodes. Does not recurse into found substitutions — that is handled by
/// recursive parsing of each span's inner text.
pub(super) fn collect_substitutions(node: Node, source: &[u8], out: &mut Vec<RawSubstSpan>) {
    if matches!(node.kind(), "command_substitution" | "process_substitution") {
        let full = node.utf8_text(source).unwrap_or("");
        let inner = strip_subst_delimiters(full);
        if !inner.is_empty() {
            out.push(RawSubstSpan {
                start: node.start_byte(),
                end: node.end_byte(),
                inner: inner.to_string(),
            });
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_substitutions(child, source, out);
    }
}

/// `$(cmd)` → `cmd`, `` `cmd` `` → `cmd`, `<(cmd)` / `>(cmd)` → `cmd`.
fn strip_subst_delimiters(text: &str) -> &str {
    let t = if text.starts_with("$(") || text.starts_with("<(") || text.starts_with(">(") {
        text.get(2..text.len().saturating_sub(1)).unwrap_or("")
    } else if text.starts_with('`') && text.ends_with('`') && text.len() >= 2 {
        &text[1..text.len() - 1]
    } else {
        text
    };
    t.trim()
}

pub(super) fn build_segments(walk: &WalkResult, source: &str) -> Vec<BuiltSegment> {
    walk.segments
        .iter()
        .filter_map(|seg: &SegmentInfo| {
            let raw = source.get(seg.start..seg.end).unwrap_or("");
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            let trim_offset = raw.len() - raw.trim_start().len();
            Some(BuiltSegment {
                source_start: seg.start,
                source_end: seg.end,
                trim_offset,
                command: trimmed.to_string(),
                redirection: seg.redirection.clone(),
            })
        })
        .collect()
}

fn parse_substitution_recursive(
    inner: &str,
    depth: usize,
    parse_fn: &dyn Fn(&str, usize) -> Result<ParsedPipeline, ParseError>,
) -> ParsedPipeline {
    if depth >= MAX_SUBSTITUTION_DEPTH {
        return ParsedPipeline::empty_with_error();
    }
    parse_fn(inner, depth + 1).unwrap_or_else(|_| ParsedPipeline::empty_with_error())
}

/// Map raw substitution spans to segments and recursively parse each.
///
/// Spans that fall within a segment become segment-relative substitutions.
/// Spans outside all segments (for-loop word lists, case subjects) become
/// structural substitutions on the pipeline.
pub(super) fn assign_substitutions(
    raw_spans: &[RawSubstSpan],
    built: &[BuiltSegment],
    depth: usize,
    parse_fn: &dyn Fn(&str, usize) -> Result<ParsedPipeline, ParseError>,
) -> (Vec<Vec<SubstitutionSpan>>, Vec<SubstitutionSpan>) {
    let mut per_segment: Vec<Vec<SubstitutionSpan>> = built.iter().map(|_| Vec::new()).collect();
    let mut structural = Vec::new();

    for raw in raw_spans {
        let pipeline = parse_substitution_recursive(&raw.inner, depth, parse_fn);
        let owner = built
            .iter()
            .enumerate()
            .find(|(_, seg)| raw.start >= seg.source_start && raw.end <= seg.source_end);
        match owner {
            Some((idx, seg)) => {
                per_segment[idx].push(SubstitutionSpan {
                    start: raw.start.saturating_sub(seg.source_start + seg.trim_offset),
                    end: raw.end.saturating_sub(seg.source_start + seg.trim_offset),
                    pipeline,
                });
            }
            None => {
                structural.push(SubstitutionSpan {
                    start: raw.start,
                    end: raw.end,
                    pipeline,
                });
            }
        }
    }

    (per_segment, structural)
}
